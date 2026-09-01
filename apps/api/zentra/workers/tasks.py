"""Background tasks.

Every task is idempotent and bounded: a duplicate delivery is safe, a transient
failure retries with backoff, and a permanent failure records a `failed` state
rather than disappearing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select

from zentra.config import get_settings
from zentra.db.models import Alert, Organization, PublicScan, Report, Scan, Vendor
from zentra.db.session import session_scope
from zentra.errors import InvalidDomainError, UnsafeTargetError
from zentra.logging import get_logger
from zentra.services import scans as scans_service

# Importing the app registers it as Celery's default, so the `shared_task`
# definitions below bind to Zentra's configuration (broker, queue, timeouts)
# rather than to an unconfigured ambient app.
from zentra.workers.celery_app import celery_app as _celery_app  # noqa: F401

log = get_logger("zentra.tasks")

#: A scan stuck in `running` for longer than this is presumed dead.
STUCK_SCAN_MINUTES = 30

PERMANENT_ERRORS = (UnsafeTargetError, InvalidDomainError)


@shared_task(
    name="zentra.run_scan",
    bind=True,
    autoretry_for=(ConnectionError, TimeoutError),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
    soft_time_limit=540,
    time_limit=600,
)
def run_scan_task(self: Any, scan_id: str) -> dict[str, Any]:
    """Execute a queued scan.

    Safe to deliver more than once: :func:`execute_scan` returns immediately if
    the scan has already reached a terminal state.
    """
    try:
        identifier = uuid.UUID(scan_id)
    except ValueError:
        log.error("run_scan_bad_id", scan_id=scan_id[:64])
        return {"status": "invalid_scan_id"}

    try:
        with session_scope() as session:
            scan = scans_service.execute_scan(session, identifier)
            return {
                "scan_id": str(scan.id),
                "status": scan.status,
                "score": scan.score,
                "risk_level": scan.risk_level,
            }
    except SoftTimeLimitExceeded:
        _mark_failed(identifier, "TIMEOUT", "The scan exceeded its time limit.")
        raise
    except PERMANENT_ERRORS as exc:
        _mark_failed(identifier, type(exc).__name__, "The vendor's domain could not be scanned.")
        return {"scan_id": scan_id, "status": "failed", "reason": type(exc).__name__}
    except Exception as exc:
        log.error("run_scan_error", scan_id=scan_id, error_type=type(exc).__name__)
        if self.request.retries >= self.max_retries:
            _mark_failed(
                identifier,
                type(exc).__name__,
                "The scan could not be completed after several attempts.",
            )
            return {"scan_id": scan_id, "status": "failed"}
        raise self.retry(exc=exc) from exc


def _mark_failed(scan_id: uuid.UUID, code: str, message: str) -> None:
    """Record a terminal failure. A failed scan must never vanish silently."""
    try:
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is None or scan.status in ("completed", "partial", "failed"):
                return
            scan.status = "failed"
            scan.error_code = code[:100]
            scan.error_message = message
            scan.completed_at = datetime.now(UTC)
            vendor = session.get(Vendor, scan.vendor_id)
            if vendor is not None:
                from zentra.services.vendors import schedule_next_scan

                schedule_next_scan(vendor)
    except Exception:
        log.exception("mark_failed_error", scan_id=str(scan_id))


@shared_task(name="zentra.rescan_due_vendors")
def rescan_due_vendors(limit: int = 200) -> dict[str, Any]:
    """Queue scheduled rescans for vendors whose next scan is due."""
    queued: list[str] = []
    with session_scope() as session:
        for vendor in scans_service.due_for_rescan(session, limit=limit):
            existing = scans_service.active_scan_for(session, vendor.id)
            if existing is not None:
                # Push the schedule forward so we do not re-evaluate every sweep.
                from zentra.services.vendors import schedule_next_scan

                schedule_next_scan(vendor)
                continue
            scan = scans_service.queue_scan(session, vendor=vendor, trigger="scheduled")
            # Move the vendor's schedule immediately so a slow worker does not
            # cause the same vendor to be queued twice.
            from zentra.services.vendors import schedule_next_scan

            schedule_next_scan(vendor)
            queued.append(str(scan.id))
    for scan_id in queued:
        run_scan_task.delay(scan_id)
    log.info("rescan_sweep", queued=len(queued))
    return {"queued": len(queued)}


@shared_task(name="zentra.reap_stuck_scans")
def reap_stuck_scans() -> dict[str, Any]:
    """Fail scans whose worker died mid-run so they do not hang forever."""
    cutoff = datetime.now(UTC) - timedelta(minutes=STUCK_SCAN_MINUTES)
    reaped = 0
    with session_scope() as session:
        stuck = session.execute(
            select(Scan).where(Scan.status == "running", Scan.started_at < cutoff).limit(200)
        ).scalars()
        for scan in stuck:
            scan.status = "failed"
            scan.error_code = "WORKER_LOST"
            scan.error_message = (
                "The scan did not complete. Zentra will retry it on the next schedule."
            )
            scan.completed_at = datetime.now(UTC)
            reaped += 1
    if reaped:
        log.warning("stuck_scans_reaped", count=reaped)
    return {"reaped": reaped}


@shared_task(name="zentra.generate_report")
def generate_report_task(report_id: str) -> dict[str, Any]:
    from zentra.services import reports as reports_service

    try:
        identifier = uuid.UUID(report_id)
    except ValueError:
        return {"status": "invalid_report_id"}
    with session_scope() as session:
        report = reports_service.render_report(session, report_id=identifier)
        return {"report_id": str(report.id), "status": report.status}


@shared_task(name="zentra.deliver_alert")
def deliver_alert_task(alert_id: str) -> dict[str, Any]:
    from zentra.services import alerts as alerts_service

    try:
        identifier = uuid.UUID(alert_id)
    except ValueError:
        return {"status": "invalid_alert_id"}
    with session_scope() as session:
        alert = session.get(Alert, identifier)
        if alert is None or alert.notification_status == "sent":
            return {"status": "skipped"}
        alerts_service.deliver_pending(session, alert=alert)
        return {"status": alert.notification_status}


@shared_task(name="zentra.recompute_benchmarks")
def recompute_benchmarks() -> dict[str, Any]:
    from zentra.services import benchmark as benchmark_service

    with session_scope() as session:
        cohorts = benchmark_service.recompute(session)
    log.info("benchmarks_recomputed", cohorts=cohorts)
    return {"cohorts": cohorts}


@shared_task(name="zentra.send_weekly_summaries")
def send_weekly_summaries() -> dict[str, Any]:
    from zentra.core.entitlements import Feature
    from zentra.integrations.email.service import send_weekly_summary
    from zentra.services.alerts import _recipients
    from zentra.services.organizations import entitlements_for
    from zentra.services.vendors import dashboard_summary

    sent = 0
    with session_scope() as session:
        organizations = session.execute(
            select(Organization).where(Organization.deleted_at.is_(None)).limit(1000)
        ).scalars()
        for organization in organizations:
            entitlements = entitlements_for(session, organization)
            if not entitlements.has(Feature.ALERTS):
                continue
            recipients = _recipients(session, organization.id)
            if not recipients:
                continue
            summary = dashboard_summary(session, organization.id)
            if summary["total_vendors"] == 0:
                continue
            try:
                send_weekly_summary(to=recipients, organization=organization, summary=summary)
                sent += 1
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "weekly_summary_failed",
                    organization_id=str(organization.id),
                    error_type=type(exc).__name__,
                )
    return {"sent": sent}


@shared_task(name="zentra.purge_expired_data")
def purge_expired_data() -> dict[str, Any]:
    """Enforce retention: anonymous public scans and expired report exports."""
    from zentra.services import reports as reports_service

    settings = get_settings()
    removed_public = 0
    with session_scope() as session:
        cutoff = datetime.now(UTC) - timedelta(days=30)
        rows = session.execute(
            select(PublicScan).where(PublicScan.created_at < cutoff).limit(5000)
        ).scalars()
        for row in rows:
            session.delete(row)
            removed_public += 1

    removed_exports = reports_service.purge_expired_exports()
    log.info(
        "retention_purge",
        public_scans_removed=removed_public,
        exports_removed=removed_exports,
        environment=settings.environment,
    )
    return {"public_scans": removed_public, "exports": removed_exports}


@shared_task(name="zentra.cleanup_reports")
def cleanup_reports() -> dict[str, Any]:
    with session_scope() as session:
        stale = session.execute(
            select(Report).where(
                Report.status == "generating",
                Report.created_at < datetime.now(UTC) - timedelta(minutes=30),
            )
        ).scalars()
        count = 0
        for report in stale:
            report.status = "failed"
            report.error_message = "Report generation timed out."
            count += 1
    return {"failed": count}
