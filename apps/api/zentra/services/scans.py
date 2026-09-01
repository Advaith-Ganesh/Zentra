"""Scan lifecycle: queueing, execution and persistence."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.db.models import Scan, ScanResult, User, Vendor
from zentra.errors import ConflictError, NotFoundError
from zentra.logging import get_logger
from zentra.scanners.orchestration import ScanOutcome, run_scan
from zentra.services import alerts as alerts_service
from zentra.services import findings as findings_service
from zentra.services import vendors as vendors_service

log = get_logger("zentra.scans")

ACTIVE_STATUSES = ("queued", "running")


def get_scan(session: Session, organization_id: uuid.UUID, scan_id: uuid.UUID) -> Scan:
    scan = session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == organization_id)
    ).scalar_one_or_none()
    if scan is None:
        raise NotFoundError("Scan could not be found.", code="SCAN_NOT_FOUND")
    return scan


def list_scans(
    session: Session,
    organization_id: uuid.UUID,
    *,
    vendor_id: uuid.UUID | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[Scan]:
    query = select(Scan).where(Scan.organization_id == organization_id)
    if vendor_id:
        query = query.where(Scan.vendor_id == vendor_id)
    return list(
        session.execute(
            query.order_by(Scan.created_at.desc()).limit(min(limit, 100)).offset(offset)
        ).scalars()
    )


def active_scan_for(session: Session, vendor_id: uuid.UUID) -> Scan | None:
    return (
        session.execute(
            select(Scan)
            .where(Scan.vendor_id == vendor_id, Scan.status.in_(ACTIVE_STATUSES))
            .order_by(Scan.created_at.desc())
        )
        .scalars()
        .first()
    )


def queue_scan(
    session: Session,
    *,
    vendor: Vendor,
    trigger: str = "manual",
    actor: User | None = None,
    idempotency_key: str | None = None,
    allow_duplicate: bool = False,
) -> Scan:
    """Create a queued scan row.

    Returns the existing in-flight scan rather than creating a duplicate, so a
    double-clicked "Scan now" button cannot cost two provider quotas.
    """
    if not allow_duplicate:
        existing = active_scan_for(session, vendor.id)
        if existing is not None:
            log.info("scan_queue_deduplicated", vendor_id=str(vendor.id), scan_id=str(existing.id))
            return existing

    scan = Scan(
        organization_id=vendor.organization_id,
        vendor_id=vendor.id,
        trigger=trigger,
        status="queued",
        requested_by=actor.id if actor else None,
        idempotency_key=idempotency_key,
    )
    session.add(scan)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        if idempotency_key:
            existing = session.execute(
                select(Scan).where(
                    Scan.vendor_id == vendor.id, Scan.idempotency_key == idempotency_key
                )
            ).scalar_one_or_none()
            if existing:
                return existing
        raise ConflictError("A scan for this vendor is already queued.") from exc

    audit.record(
        session,
        action=AuditAction.SCAN_TRIGGERED,
        organization_id=vendor.organization_id,
        actor_user_id=actor.id if actor else None,
        actor_type="user" if actor else "system",
        resource_type="scan",
        resource_id=scan.id,
        metadata={"trigger": trigger, "vendor_id": str(vendor.id)},
    )
    return scan


def execute_scan(session: Session, scan_id: uuid.UUID) -> Scan:
    """Run a queued scan to completion and persist everything it produced.

    This is what the Celery task calls. It is safe to call twice: a scan that
    is already completed is returned untouched.
    """
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError("Scan could not be found.", code="SCAN_NOT_FOUND")
    if scan.status in ("completed", "partial", "failed", "cancelled"):
        log.info("scan_already_finalized", scan_id=str(scan_id), status=scan.status)
        return scan

    vendor = session.get(Vendor, scan.vendor_id)
    if vendor is None:
        scan.status = "failed"
        scan.error_code = "VENDOR_DELETED"
        scan.error_message = "The vendor was removed before the scan ran."
        scan.completed_at = datetime.now(UTC)
        session.flush()
        return scan

    scan.status = "running"
    scan.started_at = datetime.now(UTC)
    session.flush()

    try:
        outcome = asyncio.run(
            run_scan(
                vendor.domain,
                vendor_id=str(vendor.id),
                organization_id=str(vendor.organization_id),
                scan_id=str(scan.id),
            )
        )
    except Exception as exc:  # noqa: BLE001 - a failed scan is a recorded state
        scan.status = "failed"
        scan.error_code = type(exc).__name__
        # Never surface an internal exception message to a customer.
        scan.error_message = "The scan could not be completed. Zentra will retry automatically."
        scan.completed_at = datetime.now(UTC)
        vendors_service.schedule_next_scan(vendor)
        audit.record(
            session,
            action=AuditAction.SCAN_FAILED,
            organization_id=vendor.organization_id,
            actor_type="system",
            resource_type="scan",
            resource_id=scan.id,
            metadata={"error_type": type(exc).__name__},
        )
        log.error(
            "scan_failed",
            scan_id=str(scan.id),
            vendor_id=str(vendor.id),
            error_type=type(exc).__name__,
        )
        session.flush()
        return scan

    return persist_outcome(session, scan=scan, vendor=vendor, outcome=outcome)


def persist_outcome(session: Session, *, scan: Scan, vendor: Vendor, outcome: ScanOutcome) -> Scan:
    """Write a completed scan's results, score, findings and alerts."""
    score = outcome.score
    previous_score = vendor.current_score

    for result in outcome.results:
        session.add(
            ScanResult(
                scan_id=scan.id,
                organization_id=vendor.organization_id,
                vendor_id=vendor.id,
                check_type=result.check_type.value,
                status=result.status.value,
                severity=result.severity.value,
                summary=result.summary,
                details=result.details,
                evidence=[e.to_dict() for e in result.evidence],
                source=result.source,
                confidence=result.confidence,
                provider_status=result.provider_status,
                duration_ms=result.duration_ms,
                checked_at=result.checked_at,
            )
        )

    scan.status = outcome.status
    scan.completed_at = datetime.now(UTC)
    scan.checks_total = len(outcome.results)
    scan.checks_succeeded = score.checks_conclusive
    scan.coverage = score.coverage
    scan.confidence = score.confidence
    scan.score_breakdown = score.to_dict()
    scan.verdict = outcome.verdict.to_dict()
    if score.is_scorable:
        scan.score = score.score
        scan.risk_level = score.risk_level.value if score.risk_level else None
    else:
        scan.score = None
        scan.risk_level = None

    # Update the vendor's current position only from a scorable scan; an
    # inconclusive scan must not overwrite a good previous assessment.
    if score.is_scorable:
        vendor.previous_score = previous_score
        vendor.current_score = score.score
        vendor.current_risk_level = score.risk_level.value if score.risk_level else None
        vendor.current_confidence = score.confidence
    vendor.last_scanned_at = scan.completed_at
    vendors_service.schedule_next_scan(vendor)
    session.flush()

    created, resolved = findings_service.sync_findings(
        session, vendor=vendor, scan=scan, results=outcome.results
    )

    alert = None
    if score.is_scorable:
        alert = alerts_service.evaluate_score_change(
            session,
            vendor=vendor,
            scan=scan,
            old_score=previous_score,
            new_score=score.score,
        )
    if alert is not None:
        alerts_service.deliver_pending(session, alert=alert)

    audit.record(
        session,
        action=AuditAction.SCAN_COMPLETED,
        organization_id=vendor.organization_id,
        actor_type="system",
        resource_type="scan",
        resource_id=scan.id,
        metadata={
            "score": scan.score,
            "risk_level": scan.risk_level,
            "status": scan.status,
            "coverage": float(score.coverage),
            "new_findings": len(created),
            "resolved_findings": len(resolved),
            "scanners_failed": outcome.scanners_failed,
        },
    )
    session.flush()
    return scan


def scan_results(session: Session, scan: Scan) -> list[ScanResult]:
    return list(
        session.execute(
            select(ScanResult).where(ScanResult.scan_id == scan.id).order_by(ScanResult.check_type)
        ).scalars()
    )


def latest_completed_scan(session: Session, vendor_id: uuid.UUID) -> Scan | None:
    return (
        session.execute(
            select(Scan)
            .where(Scan.vendor_id == vendor_id, Scan.status.in_(["completed", "partial"]))
            .order_by(Scan.completed_at.desc())
        )
        .scalars()
        .first()
    )


def score_history(
    session: Session, vendor_id: uuid.UUID, *, limit: int = 60
) -> list[dict[str, Any]]:
    rows = session.execute(
        select(Scan.completed_at, Scan.score, Scan.risk_level, Scan.id)
        .where(
            Scan.vendor_id == vendor_id,
            Scan.status.in_(["completed", "partial"]),
            Scan.score.isnot(None),
        )
        .order_by(Scan.completed_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "scan_id": str(row[3]),
            "date": row[0].isoformat() if row[0] else None,
            "score": row[1],
            "risk_level": row[2],
        }
        for row in reversed(rows)
    ]


def due_for_rescan(session: Session, *, limit: int = 100) -> list[Vendor]:
    now = datetime.now(UTC)
    return list(
        session.execute(
            select(Vendor)
            .where(
                Vendor.status == "active",
                Vendor.next_scan_at.isnot(None),
                Vendor.next_scan_at <= now,
            )
            .order_by(Vendor.next_scan_at.asc())
            .limit(limit)
        ).scalars()
    )
