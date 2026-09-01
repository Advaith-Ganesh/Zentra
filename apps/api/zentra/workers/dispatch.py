"""Task dispatch with a safe local fallback.

In production the API always hands work to Celery. In local development a
developer may not have a worker running, so when the broker is unreachable we
run the scan inline in a background thread instead of silently dropping it.
That fallback is disabled in production, where a missing worker must surface as
an error rather than be papered over.
"""

from __future__ import annotations

import os
import threading
import uuid

from zentra.config import get_settings
from zentra.logging import get_logger

log = get_logger("zentra.dispatch")


def _dispatch_disabled(settings) -> bool:
    """Tests drive the worker explicitly.

    Automatic dispatch would leave background work running past the end of a
    test, so the test environment queues the scan row and lets the test call
    the worker itself.
    """
    return settings.environment == "test" and os.getenv("ZENTRA_TEST_DISPATCH") != "1"


def dispatch_scan(scan_id: uuid.UUID) -> str | None:
    """Queue a scan. Returns the Celery task ID when one was created."""
    settings = get_settings()
    if _dispatch_disabled(settings):
        log.debug("scan_dispatch_skipped_in_tests", scan_id=str(scan_id))
        return None
    try:
        from zentra.workers.tasks import run_scan_task

        result = run_scan_task.delay(str(scan_id))
        log.info("scan_dispatched", scan_id=str(scan_id), task_id=result.id)
        return str(result.id)
    except Exception as exc:  # noqa: BLE001 - broker unavailable
        log.warning(
            "scan_dispatch_failed",
            scan_id=str(scan_id),
            error_type=type(exc).__name__,
            environment=settings.environment,
        )
        if settings.is_production:
            # Do not hide a broken broker in production; the scan stays queued
            # and the rescan sweep will pick it up.
            return None
        _run_inline(scan_id)
        return None


def dispatch_report(report_id: uuid.UUID) -> str | None:
    settings = get_settings()
    if _dispatch_disabled(settings):
        log.debug("report_dispatch_skipped_in_tests", report_id=str(report_id))
        return None
    try:
        from zentra.workers.tasks import generate_report_task

        result = generate_report_task.delay(str(report_id))
        return str(result.id)
    except Exception as exc:  # noqa: BLE001
        log.warning("report_dispatch_failed", error_type=type(exc).__name__)
        if settings.is_production:
            return None
        _run_report_inline(report_id)
        return None


def _run_inline(scan_id: uuid.UUID) -> None:
    def _work() -> None:
        from zentra.db.session import session_scope
        from zentra.services import scans as scans_service

        try:
            with session_scope() as session:
                scans_service.execute_scan(session, scan_id)
        except Exception:
            log.exception("inline_scan_failed", scan_id=str(scan_id))

    threading.Thread(target=_work, name=f"zentra-scan-{scan_id}", daemon=True).start()
    log.info("scan_running_inline", scan_id=str(scan_id))


def _run_report_inline(report_id: uuid.UUID) -> None:
    def _work() -> None:
        from zentra.db.session import session_scope
        from zentra.services import reports as reports_service

        try:
            with session_scope() as session:
                reports_service.render_report(session, report_id=report_id)
        except Exception:
            log.exception("inline_report_failed", report_id=str(report_id))

    threading.Thread(target=_work, name=f"zentra-report-{report_id}", daemon=True).start()
