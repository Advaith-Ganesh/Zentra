"""Report generation lifecycle."""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zentra.config import get_settings
from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.core.entitlements import Feature
from zentra.db.models import (
    Finding,
    Organization,
    Report,
    ReportExport,
    User,
    Vendor,
)
from zentra.db.session import session_scope
from zentra.errors import ConflictError, NotFoundError, ValidationError
from zentra.logging import get_logger
from zentra.reports.pdf import build_branding, render_pdf
from zentra.services import scans as scans_service

log = get_logger("zentra.reports")

EXPORT_TTL_DAYS = 30
MAX_VENDORS_PER_REPORT = 500

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}


def storage_dir() -> Path:
    path = Path(get_settings().report_storage_dir).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def create_report(
    session: Session,
    *,
    organization: Organization,
    actor: User | None,
    kind: str = "vendor_risk_register",
    title: str | None = None,
    vendor_ids: list[uuid.UUID] | None = None,
    include_resolved_findings: bool = False,
    idempotency_key: str | None = None,
) -> Report:
    if vendor_ids and len(vendor_ids) > MAX_VENDORS_PER_REPORT:
        raise ValidationError(
            f"A report can cover at most {MAX_VENDORS_PER_REPORT} vendors.",
            code="TOO_MANY_VENDORS",
        )
    if idempotency_key:
        existing = session.execute(
            select(Report).where(
                Report.organization_id == organization.id,
                Report.idempotency_key == idempotency_key,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing

    report = Report(
        organization_id=organization.id,
        kind=kind,
        title=(title or f"Vendor Risk Register — {organization.name}")[:200],
        status="queued",
        scope={
            "vendor_ids": [str(v) for v in (vendor_ids or [])],
            "include_resolved_findings": include_resolved_findings,
        },
        generated_by=actor.id if actor else None,
        idempotency_key=idempotency_key,
    )
    session.add(report)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        if idempotency_key:
            existing = session.execute(
                select(Report).where(
                    Report.organization_id == organization.id,
                    Report.idempotency_key == idempotency_key,
                )
            ).scalar_one_or_none()
            if existing:
                return existing
        raise ConflictError("A report with that idempotency key already exists.") from exc

    audit.record(
        session,
        action=AuditAction.REPORT_GENERATED,
        organization_id=organization.id,
        actor_user_id=actor.id if actor else None,
        resource_type="report",
        resource_id=report.id,
        metadata={"kind": kind, "vendor_count": len(vendor_ids or [])},
    )
    return report


def get_report(session: Session, organization_id: uuid.UUID, report_id: uuid.UUID) -> Report:
    report = session.execute(
        select(Report).where(Report.id == report_id, Report.organization_id == organization_id)
    ).scalar_one_or_none()
    if report is None:
        raise NotFoundError("Report could not be found.", code="REPORT_NOT_FOUND")
    return report


def latest_export(session: Session, report: Report) -> ReportExport | None:
    return (
        session.execute(
            select(ReportExport)
            .where(ReportExport.report_id == report.id)
            .order_by(ReportExport.created_at.desc())
        )
        .scalars()
        .first()
    )


def list_reports(session: Session, organization_id: uuid.UUID, *, limit: int = 50) -> list[Report]:
    return list(
        session.execute(
            select(Report)
            .where(Report.organization_id == organization_id)
            .order_by(Report.created_at.desc())
            .limit(min(limit, 200))
        ).scalars()
    )


def render_report(session: Session, *, report_id: uuid.UUID) -> Report:
    """Build the PDF for a queued report. Idempotent."""
    report = session.get(Report, report_id)
    if report is None:
        raise NotFoundError("Report could not be found.", code="REPORT_NOT_FOUND")
    if report.status == "completed":
        return report

    report.status = "generating"
    session.flush()

    try:
        context = build_context(session, report)
        pdf_bytes = render_pdf(context)
    except Exception as exc:  # noqa: BLE001 - a failed report is a recorded state
        report.status = "failed"
        report.error_message = (
            "The report could not be generated. Please try again, or contact support if the "
            "problem persists."
        )
        log.error(
            "report_generation_failed",
            report_id=str(report_id),
            error_type=type(exc).__name__,
        )
        session.flush()
        return report

    filename = f"{report.organization_id}-{report.id}.pdf"
    destination = storage_dir() / filename
    # 0600: report contents are customer data.
    file_descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(file_descriptor, "wb") as handle:
        handle.write(pdf_bytes)

    session.add(
        ReportExport(
            report_id=report.id,
            organization_id=report.organization_id,
            format="pdf",
            file_path=str(destination),
            file_size=len(pdf_bytes),
            checksum=hashlib.sha256(pdf_bytes).hexdigest(),
            expires_at=datetime.now(UTC) + timedelta(days=EXPORT_TTL_DAYS),
        )
    )
    report.status = "completed"
    report.completed_at = datetime.now(UTC)
    report.summary = context["summary"]
    session.flush()
    log.info("report_generated", report_id=str(report.id), bytes=len(pdf_bytes))
    return report


def build_context(session: Session, report: Report) -> dict[str, Any]:
    """Assemble everything the template needs, in one place."""
    from zentra.services.organizations import entitlements_for
    from zentra.services.vendors import dashboard_summary

    organization = session.get(Organization, report.organization_id)
    if organization is None:
        raise NotFoundError("Organization could not be found.")
    entitlements = entitlements_for(session, organization)

    scope_ids = [uuid.UUID(v) for v in (report.scope or {}).get("vendor_ids", [])]
    query = select(Vendor).where(
        Vendor.organization_id == organization.id, Vendor.status != "archived"
    )
    if scope_ids:
        query = query.where(Vendor.id.in_(scope_ids))
    vendors = list(session.execute(query).scalars())
    vendors.sort(
        key=lambda v: (
            _RISK_ORDER.get(v.current_risk_level, 4),
            -(v.current_score or 0),
            v.name.lower(),
        )
    )

    include_resolved = bool((report.scope or {}).get("include_resolved_findings"))
    statuses = (
        ["open", "in_progress", "resolved", "accepted_risk"]
        if include_resolved
        else ["open", "in_progress"]
    )

    # One query for all findings, grouped in Python: avoids N+1 across vendors.
    vendor_ids = [v.id for v in vendors]
    findings_by_vendor: dict[uuid.UUID, list[Finding]] = {v.id: [] for v in vendors}
    if vendor_ids:
        for finding in session.execute(
            select(Finding).where(
                Finding.organization_id == organization.id,
                Finding.vendor_id.in_(vendor_ids),
                Finding.status.in_(statuses),
            )
        ).scalars():
            findings_by_vendor.setdefault(finding.vendor_id, []).append(finding)

    rows: list[dict[str, Any]] = []
    unscored = 0
    for vendor in vendors:
        latest = scans_service.latest_completed_scan(session, vendor.id)
        breakdown_source = (latest.score_breakdown or {}) if latest else {}
        categories = breakdown_source.get("categories") or []
        breakdown = [
            {
                "display_name": c.get("display_name", c.get("category", "")),
                "points": c.get("points", 0),
                "max_points": c.get("max_points", 0),
                "assessed": c.get("assessed", False),
                "pct": _percentage(c.get("points", 0), c.get("max_points", 0)),
            }
            for c in categories
        ]
        unassessed = [c["display_name"] for c in breakdown if not c["assessed"]]

        vendor_findings = sorted(
            findings_by_vendor.get(vendor.id, []),
            key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.title),
        )
        verdict = (latest.verdict or {}) if latest else {}
        if vendor.current_score is None:
            unscored += 1

        rows.append(
            {
                "name": vendor.name,
                "domain": vendor.domain,
                "category": vendor.category,
                "criticality": vendor.criticality,
                "owner": vendor.owner_label,
                "score": vendor.current_score,
                "risk_level": vendor.current_risk_level,
                "last_assessed": (
                    vendor.last_scanned_at.strftime("%d %b %Y") if vendor.last_scanned_at else None
                ),
                "key_findings": [f.title for f in vendor_findings[:3]],
                "recommended_action": _recommended_action(verdict, vendor_findings, vendor),
                "verdict": verdict or None,
                "breakdown": breakdown or None,
                "unassessed": unassessed,
                "findings": [
                    {
                        "title": f.title,
                        "description": f.description,
                        "recommendation": f.recommendation,
                        "severity": f.severity,
                        "status_label": f.status.replace("_", " ").title(),
                        "source": f.source,
                        "first_seen": f.first_seen_at.strftime("%d %b %Y"),
                        "last_seen": f.last_seen_at.strftime("%d %b %Y"),
                        "confidence": f"{float(f.confidence):.0%}",
                    }
                    for f in vendor_findings[:12]
                ],
            }
        )

    now = datetime.now(UTC)
    summary = dashboard_summary(session, organization.id)
    generated_by = session.get(User, report.generated_by) if report.generated_by else None

    return {
        "title": report.title,
        "report_id": str(report.id),
        "organization": {"name": organization.name},
        "brand": build_branding(
            white_label_allowed=entitlements.has(Feature.WHITE_LABEL_REPORTS),
            branding=organization.branding,
            organization_name=organization.name,
        ),
        "generated_at_display": now.strftime("%d %B %Y"),
        "generated_at": now.isoformat(),
        "period": f"As at {now.strftime('%d %B %Y')}",
        "requested_by": (generated_by.full_name or generated_by.email) if generated_by else None,
        "summary": summary,
        "unscored_vendors": unscored,
        "vendors": rows,
    }


def _percentage(points: float, maximum: float) -> int:
    if not maximum:
        return 0
    return max(0, min(100, round((float(points) / float(maximum)) * 100)))


def _recommended_action(verdict: dict[str, Any], findings: list[Finding], vendor: Vendor) -> str:
    if verdict.get("recommended_action"):
        return str(verdict["recommended_action"])
    if findings:
        return findings[0].recommendation
    if vendor.current_score is None:
        return (
            "Re-run the assessment. Too few checks completed to draw a conclusion; this is "
            "not an indication that the vendor is low risk."
        )
    return "No action needed. Zentra continues to monitor this vendor."


def read_export(session: Session, *, export: ReportExport) -> bytes:
    path = Path(export.file_path)
    # Confine reads to the configured storage directory.
    try:
        path.resolve().relative_to(storage_dir())
    except ValueError as exc:
        raise NotFoundError("The report file is no longer available.") from exc
    if not path.exists():
        raise NotFoundError("The report file is no longer available.", code="REPORT_FILE_MISSING")
    export.download_count += 1
    session.flush()
    return path.read_bytes()


def purge_expired_exports() -> int:
    removed = 0
    now = datetime.now(UTC)
    with session_scope() as session:
        expired = session.execute(
            select(ReportExport).where(ReportExport.expires_at < now).limit(1000)
        ).scalars()
        for export in expired:
            try:
                path = Path(export.file_path)
                if path.exists():
                    path.unlink()
            except OSError:
                log.warning("report_file_unlink_failed")
            session.delete(export)
            removed += 1
    return removed
