"""Finding generation and remediation tracking.

A "finding" is a deduplicated, tracked problem. Scans produce check results
every time they run; findings persist across scans so a customer can assign,
comment on and resolve them without losing history.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.db.models import Finding, FindingStatusHistory, Scan, User, Vendor
from zentra.errors import NotFoundError, ValidationError
from zentra.scanners.base import CheckResult, Severity

VALID_STATUSES = ("open", "in_progress", "resolved", "accepted_risk")
CLOSED_STATUSES = ("resolved", "accepted_risk")


def fingerprint(vendor_id: uuid.UUID, result: CheckResult) -> str:
    """Stable identity for a problem so it can be tracked across scans.

    Deliberately excludes volatile detail (expiry dates, port banners) so the
    same underlying problem does not create a new finding on every scan.
    """
    parts = [str(vendor_id), result.check_type.value, result.severity.value]
    if result.check_type.value == "cve_exposure":
        cves = sorted(
            v.get("cve_id", "")
            for v in (result.details.get("vulnerabilities") or [])
            if isinstance(v, dict)
        )
        parts.append(",".join(cves[:10]))
    elif result.check_type.value == "internet_exposure":
        parts.append(",".join(str(p) for p in (result.details.get("sensitive_ports") or [])))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:40]


def sync_findings(
    session: Session,
    *,
    vendor: Vendor,
    scan: Scan,
    results: list[CheckResult],
) -> tuple[list[Finding], list[Finding]]:
    """Create/refresh findings from a scan. Returns ``(new, resolved)``.

    A finding whose underlying problem no longer appears in a completed scan is
    auto-resolved, unless a person has already marked it accepted-risk.
    """
    now = datetime.now(UTC)
    problems = [r for r in results if r.is_problem and r.severity.rank > Severity.INFO.rank]
    seen: dict[str, CheckResult] = {}
    for result in problems:
        seen[fingerprint(vendor.id, result)] = result

    existing = {
        f.fingerprint: f
        for f in session.execute(select(Finding).where(Finding.vendor_id == vendor.id)).scalars()
    }

    created: list[Finding] = []
    for key, result in seen.items():
        finding = existing.get(key)
        if finding is None:
            finding = Finding(
                organization_id=vendor.organization_id,
                vendor_id=vendor.id,
                first_scan_id=scan.id,
                last_scan_id=scan.id,
                fingerprint=key,
                check_type=result.check_type.value,
                severity=result.severity.value,
                title=(result.title or result.summary)[:300],
                description=result.summary,
                recommendation=result.recommendation
                or "Review this with the vendor at your next security check-in.",
                evidence=[e.to_dict() for e in result.evidence],
                source=result.source,
                confidence=result.confidence,
                status="open",
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(finding)
            created.append(finding)
        else:
            finding.last_scan_id = scan.id
            finding.last_seen_at = now
            finding.severity = result.severity.value
            finding.title = (result.title or result.summary)[:300]
            finding.description = result.summary
            finding.recommendation = result.recommendation or finding.recommendation
            finding.evidence = [e.to_dict() for e in result.evidence]
            finding.confidence = result.confidence
            if finding.status == "resolved":
                # It came back.
                _transition(session, finding, "open", note="Detected again by a later scan.")

    resolved: list[Finding] = []
    for key, finding in existing.items():
        if key in seen or finding.status in CLOSED_STATUSES:
            continue
        _transition(
            session,
            finding,
            "resolved",
            note="No longer detected by the latest completed scan.",
        )
        resolved.append(finding)

    session.flush()
    return created, resolved


def _transition(
    session: Session,
    finding: Finding,
    to_status: str,
    *,
    note: str | None = None,
    actor: User | None = None,
) -> None:
    from_status = finding.status
    finding.status = to_status
    finding.resolved_at = datetime.now(UTC) if to_status in CLOSED_STATUSES else None
    session.add(
        FindingStatusHistory(
            finding_id=finding.id,
            organization_id=finding.organization_id,
            from_status=from_status,
            to_status=to_status,
            note=note,
            actor_user_id=actor.id if actor else None,
        )
    )


def get_finding(session: Session, organization_id: uuid.UUID, finding_id: uuid.UUID) -> Finding:
    finding = session.execute(
        select(Finding).where(Finding.id == finding_id, Finding.organization_id == organization_id)
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding could not be found.", code="FINDING_NOT_FOUND")
    return finding


def list_findings(
    session: Session,
    organization_id: uuid.UUID,
    *,
    vendor_id: uuid.UUID | None = None,
    statuses: list[str] | None = None,
    severities: list[str] | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Finding]:
    query = select(Finding).where(Finding.organization_id == organization_id)
    if vendor_id:
        query = query.where(Finding.vendor_id == vendor_id)
    if statuses:
        query = query.where(Finding.status.in_(statuses))
    if severities:
        query = query.where(Finding.severity.in_(severities))
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = list(
        session.execute(
            query.order_by(Finding.last_seen_at.desc()).limit(min(limit, 500)).offset(offset)
        ).scalars()
    )
    return sorted(rows, key=lambda f: (severity_order.get(f.severity, 9), f.title))


def update_finding(
    session: Session,
    *,
    finding: Finding,
    actor: User,
    status: str | None = None,
    note: str | None = None,
    assigned_to: uuid.UUID | None = None,
    unassign: bool = False,
) -> Finding:
    if status is not None:
        if status not in VALID_STATUSES:
            raise ValidationError(
                f"Status must be one of: {', '.join(VALID_STATUSES)}.",
                code="INVALID_FINDING_STATUS",
            )
        if status != finding.status:
            _transition(session, finding, status, note=note, actor=actor)
        elif note:
            session.add(
                FindingStatusHistory(
                    finding_id=finding.id,
                    organization_id=finding.organization_id,
                    from_status=finding.status,
                    to_status=finding.status,
                    note=note,
                    actor_user_id=actor.id,
                )
            )
    elif note:
        session.add(
            FindingStatusHistory(
                finding_id=finding.id,
                organization_id=finding.organization_id,
                from_status=finding.status,
                to_status=finding.status,
                note=note,
                actor_user_id=actor.id,
            )
        )

    if unassign:
        finding.assigned_to = None
    elif assigned_to is not None:
        member = session.get(User, assigned_to)
        if member is None:
            raise ValidationError("Assignee could not be found.", code="ASSIGNEE_NOT_FOUND")
        from zentra.services.organizations import get_membership

        if get_membership(session, finding.organization_id, assigned_to) is None:
            raise ValidationError(
                "Assignee is not a member of this organization.", code="ASSIGNEE_NOT_MEMBER"
            )
        finding.assigned_to = assigned_to
        audit.record(
            session,
            action=AuditAction.FINDING_ASSIGNED,
            organization_id=finding.organization_id,
            actor_user_id=actor.id,
            resource_type="finding",
            resource_id=finding.id,
        )

    audit.record(
        session,
        action=AuditAction.FINDING_UPDATED,
        organization_id=finding.organization_id,
        actor_user_id=actor.id,
        resource_type="finding",
        resource_id=finding.id,
        metadata={"status": finding.status},
    )
    session.flush()
    return finding


def finding_history(session: Session, finding: Finding) -> list[FindingStatusHistory]:
    return list(
        session.execute(
            select(FindingStatusHistory)
            .where(FindingStatusHistory.finding_id == finding.id)
            .order_by(FindingStatusHistory.created_at.desc())
        ).scalars()
    )
