"""Vendor CRUD, always scoped to a single organization."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.core.domains import normalize_domain
from zentra.db.models import Finding, Organization, Scan, User, Vendor
from zentra.errors import DuplicateVendorError, ValidationError, VendorNotFoundError

VALID_CRITICALITY = ("low", "medium", "high", "critical")
VALID_STATUS = ("active", "paused", "archived")

SortField = Literal["name", "current_score", "last_scanned_at", "created_at", "criticality"]


def get_vendor(session: Session, organization_id: uuid.UUID, vendor_id: uuid.UUID) -> Vendor:
    """Fetch a vendor, enforcing organization scope in the query itself.

    Scoping in the WHERE clause (rather than fetching then comparing) means a
    cross-tenant read is impossible even if a caller forgets to check.
    """
    vendor = session.execute(
        select(Vendor).where(Vendor.id == vendor_id, Vendor.organization_id == organization_id)
    ).scalar_one_or_none()
    if vendor is None:
        raise VendorNotFoundError()
    return vendor


def _base_query(organization_id: uuid.UUID) -> Select[tuple[Vendor]]:
    return select(Vendor).where(Vendor.organization_id == organization_id)


def list_vendors(
    session: Session,
    organization_id: uuid.UUID,
    *,
    search: str | None = None,
    status: str | None = "active",
    risk_levels: list[str] | None = None,
    criticality: list[str] | None = None,
    sort: SortField = "current_score",
    direction: Literal["asc", "desc"] = "desc",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Vendor], int]:
    query = _base_query(organization_id)

    if status and status != "all":
        query = query.where(Vendor.status == status)
    if search:
        # Parameterized LIKE — the value is bound, never interpolated.
        pattern = f"%{search.strip()[:100]}%"
        query = query.where(or_(Vendor.name.ilike(pattern), Vendor.domain.ilike(pattern)))
    if risk_levels:
        query = query.where(Vendor.current_risk_level.in_(risk_levels))
    if criticality:
        query = query.where(Vendor.criticality.in_(criticality))

    total = int(session.execute(select(func.count()).select_from(query.subquery())).scalar_one())

    column = {
        "name": Vendor.name,
        "current_score": Vendor.current_score,
        "last_scanned_at": Vendor.last_scanned_at,
        "created_at": Vendor.created_at,
        "criticality": Vendor.criticality,
    }[sort]
    ordering = column.desc().nullslast() if direction == "desc" else column.asc().nullsfirst()
    query = (
        query.order_by(ordering, Vendor.name.asc()).limit(min(limit, 200)).offset(max(offset, 0))
    )
    return list(session.execute(query).scalars()), total


def create_vendor(
    session: Session,
    *,
    organization: Organization,
    name: str,
    domain: str,
    actor: User | None = None,
    description: str | None = None,
    category: str | None = None,
    criticality: str = "medium",
    owner_label: str | None = None,
    owner_user_id: uuid.UUID | None = None,
    scan_interval_hours: int | None = None,
    is_demo: bool = False,
) -> Vendor:
    """Create a vendor. The caller is responsible for the entitlement check."""
    name = (name or "").strip()
    if not 1 <= len(name) <= 200:
        raise ValidationError("Vendor name must be between 1 and 200 characters.")
    if criticality not in VALID_CRITICALITY:
        raise ValidationError(f"Criticality must be one of: {', '.join(VALID_CRITICALITY)}.")
    normalized = normalize_domain(domain)

    existing = session.execute(
        select(Vendor.id).where(
            Vendor.organization_id == organization.id,
            func.lower(Vendor.domain) == normalized,
        )
    ).first()
    if existing:
        raise DuplicateVendorError()

    vendor = Vendor(
        organization_id=organization.id,
        name=name,
        domain=normalized,
        description=(description or "").strip()[:2000] or None,
        category=(category or "").strip()[:100] or None,
        criticality=criticality,
        owner_label=(owner_label or "").strip()[:200] or None,
        owner_user_id=owner_user_id,
        scan_interval_hours=scan_interval_hours or 24,
        is_demo=is_demo,
    )
    session.add(vendor)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise DuplicateVendorError() from exc

    audit.record(
        session,
        action=AuditAction.VENDOR_CREATED,
        organization_id=organization.id,
        actor_user_id=actor.id if actor else None,
        actor_type="user" if actor else "system",
        resource_type="vendor",
        resource_id=vendor.id,
        metadata={"domain": normalized, "criticality": criticality},
    )
    return vendor


def update_vendor(
    session: Session,
    *,
    vendor: Vendor,
    actor: User | None = None,
    **fields: Any,
) -> Vendor:
    allowed = {
        "name",
        "description",
        "category",
        "criticality",
        "owner_label",
        "owner_user_id",
        "status",
        "scan_interval_hours",
    }
    changed: dict[str, Any] = {}
    for key, value in fields.items():
        if key not in allowed or value is None:
            continue
        if key == "criticality" and value not in VALID_CRITICALITY:
            raise ValidationError(f"Criticality must be one of: {', '.join(VALID_CRITICALITY)}.")
        if key == "status" and value not in VALID_STATUS:
            raise ValidationError(f"Status must be one of: {', '.join(VALID_STATUS)}.")
        if key == "scan_interval_hours" and not 1 <= int(value) <= 720:
            raise ValidationError("Scan interval must be between 1 and 720 hours.")
        if key == "name":
            value = str(value).strip()
            if not 1 <= len(value) <= 200:
                raise ValidationError("Vendor name must be between 1 and 200 characters.")
        if getattr(vendor, key) != value:
            setattr(vendor, key, value)
            changed[key] = value

    if changed:
        audit.record(
            session,
            action=AuditAction.VENDOR_UPDATED,
            organization_id=vendor.organization_id,
            actor_user_id=actor.id if actor else None,
            resource_type="vendor",
            resource_id=vendor.id,
            metadata={"fields": sorted(changed)},
        )
    session.flush()
    return vendor


def archive_vendor(session: Session, *, vendor: Vendor, actor: User | None = None) -> Vendor:
    vendor.status = "archived"
    vendor.next_scan_at = None
    audit.record(
        session,
        action=AuditAction.VENDOR_ARCHIVED,
        organization_id=vendor.organization_id,
        actor_user_id=actor.id if actor else None,
        resource_type="vendor",
        resource_id=vendor.id,
    )
    session.flush()
    return vendor


def delete_vendor(session: Session, *, vendor: Vendor, actor: User | None = None) -> None:
    organization_id = vendor.organization_id
    vendor_id = vendor.id
    session.delete(vendor)
    audit.record(
        session,
        action=AuditAction.VENDOR_DELETED,
        organization_id=organization_id,
        actor_user_id=actor.id if actor else None,
        resource_type="vendor",
        resource_id=vendor_id,
    )
    session.flush()


def schedule_next_scan(vendor: Vendor, *, interval_hours: int | None = None) -> None:
    hours = interval_hours or vendor.scan_interval_hours or 24
    vendor.next_scan_at = datetime.now(UTC) + timedelta(hours=hours)


def dashboard_summary(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """Aggregate dashboard counters in a single round trip per metric."""
    rows = session.execute(
        select(
            func.count(Vendor.id),
            func.count(Vendor.id).filter(Vendor.current_risk_level == "critical"),
            func.count(Vendor.id).filter(Vendor.current_risk_level == "high"),
            func.count(Vendor.id).filter(Vendor.current_risk_level == "medium"),
            func.count(Vendor.id).filter(Vendor.current_risk_level == "low"),
            func.count(Vendor.id).filter(Vendor.current_score.is_(None)),
            func.avg(Vendor.current_score),
        ).where(Vendor.organization_id == organization_id, Vendor.status == "active")
    ).one()

    open_findings = int(
        session.execute(
            select(func.count(Finding.id)).where(
                Finding.organization_id == organization_id,
                Finding.status.in_(["open", "in_progress"]),
            )
        ).scalar_one()
    )
    critical_findings = int(
        session.execute(
            select(func.count(Finding.id)).where(
                Finding.organization_id == organization_id,
                Finding.status.in_(["open", "in_progress"]),
                Finding.severity.in_(["critical", "high"]),
            )
        ).scalar_one()
    )
    scans_running = int(
        session.execute(
            select(func.count(Scan.id)).where(
                Scan.organization_id == organization_id,
                Scan.status.in_(["queued", "running"]),
            )
        ).scalar_one()
    )

    total, critical, high, medium, low, unscored, average = rows
    return {
        "total_vendors": int(total),
        "critical_vendors": int(critical),
        "high_risk_vendors": int(high),
        "medium_risk_vendors": int(medium),
        "low_risk_vendors": int(low),
        "unscored_vendors": int(unscored),
        "average_score": round(float(average), 1) if average is not None else None,
        "vendors_needing_attention": int(critical) + int(high),
        "open_findings": open_findings,
        "critical_open_findings": critical_findings,
        "scans_in_progress": scans_running,
    }
