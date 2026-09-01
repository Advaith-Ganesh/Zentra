"""Alert generation and delivery."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zentra.config import get_settings
from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.core.entitlements import Feature
from zentra.db.models import Alert, Organization, Scan, User, Vendor
from zentra.logging import get_logger

log = get_logger("zentra.alerts")


def _dedupe_key(vendor_id: uuid.UUID, kind: str, scan_id: uuid.UUID | None) -> str:
    return f"{vendor_id}:{kind}:{scan_id or 'none'}"


def evaluate_score_change(
    session: Session,
    *,
    vendor: Vendor,
    scan: Scan,
    old_score: int | None,
    new_score: int | None,
    threshold: int | None = None,
) -> Alert | None:
    """Raise an alert when a vendor's risk score worsens materially.

    A "material" change defaults to ``ALERT_SCORE_DELTA_THRESHOLD`` points and
    is configurable per organization via ``settings.alert_score_delta``.
    """
    if new_score is None:
        return None
    settings = get_settings()
    organization = session.get(Organization, vendor.organization_id)
    configured = None
    if organization is not None:
        raw = (organization.settings or {}).get("alert_score_delta")
        if isinstance(raw, int) and 1 <= raw <= 100:
            configured = raw
    limit = threshold or configured or settings.alert_score_delta_threshold

    if old_score is None:
        # First score for this vendor: only alert when it lands high.
        if scan.risk_level in ("high", "critical"):
            return create_alert(
                session,
                vendor=vendor,
                scan=scan,
                kind="score_increase",
                severity="high" if scan.risk_level == "high" else "critical",
                title=f"{vendor.name} scored {new_score}/100 ({scan.risk_level} risk)",
                message=(
                    f"Zentra's first assessment of {vendor.name} ({vendor.domain}) detected "
                    f"signals associated with {scan.risk_level} risk."
                ),
                old_score=None,
                new_score=new_score,
                reason="initial_high_risk",
            )
        return None

    delta = new_score - old_score
    if delta < limit:
        return None

    severity = "critical" if scan.risk_level == "critical" else "high" if delta >= 20 else "medium"
    return create_alert(
        session,
        vendor=vendor,
        scan=scan,
        kind="score_increase",
        severity=severity,
        title=f"{vendor.name}'s risk score rose by {delta} points",
        message=(
            f"{vendor.name} ({vendor.domain}) moved from {old_score} to {new_score} out of 100. "
            f"Zentra detected new or worsened signals in the latest assessment."
        ),
        old_score=old_score,
        new_score=new_score,
        reason=f"score_increase_{delta}",
    )


def create_alert(
    session: Session,
    *,
    vendor: Vendor,
    scan: Scan | None,
    kind: str,
    severity: str,
    title: str,
    message: str,
    old_score: int | None = None,
    new_score: int | None = None,
    reason: str | None = None,
) -> Alert | None:
    """Insert an alert. Idempotent per (organization, dedupe key)."""
    key = _dedupe_key(vendor.id, kind, scan.id if scan else None)
    alert = Alert(
        organization_id=vendor.organization_id,
        vendor_id=vendor.id,
        scan_id=scan.id if scan else None,
        kind=kind,
        severity=severity,
        title=title[:300],
        message=message,
        old_score=old_score,
        new_score=new_score,
        score_delta=(new_score - old_score)
        if (old_score is not None and new_score is not None)
        else None,
        reason=reason,
        dedupe_key=key,
    )
    session.add(alert)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        log.info("alert_deduplicated", vendor_id=str(vendor.id), kind=kind)
        return None
    log.info(
        "alert_created",
        alert_id=str(alert.id),
        organization_id=str(vendor.organization_id),
        vendor_id=str(vendor.id),
        kind=kind,
        severity=severity,
        score_delta=alert.score_delta,
    )
    return alert


def list_alerts(
    session: Session,
    organization_id: uuid.UUID,
    *,
    limit: int = 20,
    unacknowledged_only: bool = False,
) -> list[Alert]:
    query = select(Alert).where(Alert.organization_id == organization_id)
    if unacknowledged_only:
        query = query.where(Alert.acknowledged_at.is_(None))
    return list(
        session.execute(query.order_by(Alert.created_at.desc()).limit(min(limit, 200))).scalars()
    )


def acknowledge(session: Session, *, alert: Alert, actor: User) -> Alert:
    alert.acknowledged_at = datetime.now(UTC)
    alert.acknowledged_by = actor.id
    session.flush()
    return alert


def deliver_pending(session: Session, *, alert: Alert) -> None:
    """Send an alert over every enabled channel.

    Delivery failures are recorded on the alert rather than raised: an email
    outage must not roll back a completed scan.
    """
    from zentra.integrations.email.service import send_risk_alert
    from zentra.integrations.teams.client import notify_teams
    from zentra.services.organizations import entitlements_for, get_organization

    organization = get_organization(session, alert.organization_id)
    entitlements = entitlements_for(session, organization)
    if not entitlements.has(Feature.ALERTS):
        alert.notification_status = "suppressed"
        session.flush()
        log.info("alert_suppressed_plan", alert_id=str(alert.id), plan=entitlements.plan.value)
        return

    vendor = session.get(Vendor, alert.vendor_id) if alert.vendor_id else None
    recipients = _recipients(session, organization.id)
    delivered = False
    errors: list[str] = []

    if recipients:
        try:
            send_risk_alert(alert=alert, vendor=vendor, organization=organization, to=recipients)
            delivered = True
        except Exception as exc:  # noqa: BLE001 - never fail the scan on delivery
            errors.append(f"email:{type(exc).__name__}")
            log.warning("alert_email_failed", alert_id=str(alert.id), error=type(exc).__name__)

    try:
        if notify_teams(session, organization=organization, alert=alert, vendor=vendor):
            delivered = True
    except Exception as exc:  # noqa: BLE001
        errors.append(f"teams:{type(exc).__name__}")

    try:
        from zentra.integrations.slack.client import notify_slack

        if notify_slack(session, organization=organization, alert=alert, vendor=vendor):
            delivered = True
    except Exception as exc:  # noqa: BLE001
        errors.append(f"slack:{type(exc).__name__}")

    alert.notification_status = "sent" if delivered else "failed"
    alert.notified_at = datetime.now(UTC) if delivered else None
    if delivered:
        audit.record(
            session,
            action=AuditAction.ALERT_SENT,
            organization_id=organization.id,
            actor_type="system",
            resource_type="alert",
            resource_id=alert.id,
            metadata={"channels_failed": errors, "kind": alert.kind},
        )
    session.flush()


def _recipients(session: Session, organization_id: uuid.UUID) -> list[str]:
    from zentra.db.models import OrganizationMember

    rows = session.execute(
        select(User.email)
        .join(OrganizationMember, OrganizationMember.user_id == User.id)
        .where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.status == "active",
            OrganizationMember.role.in_(["owner", "admin", "analyst"]),
            User.deleted_at.is_(None),
        )
    ).scalars()
    return list(rows)[:20]
