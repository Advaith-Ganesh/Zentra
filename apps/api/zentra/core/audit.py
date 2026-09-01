"""Structured audit logging.

Audit records are written to the database (tenant-scoped, queryable by the
customer) *and* emitted to the structured log stream. Payloads pass through the
same redaction processor as every other log line.
"""

from __future__ import annotations

import ipaddress
import uuid
from enum import StrEnum
from typing import Any

from sqlalchemy.orm import Session

from zentra.db.models import AuditLog
from zentra.logging import get_logger, request_id_var

log = get_logger("zentra.audit")


class AuditAction(StrEnum):
    USER_SIGNED_UP = "user.signed_up"
    USER_SIGNED_IN = "user.signed_in"
    USER_SIGNED_OUT = "user.signed_out"
    USER_PASSWORD_RESET_REQUESTED = "user.password_reset_requested"  # noqa: S105 - an action name

    ORGANIZATION_CREATED = "organization.created"
    ORGANIZATION_UPDATED = "organization.updated"

    MEMBER_INVITED = "member.invited"
    MEMBER_JOINED = "member.joined"
    MEMBER_REMOVED = "member.removed"
    MEMBER_ROLE_CHANGED = "member.role_changed"

    VENDOR_CREATED = "vendor.created"
    VENDOR_UPDATED = "vendor.updated"
    VENDOR_DELETED = "vendor.deleted"
    VENDOR_ARCHIVED = "vendor.archived"

    SCAN_TRIGGERED = "scan.triggered"
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"

    FINDING_UPDATED = "finding.updated"
    FINDING_ASSIGNED = "finding.assigned"

    REPORT_GENERATED = "report.generated"
    REPORT_DOWNLOADED = "report.downloaded"

    SUBSCRIPTION_CHANGED = "subscription.changed"
    CHECKOUT_STARTED = "billing.checkout_started"

    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"

    INTEGRATION_INSTALLED = "integration.installed"
    INTEGRATION_REMOVED = "integration.removed"

    ALERT_SENT = "alert.sent"
    API_ERROR = "api.error"


def _valid_ip(value: str | None) -> str | None:
    """The audit column is INET; anything that is not an address is dropped."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def record(
    session: Session,
    *,
    action: AuditAction | str,
    organization_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    actor_api_key_id: uuid.UUID | None = None,
    actor_type: str = "user",
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
    metadata: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditLog:
    """Append an audit entry. Never raises into the caller's happy path."""
    action_value = action.value if isinstance(action, AuditAction) else action
    entry = AuditLog(
        organization_id=organization_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        actor_api_key_id=actor_api_key_id,
        action=action_value,
        resource_type=resource_type,
        resource_id=resource_id,
        audit_metadata=metadata or {},
        ip_address=_valid_ip(ip_address),
        user_agent=(user_agent or "")[:500] or None,
        request_id=request_id_var.get(),
    )
    session.add(entry)
    log.info(
        "audit",
        action=action_value,
        organization_id=str(organization_id) if organization_id else None,
        actor_user_id=str(actor_user_id) if actor_user_id else None,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        **(metadata or {}),
    )
    return entry
