"""API key issuance and revocation.

Only a SHA-256 hash of each key is stored. The plaintext secret is returned to
the caller exactly once, at creation, and cannot be recovered afterwards.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.core.security import generate_api_key
from zentra.db.models import ApiKey, Organization, User
from zentra.errors import NotFoundError, ValidationError

DEFAULT_SCOPES = ("vendors:read", "vendors:write", "scans:write", "reports:read")
VALID_SCOPES = frozenset(
    {"vendors:read", "vendors:write", "scans:write", "reports:read", "findings:write"}
)
MAX_ACTIVE_KEYS = 20


def create_api_key(
    session: Session,
    *,
    organization: Organization,
    actor: User,
    name: str,
    scopes: list[str] | None = None,
    expires_in_days: int | None = None,
) -> tuple[ApiKey, str]:
    name = (name or "").strip()
    if not 1 <= len(name) <= 100:
        raise ValidationError("API key name must be between 1 and 100 characters.")

    active = (
        session.execute(
            select(ApiKey).where(
                ApiKey.organization_id == organization.id, ApiKey.revoked_at.is_(None)
            )
        )
        .scalars()
        .all()
    )
    if len(active) >= MAX_ACTIVE_KEYS:
        raise ValidationError(
            f"An organization may hold at most {MAX_ACTIVE_KEYS} active API keys. "
            "Revoke an unused key first.",
            code="TOO_MANY_API_KEYS",
        )

    requested = scopes or list(DEFAULT_SCOPES)
    invalid = sorted(set(requested) - VALID_SCOPES)
    if invalid:
        raise ValidationError(f"Unknown scope(s): {', '.join(invalid)}.", code="INVALID_SCOPE")

    secret, prefix, key_hash = generate_api_key()
    record = ApiKey(
        organization_id=organization.id,
        name=name,
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=requested,
        created_by=actor.id,
        expires_at=(
            datetime.now(UTC) + timedelta(days=expires_in_days) if expires_in_days else None
        ),
    )
    session.add(record)
    session.flush()
    audit.record(
        session,
        action=AuditAction.API_KEY_CREATED,
        organization_id=organization.id,
        actor_user_id=actor.id,
        resource_type="api_key",
        resource_id=record.id,
        metadata={"name": name, "scopes": requested, "key_prefix": prefix},
    )
    return record, secret


def list_api_keys(session: Session, organization_id: uuid.UUID) -> list[ApiKey]:
    return list(
        session.execute(
            select(ApiKey)
            .where(ApiKey.organization_id == organization_id)
            .order_by(ApiKey.created_at.desc())
        ).scalars()
    )


def revoke_api_key(
    session: Session, *, organization_id: uuid.UUID, key_id: uuid.UUID, actor: User
) -> ApiKey:
    record = session.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.organization_id == organization_id)
    ).scalar_one_or_none()
    if record is None:
        raise NotFoundError("API key could not be found.", code="API_KEY_NOT_FOUND")
    if record.revoked_at is None:
        record.revoked_at = datetime.now(UTC)
        audit.record(
            session,
            action=AuditAction.API_KEY_REVOKED,
            organization_id=organization_id,
            actor_user_id=actor.id,
            resource_type="api_key",
            resource_id=record.id,
            metadata={"key_prefix": record.key_prefix},
        )
    session.flush()
    return record
