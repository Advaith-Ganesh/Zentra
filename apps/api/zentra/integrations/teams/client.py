"""Microsoft Teams integration via incoming webhooks.

Teams incoming webhooks need no OAuth app: the customer pastes a webhook URL
from their channel. The URL is a bearer secret, so it is encrypted at rest and
never returned by the API.

The webhook URL is validated against the SSRF guard before any request, because
it is user-supplied.
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from zentra.config import get_settings
from zentra.core.crypto import decrypt_secret, encrypt_secret, encryption_available
from zentra.core.feature_flags import Flag, is_enabled
from zentra.db.models import Alert, IntegrationConnection, Organization, User, Vendor
from zentra.errors import ValidationError
from zentra.logging import get_logger

log = get_logger("zentra.teams")

#: Only Microsoft-operated webhook hosts are accepted.
ALLOWED_WEBHOOK_SUFFIXES = (
    ".webhook.office.com",
    ".office.com",
    ".microsoft.com",
    ".logic.azure.com",
)


def teams_enabled() -> bool:
    return is_enabled(Flag.TEAMS) and encryption_available()


def validate_webhook_url(url: str) -> str:
    """Reject anything that is not an https Microsoft webhook endpoint."""
    if not isinstance(url, str) or len(url) > 2000:
        raise ValidationError("The webhook URL is not valid.", code="INVALID_WEBHOOK_URL")
    parsed = urlparse(url.strip())
    if parsed.scheme != "https":
        raise ValidationError("The webhook URL must use https.", code="INVALID_WEBHOOK_URL")
    host = (parsed.hostname or "").lower()
    if not host or not any(host.endswith(suffix) for suffix in ALLOWED_WEBHOOK_SUFFIXES):
        raise ValidationError(
            "The webhook URL must be a Microsoft Teams incoming webhook address.",
            code="INVALID_WEBHOOK_URL",
        )
    return url.strip()


def connect(
    session: Session,
    *,
    organization: Organization,
    webhook_url: str,
    actor: User,
    label: str | None = None,
) -> IntegrationConnection:
    if not teams_enabled():
        raise ValidationError("Teams integration is not enabled.", code="TEAMS_DISABLED")
    validated = validate_webhook_url(webhook_url)

    connection = (
        session.execute(
            select(IntegrationConnection).where(
                IntegrationConnection.organization_id == organization.id,
                IntegrationConnection.provider == "teams",
            )
        )
        .scalars()
        .first()
    )
    if connection is None:
        connection = IntegrationConnection(
            organization_id=organization.id, provider="teams", created_by=actor.id
        )
        session.add(connection)
    connection.display_name = (label or "Microsoft Teams")[:100]
    connection.status = "active"
    connection.encrypted_secret = encrypt_secret(validated)
    connection.config = {"host": urlparse(validated).hostname}
    session.flush()
    log.info("teams_connected", organization_id=str(organization.id))
    return connection


def disconnect(session: Session, *, organization_id: uuid.UUID) -> bool:
    connection = (
        session.execute(
            select(IntegrationConnection).where(
                IntegrationConnection.organization_id == organization_id,
                IntegrationConnection.provider == "teams",
            )
        )
        .scalars()
        .first()
    )
    if connection is None:
        return False
    session.delete(connection)
    session.flush()
    return True


def _card(title: str, message: str, facts: list[tuple[str, str]], url: str) -> dict[str, Any]:
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "111318",
        "summary": title[:150],
        "title": title[:150],
        "text": message[:4000],
        "sections": [{"facts": [{"name": name, "value": value} for name, value in facts]}],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "Review in Zentra",
                "targets": [{"os": "default", "uri": url}],
            }
        ],
    }


def notify_teams(
    session: Session, *, organization: Organization, alert: Alert, vendor: Vendor | None
) -> bool:
    if not teams_enabled():
        return False
    connection = (
        session.execute(
            select(IntegrationConnection).where(
                IntegrationConnection.organization_id == organization.id,
                IntegrationConnection.provider == "teams",
                IntegrationConnection.status == "active",
            )
        )
        .scalars()
        .first()
    )
    if connection is None or not connection.encrypted_secret:
        return False
    try:
        webhook_url = validate_webhook_url(decrypt_secret(connection.encrypted_secret))
    except Exception:  # noqa: BLE001
        log.warning("teams_secret_unusable", organization_id=str(organization.id))
        return False

    settings = get_settings()
    url = (
        f"{settings.app_url}/dashboard/vendors/{vendor.id}"
        if vendor
        else f"{settings.app_url}/dashboard"
    )
    facts: list[tuple[str, str]] = []
    if vendor:
        facts.append(("Vendor", f"{vendor.name} ({vendor.domain})"))
    if alert.old_score is not None and alert.new_score is not None:
        facts.append(("Score change", f"{alert.old_score} → {alert.new_score}"))
    facts.append(("Severity", alert.severity.title()))

    try:
        response = httpx.post(
            webhook_url,
            json=_card(alert.title, alert.message, facts, url),
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        log.warning("teams_post_failed", error=type(exc).__name__)
        return False
    if response.status_code >= 400:
        log.warning("teams_post_rejected", status=response.status_code)
        return False
    return True
