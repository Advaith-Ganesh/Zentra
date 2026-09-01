"""Slack integration.

Feature flagged: disabled entirely unless SLACK_CLIENT_ID, SLACK_CLIENT_SECRET
and SLACK_SIGNING_SECRET are all configured. Bot tokens are encrypted at rest
and never leave the backend.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from zentra.config import get_settings
from zentra.core.crypto import decrypt_secret, encrypt_secret, encryption_available
from zentra.core.feature_flags import Flag, is_enabled
from zentra.db.models import Alert, Organization, SlackWorkspace, User, Vendor
from zentra.errors import ProviderError, ValidationError
from zentra.logging import get_logger

log = get_logger("zentra.slack")

OAUTH_AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
OAUTH_ACCESS_URL = "https://slack.com/api/oauth.v2.access"
POST_MESSAGE_URL = "https://slack.com/api/chat.postMessage"
SCOPES = "commands,chat:write,chat:write.public"

#: Slack requires replay protection: reject anything older than five minutes.
MAX_TIMESTAMP_SKEW_SECONDS = 60 * 5


def slack_enabled() -> bool:
    return is_enabled(Flag.SLACK) and encryption_available()


def verify_slack_signature(
    *, body: bytes, timestamp: str | None, signature: str | None, signing_secret: str | None = None
) -> bool:
    """Verify Slack's v0 request signature.

    Returns False for any missing, stale or mismatched signature.
    """
    secret = signing_secret if signing_secret is not None else get_settings().slack_signing_secret
    if not secret or not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts) > MAX_TIMESTAMP_SKEW_SECONDS:
        return False
    basestring = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def build_install_url(*, state: str) -> str:
    settings = get_settings()
    if not slack_enabled():
        raise ValidationError("Slack is not enabled for this deployment.", code="SLACK_DISABLED")
    from urllib.parse import urlencode

    params = {
        "client_id": settings.slack_client_id,
        "scope": SCOPES,
        "state": state,
        "redirect_uri": f"{settings.api_url}/api/v1/integrations/slack/callback",
    }
    return f"{OAUTH_AUTHORIZE_URL}?{urlencode(params)}"


def exchange_oauth_code(code: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        response = httpx.post(
            OAUTH_ACCESS_URL,
            data={
                "code": code,
                "client_id": settings.slack_client_id,
                "client_secret": settings.slack_client_secret,
                "redirect_uri": f"{settings.api_url}/api/v1/integrations/slack/callback",
            },
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        raise ProviderError("Slack could not be reached.") from exc
    try:
        payload = response.json()
    except ValueError as exc:
        raise ProviderError("Slack returned an unreadable response.") from exc
    if not payload.get("ok"):
        # Slack's error codes are safe to surface; tokens are never in them.
        raise ProviderError(f"Slack rejected the installation: {payload.get('error', 'unknown')}")
    return payload


def store_installation(
    session: Session, *, organization: Organization, payload: dict[str, Any], installed_by: User
) -> SlackWorkspace:
    team = payload.get("team") or {}
    token = payload.get("access_token") or ""
    if not token:
        raise ProviderError("Slack did not return an access token.")

    team_id = str(team.get("id", ""))[:50]
    workspace = session.execute(
        select(SlackWorkspace).where(SlackWorkspace.team_id == team_id)
    ).scalar_one_or_none()
    if workspace is None:
        workspace = SlackWorkspace(organization_id=organization.id, team_id=team_id)
        session.add(workspace)
    workspace.organization_id = organization.id
    workspace.team_name = str(team.get("name", ""))[:200] or None
    workspace.bot_user_id = str(payload.get("bot_user_id", ""))[:50] or None
    workspace.encrypted_bot_token = encrypt_secret(token)
    workspace.scopes = str(payload.get("scope", ""))[:500] or None
    workspace.installed_by = installed_by.id
    session.flush()
    log.info(
        "slack_installed",
        organization_id=str(organization.id),
        team_id=team_id,
    )
    return workspace


def workspace_for(session: Session, organization_id: uuid.UUID) -> SlackWorkspace | None:
    return (
        session.execute(
            select(SlackWorkspace).where(SlackWorkspace.organization_id == organization_id)
        )
        .scalars()
        .first()
    )


def organization_for_team(session: Session, team_id: str) -> uuid.UUID | None:
    row = session.execute(
        select(SlackWorkspace.organization_id).where(SlackWorkspace.team_id == team_id)
    ).scalar_one_or_none()
    return row


def post_message(
    session: Session, *, organization_id: uuid.UUID, blocks: list[dict[str, Any]], text: str
) -> bool:
    if not slack_enabled():
        return False
    workspace = workspace_for(session, organization_id)
    if workspace is None or not workspace.default_channel_id:
        return False
    try:
        token = decrypt_secret(workspace.encrypted_bot_token)
    except Exception:  # noqa: BLE001
        log.warning("slack_token_decrypt_failed", organization_id=str(organization_id))
        return False
    try:
        response = httpx.post(
            POST_MESSAGE_URL,
            json={"channel": workspace.default_channel_id, "text": text, "blocks": blocks},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("slack_post_failed", error=type(exc).__name__)
        return False
    if not payload.get("ok"):
        log.warning("slack_post_rejected", error=str(payload.get("error"))[:80])
        return False
    return True


def notify_slack(
    session: Session, *, organization: Organization, alert: Alert, vendor: Vendor | None
) -> bool:
    if not slack_enabled():
        return False
    settings = get_settings()
    url = (
        f"{settings.app_url}/dashboard/vendors/{vendor.id}"
        if vendor
        else f"{settings.app_url}/dashboard"
    )
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": alert.title[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": alert.message[:2900]}},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Review in Zentra"},
                    "url": url,
                }
            ],
        },
    ]
    return post_message(
        session, organization_id=organization.id, blocks=blocks, text=alert.title[:200]
    )


def format_check_response(
    *,
    domain: str,
    vendor_name: str | None,
    score: int | None,
    risk_level: str | None,
    headline: str,
) -> dict[str, Any]:
    """Response body for the `/zentra check <domain>` slash command."""
    if score is None or risk_level is None:
        summary = f"*{domain}* — assessment incomplete. {headline}"
    else:
        summary = (
            f"*{vendor_name or domain}* ({domain})\n"
            f"Risk score: *{score}/100* — {risk_level.upper()}\n"
            f"{headline}"
        )
    return {
        "response_type": "ephemeral",
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": summary[:2900]}}],
        "text": summary[:200],
    }
