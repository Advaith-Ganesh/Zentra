"""Slack OAuth callback and slash command."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Form, Header, Request, Response

from zentra.auth.deps import DbSession
from zentra.config import get_settings
from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.core.domains import normalize_domain
from zentra.core.feature_flags import Flag
from zentra.core.feature_flags import require as require_flag
from zentra.core.security import decode_token
from zentra.db.models import User, Vendor
from zentra.errors import AuthenticationError, ValidationError
from zentra.integrations.slack.client import (
    exchange_oauth_code,
    format_check_response,
    organization_for_team,
    store_installation,
    verify_slack_signature,
)
from zentra.logging import get_logger
from zentra.services.organizations import get_organization

log = get_logger("zentra.api.slack")

router = APIRouter(prefix="/integrations/slack", tags=["Integrations"])


@router.get("/callback", summary="Slack OAuth callback", include_in_schema=False)
async def slack_callback(
    request: Request,
    session: DbSession,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> Response:
    require_flag(Flag.SLACK)
    settings = get_settings()
    if error or not code or not state:
        return Response(
            status_code=302,
            headers={"Location": f"{settings.app_url}/dashboard/settings?slack=error"},
        )

    # `state` is a signed, short-lived token bound to the installing user and
    # organization; this is what prevents a forged callback.
    try:
        claims = decode_token(state, expected_type="slack_state")
        organization_id = uuid.UUID(str(claims["org"]))
        user_id = uuid.UUID(str(claims["sub"]))
    except (AuthenticationError, KeyError, ValueError):
        log.warning("slack_callback_bad_state")
        return Response(
            status_code=302,
            headers={"Location": f"{settings.app_url}/dashboard/settings?slack=invalid_state"},
        )

    organization = get_organization(session, organization_id)
    user = session.get(User, user_id)
    if user is None:
        raise AuthenticationError("The installing user no longer exists.")

    payload = exchange_oauth_code(code)
    store_installation(session, organization=organization, payload=payload, installed_by=user)
    audit.record(
        session,
        action=AuditAction.INTEGRATION_INSTALLED,
        organization_id=organization.id,
        actor_user_id=user.id,
        resource_type="integration",
        metadata={"provider": "slack"},
    )
    return Response(
        status_code=302,
        headers={"Location": f"{settings.app_url}/dashboard/settings?slack=connected"},
    )


@router.post("/commands", summary="Slack slash command", include_in_schema=False)
async def slack_command(
    request: Request,
    session: DbSession,
    x_slack_signature: Annotated[str | None, Header(alias="x-slack-signature")] = None,
    x_slack_request_timestamp: Annotated[
        str | None, Header(alias="x-slack-request-timestamp")
    ] = None,
    command: Annotated[str, Form()] = "",
    text: Annotated[str, Form()] = "",
    team_id: Annotated[str, Form()] = "",
) -> dict[str, object]:
    """Handle `/zentra check <domain>`.

    The raw body is verified against Slack's signing secret before anything
    else happens.
    """
    require_flag(Flag.SLACK)
    body = await request.body()
    if not verify_slack_signature(
        body=body, timestamp=x_slack_request_timestamp, signature=x_slack_signature
    ):
        log.warning("slack_command_bad_signature")
        raise AuthenticationError("Slack signature verification failed.", code="INVALID_SIGNATURE")

    organization_id = organization_for_team(session, team_id)
    if organization_id is None:
        return {
            "response_type": "ephemeral",
            "text": "This Slack workspace is not connected to a Zentra organization.",
        }

    parts = text.strip().split()
    if not parts or parts[0].lower() != "check" or len(parts) < 2:
        return {
            "response_type": "ephemeral",
            "text": "Usage: `/zentra check example.com`",
        }

    try:
        domain = normalize_domain(parts[1])
    except ValidationError:
        return {"response_type": "ephemeral", "text": "That does not look like a valid domain."}

    from sqlalchemy import func, select

    vendor = session.execute(
        select(Vendor).where(
            Vendor.organization_id == organization_id,
            func.lower(Vendor.domain) == domain,
        )
    ).scalar_one_or_none()

    if vendor is None:
        return {
            "response_type": "ephemeral",
            "text": (
                f"{domain} is not in your Zentra vendor list. Add it in the dashboard to start "
                "monitoring it."
            ),
        }

    from zentra.services.scans import latest_completed_scan

    latest = latest_completed_scan(session, vendor.id)
    headline = (
        (latest.verdict or {}).get("headline", "No assessment yet.")
        if latest
        else ("This vendor has not been assessed yet.")
    )
    return format_check_response(
        domain=domain,
        vendor_name=vendor.name,
        score=vendor.current_score,
        risk_level=vendor.current_risk_level,
        headline=str(headline),
    )
