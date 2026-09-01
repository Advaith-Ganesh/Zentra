"""Account, organization, membership, alert and dashboard endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, Path, Query, UploadFile, status

from zentra.api.schemas import (
    AlertResponse,
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeyResponse,
    BenchmarkResponse,
    DashboardResponse,
    IntegrationResponse,
    InviteRequest,
    MembershipResponse,
    MeResponse,
    OrganizationResponse,
    OrganizationSummary,
    OrganizationUpdateRequest,
    ScanResponse,
    TeamsConnectRequest,
    UserResponse,
)
from zentra.api.v1.vendors import _vendor_response
from zentra.auth.deps import CurrentPrincipal, DbSession, Principal, require_role
from zentra.config import get_settings
from zentra.core.entitlements import Feature
from zentra.core.feature_flags import Flag, all_flags, is_enabled
from zentra.core.feature_flags import require as require_flag
from zentra.errors import NotFoundError, ValidationError
from zentra.logging import get_logger
from zentra.reports.pdf import sanitize_color, sanitize_logo
from zentra.services import alerts as alerts_service
from zentra.services import api_keys as api_keys_service
from zentra.services import benchmark as benchmark_service
from zentra.services import scans as scans_service
from zentra.services import vendors as vendors_service
from zentra.services.organizations import (
    entitlements_for,
    invite_member,
    list_members,
    list_memberships,
    remove_member,
)

log = get_logger("zentra.api.me")

router = APIRouter(tags=["Account"])


def _user_response(user) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_platform_admin=user.is_platform_admin,
        email_verified=user.email_verified_at is not None,
        created_at=user.created_at,
    )


@router.get("/me", response_model=MeResponse, summary="Current user, organization and entitlements")
async def me(principal: CurrentPrincipal, session: DbSession) -> MeResponse:
    entitlements = entitlements_for(session, principal.organization)
    memberships = list_memberships(session, principal.user.id) if principal.kind == "user" else []
    return MeResponse(
        user=_user_response(principal.user),
        organization=OrganizationResponse.model_validate(principal.organization),
        role=principal.role,
        entitlements=entitlements.to_dict(),
        feature_flags=all_flags(),
        organizations=[
            OrganizationSummary(
                id=m.organization.id,
                name=m.organization.name,
                slug=m.organization.slug,
                role=m.role,
            )
            for m in memberships
        ],
    )


@router.get(
    "/organization", response_model=OrganizationResponse, summary="Get the current organization"
)
async def get_organization(principal: CurrentPrincipal) -> OrganizationResponse:
    return OrganizationResponse.model_validate(principal.organization)


@router.patch(
    "/organization", response_model=OrganizationResponse, summary="Update the organization"
)
async def update_organization(
    payload: OrganizationUpdateRequest,
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
) -> OrganizationResponse:
    organization = principal.organization
    data = payload.model_dump(exclude_none=True)
    alert_delta = data.pop("alert_score_delta", None)
    for key, value in data.items():
        setattr(organization, key, value)
    if alert_delta is not None:
        organization.settings = {**(organization.settings or {}), "alert_score_delta": alert_delta}
    session.flush()
    return OrganizationResponse.model_validate(organization)


@router.put(
    "/organization/branding",
    response_model=OrganizationResponse,
    summary="Set white-label report branding",
    description="Scale plan only. Values are sanitized before they reach the PDF renderer.",
)
async def set_branding(
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
    company_name: Annotated[str | None, Query(max_length=80)] = None,
    brand_color: Annotated[str | None, Query(max_length=7)] = None,
) -> OrganizationResponse:
    require_flag(Flag.WHITE_LABEL)
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.WHITE_LABEL_REPORTS)

    branding = dict(principal.organization.branding or {})
    if company_name is not None:
        branding["company_name"] = company_name.strip()[:80] or None
    if brand_color is not None:
        cleaned = sanitize_color(brand_color)
        if brand_color and not cleaned:
            raise ValidationError(
                "Brand colour must be a hex value such as #1a1a1a.", code="INVALID_COLOR"
            )
        branding["brand_color"] = cleaned
    principal.organization.branding = branding
    session.flush()
    return OrganizationResponse.model_validate(principal.organization)


@router.post(
    "/organization/branding/logo",
    response_model=OrganizationResponse,
    summary="Upload a white-label report logo",
    description="PNG, JPEG or GIF, validated by file signature, not by filename.",
)
async def upload_logo(
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
    file: Annotated[UploadFile, File(description="PNG, JPEG or GIF logo.")],
) -> OrganizationResponse:
    require_flag(Flag.WHITE_LABEL)
    settings = get_settings()
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.WHITE_LABEL_REPORTS)

    data = await file.read(settings.max_logo_bytes + 1)
    if len(data) > settings.max_logo_bytes:
        raise ValidationError(
            f"The logo must be {settings.max_logo_bytes // 1024} KB or smaller.",
            code="LOGO_TOO_LARGE",
        )
    data_uri, error = sanitize_logo(data, max_bytes=settings.max_logo_bytes)
    if error or not data_uri:
        raise ValidationError(error or "The logo could not be read.", code="INVALID_LOGO")

    principal.organization.branding = {
        **(principal.organization.branding or {}),
        "logo_data_uri": data_uri,
    }
    session.flush()
    return OrganizationResponse.model_validate(principal.organization)


@router.get(
    "/organization/members", response_model=list[MembershipResponse], summary="List members"
)
async def members(principal: CurrentPrincipal, session: DbSession) -> list[MembershipResponse]:
    return [
        MembershipResponse(
            id=member.id,
            user_id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=member.role,
            status=member.status,
            created_at=member.created_at,
        )
        for member, user in list_members(session, principal.organization.id)
    ]


@router.post(
    "/organization/members/invite",
    status_code=status.HTTP_201_CREATED,
    summary="Invite a teammate",
)
async def invite(
    payload: InviteRequest,
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
) -> dict[str, str]:
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.MULTI_USER)
    invitation, token = invite_member(
        session,
        organization=principal.organization,
        email=payload.email,
        role=payload.role,
        invited_by=principal.user,
    )
    try:
        from zentra.integrations.email.service import send_invitation

        send_invitation(
            to_email=payload.email,
            organization=principal.organization,
            token=token,
            inviter=principal.user,
        )
    except Exception as exc:  # noqa: BLE001 - the invitation still exists and can be resent
        log.warning("invitation_email_failed", error_type=type(exc).__name__)
    return {"invitation_id": str(invitation.id), "message": "Invitation sent."}


@router.delete(
    "/organization/members/{member_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Remove a member",
)
async def remove(
    member_id: Annotated[uuid.UUID, Path()],
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
) -> None:
    remove_member(
        session,
        organization=principal.organization,
        member_id=member_id,
        actor=principal.user,
    )


# ------------------------------------------------------------------ dashboard
@router.get("/dashboard", response_model=DashboardResponse, summary="Dashboard overview")
async def dashboard(principal: CurrentPrincipal, session: DbSession) -> DashboardResponse:
    organization_id = principal.organization.id
    summary = vendors_service.dashboard_summary(session, organization_id)
    attention, _ = vendors_service.list_vendors(
        session,
        organization_id,
        risk_levels=["critical", "high"],
        sort="current_score",
        direction="desc",
        limit=5,
    )
    return DashboardResponse(
        summary=summary,
        vendors_needing_attention=[_vendor_response(v) for v in attention],
        recent_alerts=[
            AlertResponse.model_validate(a)
            for a in alerts_service.list_alerts(session, organization_id, limit=5)
        ],
        recent_scans=[
            ScanResponse.model_validate(s)
            for s in scans_service.list_scans(session, organization_id, limit=8)
        ],
        entitlements=entitlements_for(session, principal.organization).to_dict(),
    )


# ------------------------------------------------------------------ alerts
alerts_router = APIRouter(prefix="/alerts", tags=["Alerts"])


@alerts_router.get("", response_model=list[AlertResponse], summary="List alerts")
async def list_alerts(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    unacknowledged: bool = False,
) -> list[AlertResponse]:
    return [
        AlertResponse.model_validate(a)
        for a in alerts_service.list_alerts(
            session, principal.organization.id, limit=limit, unacknowledged_only=unacknowledged
        )
    ]


@alerts_router.post(
    "/{alert_id}/acknowledge", response_model=AlertResponse, summary="Acknowledge an alert"
)
async def acknowledge_alert(
    alert_id: Annotated[uuid.UUID, Path()],
    principal: Annotated[Principal, Depends(require_role("analyst"))],
    session: DbSession,
) -> AlertResponse:
    from sqlalchemy import select

    from zentra.db.models import Alert

    alert = session.execute(
        select(Alert).where(
            Alert.id == alert_id, Alert.organization_id == principal.organization.id
        )
    ).scalar_one_or_none()
    if alert is None:
        raise NotFoundError("Alert could not be found.", code="ALERT_NOT_FOUND")
    alerts_service.acknowledge(session, alert=alert, actor=principal.user)
    return AlertResponse.model_validate(alert)


# ------------------------------------------------------------------ api keys
keys_router = APIRouter(prefix="/api-keys", tags=["API keys"])


@keys_router.get("", response_model=list[ApiKeyResponse], summary="List API keys")
async def list_keys(
    principal: Annotated[Principal, Depends(require_role("admin"))], session: DbSession
) -> list[ApiKeyResponse]:
    require_flag(Flag.PUBLIC_API)
    return [
        ApiKeyResponse.model_validate(k)
        for k in api_keys_service.list_api_keys(session, principal.organization.id)
    ]


@keys_router.post(
    "",
    response_model=ApiKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an API key",
    description=(
        "Scale plan only. The secret is returned exactly once — Zentra stores only a hash "
        "and cannot show it again."
    ),
)
async def create_key(
    payload: ApiKeyCreateRequest,
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
) -> ApiKeyCreatedResponse:
    require_flag(Flag.PUBLIC_API)
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.PUBLIC_API)
    record, secret = api_keys_service.create_api_key(
        session,
        organization=principal.organization,
        actor=principal.user,
        name=payload.name,
        scopes=payload.scopes,
        expires_in_days=payload.expires_in_days,
    )
    return ApiKeyCreatedResponse(api_key=ApiKeyResponse.model_validate(record), secret=secret)


@keys_router.delete("/{key_id}", response_model=ApiKeyResponse, summary="Revoke an API key")
async def revoke_key(
    key_id: Annotated[uuid.UUID, Path()],
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
) -> ApiKeyResponse:
    record = api_keys_service.revoke_api_key(
        session,
        organization_id=principal.organization.id,
        key_id=key_id,
        actor=principal.user,
    )
    return ApiKeyResponse.model_validate(record)


# ------------------------------------------------------------------ benchmark
benchmark_router = APIRouter(prefix="/benchmark", tags=["Benchmarking"])


@benchmark_router.get(
    "",
    response_model=BenchmarkResponse,
    summary="Compare your vendor stack against an anonymized cohort",
    description=(
        "Only returns a benchmark when the cohort contains enough organizations to be "
        "statistically meaningful and anonymous. The sample size returned is the real one."
    ),
)
async def benchmark(principal: CurrentPrincipal, session: DbSession) -> BenchmarkResponse:
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.BENCHMARKING)
    return BenchmarkResponse.model_validate(
        benchmark_service.for_organization(session, principal.organization)
    )


# ------------------------------------------------------------------ integrations
integrations_router = APIRouter(prefix="/integrations", tags=["Integrations"])


@integrations_router.get(
    "", response_model=list[IntegrationResponse], summary="List connected integrations"
)
async def list_integrations(
    principal: Annotated[Principal, Depends(require_role("admin"))], session: DbSession
) -> list[IntegrationResponse]:
    from sqlalchemy import select

    from zentra.db.models import IntegrationConnection

    rows = session.execute(
        select(IntegrationConnection).where(
            IntegrationConnection.organization_id == principal.organization.id
        )
    ).scalars()
    return [IntegrationResponse.model_validate(r) for r in rows]


@integrations_router.post(
    "/teams",
    response_model=IntegrationResponse,
    summary="Connect a Microsoft Teams incoming webhook",
)
async def connect_teams(
    payload: TeamsConnectRequest,
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
) -> IntegrationResponse:
    require_flag(Flag.TEAMS)
    from zentra.integrations.teams.client import connect

    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.INTEGRATIONS)
    connection = connect(
        session,
        organization=principal.organization,
        webhook_url=payload.webhook_url,
        actor=principal.user,
        label=payload.label,
    )
    return IntegrationResponse.model_validate(connection)


@integrations_router.delete(
    "/teams",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Disconnect Teams",
)
async def disconnect_teams(
    principal: Annotated[Principal, Depends(require_role("admin"))], session: DbSession
) -> None:
    from zentra.integrations.teams.client import disconnect

    disconnect(session, organization_id=principal.organization.id)


@integrations_router.get("/slack/install-url", summary="Get the Slack OAuth installation URL")
async def slack_install_url(
    principal: Annotated[Principal, Depends(require_role("admin"))], session: DbSession
) -> dict[str, str]:
    require_flag(Flag.SLACK)
    from zentra.core.security import create_access_token
    from zentra.integrations.slack.client import build_install_url

    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.INTEGRATIONS)
    # The OAuth state is a short-lived signed token bound to the organization,
    # which also serves as the CSRF defence for the callback.
    state = create_access_token(
        str(principal.user.id),
        ttl_seconds=600,
        extra_claims={"typ": "slack_state", "org": str(principal.organization.id)},
    )
    return {"install_url": build_install_url(state=state)}


def slack_available() -> bool:
    return is_enabled(Flag.SLACK)
