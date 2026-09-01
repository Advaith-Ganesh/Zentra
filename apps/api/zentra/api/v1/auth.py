"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request, status

from zentra.api.middleware import client_ip
from zentra.api.schemas import (
    AcceptInviteRequest,
    AuthResponse,
    OrganizationResponse,
    PasswordResetRequest,
    SignInRequest,
    SignUpRequest,
    UserResponse,
)
from zentra.auth.deps import CurrentPrincipal, DbSession
from zentra.auth.providers import get_auth_provider, normalize_email
from zentra.config import get_settings
from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.core.ratelimit import check_rate_limit
from zentra.core.security import pseudonymize
from zentra.errors import RateLimitedError
from zentra.logging import get_logger
from zentra.services.organizations import accept_invitation, create_organization, list_memberships

log = get_logger("zentra.api.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _enforce_auth_rate_limit(request: Request, email: str | None = None) -> None:
    """Rate limit by client IP and, separately, by the email being targeted.

    The per-email bucket blunts credential stuffing that rotates source IPs.
    """
    settings = get_settings()
    limit, window = settings.rate("auth")
    identifier = pseudonymize(client_ip(request))
    result = check_rate_limit("auth", identifier, limit, window)
    if not result.allowed:
        log.warning("auth_rate_limited", scope="ip")
        raise RateLimitedError(
            "Too many authentication attempts. Please wait and try again.",
            retry_after=result.retry_after,
        )
    if email:
        email_result = check_rate_limit("auth_email", pseudonymize(email.lower()), limit, window)
        if not email_result.allowed:
            log.warning("auth_rate_limited", scope="email")
            raise RateLimitedError(
                "Too many authentication attempts for this account. Please wait and try again.",
                retry_after=email_result.retry_after,
            )


def _user_response(user) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_platform_admin=user.is_platform_admin,
        email_verified=user.email_verified_at is not None,
        created_at=user.created_at,
    )


@router.post(
    "/signup",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an account and its organization",
    responses={
        409: {"description": "An account with that email already exists."},
        422: {"description": "Password too weak or email invalid."},
        429: {"description": "Too many attempts."},
    },
)
async def sign_up(payload: SignUpRequest, request: Request, session: DbSession) -> AuthResponse:
    """Register a user, create their organization and make them its owner."""
    _enforce_auth_rate_limit(request, payload.email)
    provider = get_auth_provider()
    auth_session = provider.sign_up(
        session,
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
    )
    organization = create_organization(
        session,
        name=payload.organization_name,
        owner=auth_session.user,
        industry=payload.industry,
        company_size=payload.company_size,
    )
    audit.record(
        session,
        action=AuditAction.USER_SIGNED_UP,
        organization_id=organization.id,
        actor_user_id=auth_session.user.id,
        resource_type="user",
        resource_id=auth_session.user.id,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    try:
        from zentra.integrations.email.service import send_welcome

        send_welcome(user=auth_session.user, organization=organization)
    except Exception as exc:  # noqa: BLE001 - a welcome email must not block signup
        log.warning("welcome_email_failed", error_type=type(exc).__name__)

    return AuthResponse(
        access_token=auth_session.access_token,
        refresh_token=auth_session.refresh_token,
        expires_in=auth_session.expires_in,
        email_verification_required=auth_session.email_verification_required,
        user=_user_response(auth_session.user),
        organization=OrganizationResponse.model_validate(organization),
    )


@router.post(
    "/signin",
    response_model=AuthResponse,
    summary="Sign in with email and password",
    responses={
        401: {"description": "Invalid credentials."},
        429: {"description": "Too many attempts."},
    },
)
async def sign_in(payload: SignInRequest, request: Request, session: DbSession) -> AuthResponse:
    _enforce_auth_rate_limit(request, payload.email)
    provider = get_auth_provider()
    auth_session = provider.sign_in(session, email=payload.email, password=payload.password)
    memberships = list_memberships(session, auth_session.user.id)
    organization = memberships[0].organization if memberships else None
    audit.record(
        session,
        action=AuditAction.USER_SIGNED_IN,
        organization_id=organization.id if organization else None,
        actor_user_id=auth_session.user.id,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return AuthResponse(
        access_token=auth_session.access_token,
        refresh_token=auth_session.refresh_token,
        expires_in=auth_session.expires_in,
        user=_user_response(auth_session.user),
        organization=(OrganizationResponse.model_validate(organization) if organization else None),
    )


@router.post(
    "/signout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Sign out of the current session",
)
async def sign_out(principal: CurrentPrincipal, session: DbSession) -> None:
    """Record the sign-out.

    Access tokens are short-lived bearer tokens; the client discards them. No
    server-side session state exists to destroy.
    """
    audit.record(
        session,
        action=AuditAction.USER_SIGNED_OUT,
        organization_id=principal.organization.id,
        actor_user_id=principal.user.id,
    )


@router.post(
    "/password-reset",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a password reset email",
)
async def request_password_reset(
    payload: PasswordResetRequest, request: Request, session: DbSession
) -> dict[str, str]:
    """Always returns the same response, whether or not the account exists."""
    _enforce_auth_rate_limit(request, payload.email)
    provider = get_auth_provider()
    try:
        provider.request_password_reset(session, email=normalize_email(payload.email))
    except Exception:  # noqa: BLE001 - never leak account existence
        log.info("password_reset_error_suppressed")
    audit.record(
        session,
        action=AuditAction.USER_PASSWORD_RESET_REQUESTED,
        actor_type="anonymous",
        ip_address=client_ip(request),
    )
    return {
        "message": ("If an account exists for that address, a password reset email has been sent.")
    }


@router.post(
    "/accept-invite",
    summary="Accept an organization invitation",
    responses={404: {"description": "Invitation invalid or expired."}},
)
async def accept_invite(
    payload: AcceptInviteRequest, principal: CurrentPrincipal, session: DbSession
) -> dict[str, str]:
    membership = accept_invitation(session, token=payload.token, user=principal.user)
    return {
        "organization_id": str(membership.organization_id),
        "role": membership.role,
        "message": "You have joined the organization.",
    }
