"""FastAPI authentication and authorization dependencies.

Every protected route resolves a :class:`Principal` here. The principal always
carries an explicit organization, so no handler ever has to work out tenancy
for itself.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from zentra.auth.providers import get_auth_provider
from zentra.core.entitlements import Entitlements
from zentra.core.security import hash_api_key
from zentra.db.models import ApiKey, Organization, OrganizationMember, User
from zentra.db.session import db_dependency
from zentra.errors import (
    AuthenticationError,
    NotFoundError,
    PermissionDeniedError,
)
from zentra.logging import get_logger, organization_id_var
from zentra.services.organizations import (
    ROLE_RANK,
    entitlements_for,
    get_membership,
    get_organization,
    list_memberships,
)

log = get_logger("zentra.auth.deps")

DbSession = Annotated[Session, Depends(db_dependency)]


@dataclass
class Principal:
    """The authenticated caller, always bound to one organization."""

    user: User
    organization: Organization
    membership: OrganizationMember | None
    #: "user" for a session token, "api_key" for a machine caller.
    kind: str = "user"
    api_key: ApiKey | None = None
    scopes: tuple[str, ...] = ()

    @property
    def role(self) -> str:
        if self.kind == "api_key":
            # API keys act with analyst-level rights, bounded by their scopes.
            return "analyst"
        return self.membership.role if self.membership else "viewer"

    def require_role(self, minimum: str) -> None:
        if ROLE_RANK.get(self.role, -1) < ROLE_RANK[minimum]:
            raise PermissionDeniedError(f"This action requires the {minimum} role or higher.")

    def require_scope(self, scope: str) -> None:
        if self.kind != "api_key":
            return
        if scope not in self.scopes:
            raise PermissionDeniedError(
                f"This API key does not have the '{scope}' scope.", code="MISSING_SCOPE"
            )


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _resolve_organization(
    session: Session, user: User, requested: str | None
) -> tuple[Organization, OrganizationMember]:
    memberships = list_memberships(session, user.id)
    if not memberships:
        raise NotFoundError(
            "This account does not belong to an organization yet.",
            code="NO_ORGANIZATION",
        )
    if requested:
        try:
            requested_id = uuid.UUID(requested)
        except ValueError as exc:
            raise PermissionDeniedError("Invalid organization identifier.") from exc
        membership = get_membership(session, requested_id, user.id)
        if membership is None:
            # Deliberately 403 and not 404: the caller proved identity but is
            # not a member. It also avoids confirming the organization exists.
            raise PermissionDeniedError("You do not have access to that organization.")
    else:
        membership = memberships[0]
    organization = get_organization(session, membership.organization_id)
    return organization, membership


async def current_principal(
    request: Request,
    session: DbSession,
    authorization: Annotated[str | None, Header()] = None,
    x_zentra_organization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header()] = None,
) -> Principal:
    """Resolve a session-token or API-key principal."""
    api_key_secret = x_api_key
    token = _bearer_token(authorization)
    if not api_key_secret and token and token.startswith("zk_"):
        # Allow API keys via the Authorization header too.
        api_key_secret = token
        token = None

    if api_key_secret:
        principal = _principal_from_api_key(session, api_key_secret)
    elif token:
        provider = get_auth_provider()
        user = provider.verify_access_token(session, token)
        organization, membership = _resolve_organization(session, user, x_zentra_organization)
        principal = Principal(
            user=user, organization=organization, membership=membership, kind="user"
        )
    else:
        raise AuthenticationError("Authentication is required.")

    organization_id_var.set(str(principal.organization.id))
    request.state.principal = principal
    return principal


def _principal_from_api_key(session: Session, secret: str) -> Principal:
    from zentra.core.feature_flags import Flag, is_enabled

    if not is_enabled(Flag.PUBLIC_API):
        raise AuthenticationError("API key authentication is not enabled.", code="API_DISABLED")
    if not secret.startswith("zk_") or len(secret) > 200:
        raise AuthenticationError("Invalid API key.", code="INVALID_API_KEY")

    # Look up by hash: the raw key is never stored, so this is also a
    # constant-time comparison at the database level.
    record = session.execute(
        select(ApiKey).where(ApiKey.key_hash == hash_api_key(secret))
    ).scalar_one_or_none()
    if record is None:
        raise AuthenticationError("Invalid API key.", code="INVALID_API_KEY")
    now = datetime.now(UTC)
    if record.revoked_at is not None:
        raise AuthenticationError("This API key has been revoked.", code="API_KEY_REVOKED")
    if record.expires_at is not None and record.expires_at < now:
        raise AuthenticationError("This API key has expired.", code="API_KEY_EXPIRED")

    organization = get_organization(session, record.organization_id)
    record.last_used_at = now
    session.flush()

    creator = session.get(User, record.created_by) if record.created_by else None
    if creator is None:
        creator = User(id=uuid.UUID(int=0), email="api-key@zentra.internal")
    return Principal(
        user=creator,
        organization=organization,
        membership=None,
        kind="api_key",
        api_key=record,
        scopes=tuple(record.scopes or ()),
    )


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


async def current_entitlements(principal: CurrentPrincipal, session: DbSession) -> Entitlements:
    return entitlements_for(session, principal.organization)


CurrentEntitlements = Annotated[Entitlements, Depends(current_entitlements)]


def require_role(minimum: str):
    async def _dependency(principal: CurrentPrincipal) -> Principal:
        principal.require_role(minimum)
        return principal

    return _dependency


def require_scope(scope: str):
    async def _dependency(principal: CurrentPrincipal) -> Principal:
        principal.require_scope(scope)
        return principal

    return _dependency


async def require_platform_admin(principal: CurrentPrincipal) -> Principal:
    """Internal admin gate.

    Backed by the ``users.is_platform_admin`` column, which is only ever set
    server-side from ``ZENTRA_ADMIN_EMAILS``. There is no frontend flag that can
    grant it, and API keys can never satisfy it.
    """
    if principal.kind != "user" or not principal.user.is_platform_admin:
        log.warning(
            "admin_access_denied",
            user_id=str(principal.user.id),
            kind=principal.kind,
        )
        # 404 rather than 403 so the admin surface is not discoverable.
        raise NotFoundError("Not found.", code="NOT_FOUND")
    return principal


PlatformAdmin = Annotated[Principal, Depends(require_platform_admin)]
