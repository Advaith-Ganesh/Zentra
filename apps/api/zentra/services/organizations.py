"""Organization and membership services."""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.core.entitlements import Entitlements, build_entitlements
from zentra.core.security import generate_url_token, hash_url_token
from zentra.db.models import (
    Invitation,
    Organization,
    OrganizationMember,
    Subscription,
    User,
    Vendor,
)
from zentra.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2, "owner": 3}
INVITE_TTL_DAYS = 7


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:40]
    return slug or "org"


def unique_slug(session: Session, name: str) -> str:
    base = slugify(name)
    candidate = base
    for _ in range(20):
        exists = session.execute(
            select(Organization.id).where(Organization.slug == candidate)
        ).first()
        if not exists:
            return candidate
        candidate = f"{base}-{secrets.token_hex(3)}"
    return f"{base}-{uuid.uuid4().hex[:8]}"


def create_organization(
    session: Session,
    *,
    name: str,
    owner: User,
    industry: str | None = None,
    company_size: str | None = None,
    country: str = "GB",
    website_domain: str | None = None,
) -> Organization:
    """Create an organization and make ``owner`` its owner."""
    name = (name or "").strip()
    if not 1 <= len(name) <= 200:
        raise ValidationError("Organization name must be between 1 and 200 characters.")

    organization = Organization(
        name=name,
        slug=unique_slug(session, name),
        industry=industry,
        company_size=company_size,
        country=country,
        website_domain=website_domain,
    )
    session.add(organization)
    session.flush()

    session.add(
        OrganizationMember(
            organization_id=organization.id,
            user_id=owner.id,
            role="owner",
            status="active",
        )
    )
    session.add(Subscription(organization_id=organization.id, plan="free", status="active"))
    audit.record(
        session,
        action=AuditAction.ORGANIZATION_CREATED,
        organization_id=organization.id,
        actor_user_id=owner.id,
        resource_type="organization",
        resource_id=organization.id,
        metadata={"name": name},
    )
    session.flush()
    return organization


def get_membership(
    session: Session, organization_id: uuid.UUID, user_id: uuid.UUID
) -> OrganizationMember | None:
    return session.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.user_id == user_id,
            OrganizationMember.status == "active",
        )
    ).scalar_one_or_none()


def list_memberships(session: Session, user_id: uuid.UUID) -> list[OrganizationMember]:
    return list(
        session.execute(
            select(OrganizationMember)
            .where(
                OrganizationMember.user_id == user_id,
                OrganizationMember.status == "active",
            )
            .order_by(OrganizationMember.created_at)
        ).scalars()
    )


def require_role(membership: OrganizationMember, minimum: str) -> None:
    if ROLE_RANK.get(membership.role, -1) < ROLE_RANK[minimum]:
        raise PermissionDeniedError(f"This action requires the {minimum} role or higher.")


def get_organization(session: Session, organization_id: uuid.UUID) -> Organization:
    organization = session.get(Organization, organization_id)
    if organization is None or organization.deleted_at is not None:
        raise NotFoundError("Organization could not be found.", code="ORGANIZATION_NOT_FOUND")
    return organization


def get_subscription(session: Session, organization_id: uuid.UUID) -> Subscription | None:
    return session.execute(
        select(Subscription).where(Subscription.organization_id == organization_id)
    ).scalar_one_or_none()


def count_vendors(session: Session, organization_id: uuid.UUID) -> int:
    return int(
        session.execute(
            select(func.count(Vendor.id)).where(
                Vendor.organization_id == organization_id,
                Vendor.status != "archived",
            )
        ).scalar_one()
    )


def entitlements_for(session: Session, organization: Organization) -> Entitlements:
    """Derive the organization's entitlements from server-side state only."""
    return build_entitlements(
        organization,
        get_subscription(session, organization.id),
        count_vendors(session, organization.id),
    )


def list_members(
    session: Session, organization_id: uuid.UUID
) -> list[tuple[OrganizationMember, User]]:
    rows = session.execute(
        select(OrganizationMember, User)
        .join(User, User.id == OrganizationMember.user_id)
        .where(OrganizationMember.organization_id == organization_id)
        .order_by(OrganizationMember.created_at)
    ).all()
    return [(row[0], row[1]) for row in rows]


def invite_member(
    session: Session,
    *,
    organization: Organization,
    email: str,
    role: str,
    invited_by: User,
) -> tuple[Invitation, str]:
    """Create an invitation. Returns the record and the raw (unstored) token."""
    if role not in ROLE_RANK:
        raise ValidationError("Unknown role.")
    email = email.strip().lower()

    existing_member = session.execute(
        select(OrganizationMember)
        .join(User, User.id == OrganizationMember.user_id)
        .where(
            OrganizationMember.organization_id == organization.id,
            func.lower(User.email) == email,
        )
    ).first()
    if existing_member:
        raise ConflictError("That person is already a member of this organization.")

    session.execute(
        select(Invitation).where(
            Invitation.organization_id == organization.id,
            func.lower(Invitation.email) == email,
            Invitation.accepted_at.is_(None),
            Invitation.revoked_at.is_(None),
        )
    ).scalars().all()

    token, token_hash = generate_url_token()
    invitation = Invitation(
        organization_id=organization.id,
        email=email,
        role=role,
        token_hash=token_hash,
        invited_by=invited_by.id,
        expires_at=datetime.now(UTC) + timedelta(days=INVITE_TTL_DAYS),
    )
    session.add(invitation)
    audit.record(
        session,
        action=AuditAction.MEMBER_INVITED,
        organization_id=organization.id,
        actor_user_id=invited_by.id,
        resource_type="invitation",
        metadata={"email": email, "role": role},
    )
    session.flush()
    return invitation, token


def accept_invitation(session: Session, *, token: str, user: User) -> OrganizationMember:
    invitation = session.execute(
        select(Invitation).where(Invitation.token_hash == hash_url_token(token))
    ).scalar_one_or_none()
    if invitation is None or invitation.revoked_at is not None:
        raise NotFoundError("This invitation is no longer valid.", code="INVITATION_INVALID")
    if invitation.accepted_at is not None:
        raise ConflictError("This invitation has already been used.", code="INVITATION_USED")
    if invitation.expires_at < datetime.now(UTC):
        raise NotFoundError("This invitation has expired.", code="INVITATION_EXPIRED")
    if invitation.email.lower() != user.email.lower():
        raise PermissionDeniedError("This invitation was issued to a different email address.")

    existing = get_membership(session, invitation.organization_id, user.id)
    if existing:
        invitation.accepted_at = datetime.now(UTC)
        return existing

    member = OrganizationMember(
        organization_id=invitation.organization_id,
        user_id=user.id,
        role=invitation.role,
        status="active",
        invited_by=invitation.invited_by,
    )
    session.add(member)
    invitation.accepted_at = datetime.now(UTC)
    audit.record(
        session,
        action=AuditAction.MEMBER_JOINED,
        organization_id=invitation.organization_id,
        actor_user_id=user.id,
        resource_type="organization_member",
        metadata={"role": invitation.role},
    )
    session.flush()
    return member


def remove_member(
    session: Session, *, organization: Organization, member_id: uuid.UUID, actor: User
) -> None:
    member = session.get(OrganizationMember, member_id)
    if member is None or member.organization_id != organization.id:
        raise NotFoundError("Member could not be found.", code="MEMBER_NOT_FOUND")
    if member.role == "owner":
        owners = session.execute(
            select(func.count(OrganizationMember.id)).where(
                OrganizationMember.organization_id == organization.id,
                OrganizationMember.role == "owner",
                OrganizationMember.status == "active",
            )
        ).scalar_one()
        if owners <= 1:
            raise ValidationError(
                "You cannot remove the last owner of an organization.",
                code="LAST_OWNER",
            )
    session.delete(member)
    audit.record(
        session,
        action=AuditAction.MEMBER_REMOVED,
        organization_id=organization.id,
        actor_user_id=actor.id,
        resource_type="organization_member",
        resource_id=member_id,
    )
