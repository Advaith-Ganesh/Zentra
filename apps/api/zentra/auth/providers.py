"""Authentication providers.

Two implementations share one interface:

``LocalAuthProvider``
    Real email/password authentication against Zentra's own ``users`` table.
    Passwords are hashed with Argon2id; sessions are signed JWTs. Used for
    local development and CI so the product works end-to-end with no external
    account. It is a genuine implementation, not a stub.

``SupabaseAuthProvider``
    Production path. User records live in Supabase Auth; Zentra verifies the
    JWTs Supabase issues and mirrors a profile row into ``public.users``.
    Sign-up/sign-in are proxied to the Supabase Auth REST API using the
    project's anon key.

Neither provider ever logs or returns a password.
"""

from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zentra.config import get_settings
from zentra.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    validate_password_strength,
    verify_password,
)
from zentra.db.models import User
from zentra.errors import (
    AuthenticationError,
    ConflictError,
    InvalidCredentialsError,
    ProviderError,
    ValidationError,
)
from zentra.logging import get_logger

log = get_logger("zentra.auth")

MAX_EMAIL_LENGTH = 320


@dataclass
class AuthSession:
    user: User
    access_token: str
    refresh_token: str | None
    expires_in: int
    email_verification_required: bool = False


def normalize_email(email: str) -> str:
    if not isinstance(email, str):
        raise ValidationError("An email address is required.", code="INVALID_EMAIL")
    value = email.strip().lower()
    if not 3 <= len(value) <= MAX_EMAIL_LENGTH or "@" not in value:
        raise ValidationError("Enter a valid email address.", code="INVALID_EMAIL")
    local, _, domain = value.rpartition("@")
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValidationError("Enter a valid email address.", code="INVALID_EMAIL")
    return value


class AuthProvider(abc.ABC):
    name = "auth"
    #: True when the provider itself owns the credential store.
    external_credentials = False

    @abc.abstractmethod
    def sign_up(
        self, session: Session, *, email: str, password: str, full_name: str | None
    ) -> AuthSession: ...

    @abc.abstractmethod
    def sign_in(self, session: Session, *, email: str, password: str) -> AuthSession: ...

    @abc.abstractmethod
    def verify_access_token(self, session: Session, token: str) -> User: ...

    def request_password_reset(self, session: Session, *, email: str) -> None:
        """Best-effort. Must not reveal whether the account exists."""
        return None


# --------------------------------------------------------------------------- local
class LocalAuthProvider(AuthProvider):
    name = "local"

    def sign_up(
        self, session: Session, *, email: str, password: str, full_name: str | None
    ) -> AuthSession:
        settings = get_settings()
        email = normalize_email(email)
        validate_password_strength(password)

        existing = session.execute(
            select(User).where(func.lower(User.email) == email)
        ).scalar_one_or_none()
        if existing is not None:
            raise ConflictError("An account with that email already exists.", code="EMAIL_IN_USE")

        user = User(
            email=email,
            full_name=(full_name or "").strip()[:200] or None,
            password_hash=hash_password(password),
            # In local mode there is no mail-verification round trip; the
            # account is usable immediately. Supabase mode enforces real
            # verification.
            email_verified_at=datetime.now(UTC),
            is_platform_admin=email in settings.admin_emails,
        )
        session.add(user)
        try:
            session.flush()
        except IntegrityError as exc:
            session.rollback()
            raise ConflictError(
                "An account with that email already exists.", code="EMAIL_IN_USE"
            ) from exc
        return self._issue(user)

    def sign_in(self, session: Session, *, email: str, password: str) -> AuthSession:
        email = normalize_email(email)
        user = session.execute(
            select(User).where(func.lower(User.email) == email, User.deleted_at.is_(None))
        ).scalar_one_or_none()
        # verify_password does constant work even when the user is absent.
        if not verify_password(password, user.password_hash if user else None) or user is None:
            raise InvalidCredentialsError()
        if user.password_hash and needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
        user.last_login_at = datetime.now(UTC)
        session.flush()
        return self._issue(user)

    def verify_access_token(self, session: Session, token: str) -> User:
        claims = decode_token(token, expected_type="access")
        try:
            user_id = uuid.UUID(str(claims["sub"]))
        except (KeyError, ValueError) as exc:
            raise AuthenticationError(
                "Invalid authentication token.", code="INVALID_TOKEN"
            ) from exc
        user = session.get(User, user_id)
        if user is None or user.deleted_at is not None:
            raise AuthenticationError("This account is no longer active.", code="ACCOUNT_INACTIVE")
        return user

    @staticmethod
    def _issue(user: User) -> AuthSession:
        settings = get_settings()
        return AuthSession(
            user=user,
            access_token=create_access_token(str(user.id), email=user.email),
            refresh_token=create_refresh_token(str(user.id)),
            expires_in=settings.access_token_ttl_seconds,
        )


# --------------------------------------------------------------------------- supabase
class SupabaseAuthProvider(AuthProvider):
    """Delegates credential storage to Supabase Auth (GoTrue)."""

    name = "supabase"
    external_credentials = True

    def __init__(self) -> None:
        settings = get_settings()
        self.base_url = settings.supabase_url.rstrip("/")
        self.anon_key = settings.supabase_anon_key
        self.timeout = 10.0
        if not (self.base_url and self.anon_key):
            raise ProviderError(
                "Supabase authentication is selected but SUPABASE_URL / SUPABASE_ANON_KEY "
                "are not configured.",
                code="SUPABASE_NOT_CONFIGURED",
            )

    # -------------------------------------------------------------- transport
    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = httpx.post(
                f"{self.base_url}/auth/v1{path}",
                json=payload,
                headers={"apikey": self.anon_key, "Content-Type": "application/json"},
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise ProviderError("The authentication service is unavailable.") from exc
        try:
            data = response.json()
        except ValueError:
            data = {}
        if response.status_code >= 400:
            code = str(data.get("error_code") or data.get("error") or "")
            if response.status_code in (400, 401) and "credential" in str(data).lower():
                raise InvalidCredentialsError()
            if "already" in str(data.get("msg", "")).lower():
                raise ConflictError(
                    "An account with that email already exists.", code="EMAIL_IN_USE"
                )
            if response.status_code in (400, 422):
                raise ValidationError(
                    str(
                        data.get("msg") or "The request was rejected by the authentication service."
                    )[:200],
                    code=code[:60] or "AUTH_REJECTED",
                )
            raise ProviderError("The authentication service returned an error.")
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------- operations
    def sign_up(
        self, session: Session, *, email: str, password: str, full_name: str | None
    ) -> AuthSession:
        email = normalize_email(email)
        validate_password_strength(password)
        data = self._post(
            "/signup",
            {
                "email": email,
                "password": password,
                "data": {"full_name": (full_name or "").strip()[:200] or None},
            },
        )
        supabase_user = data.get("user") or {}
        user = self._mirror(session, supabase_user, email=email, full_name=full_name)
        access_token = str(data.get("access_token") or "")
        return AuthSession(
            user=user,
            access_token=access_token,
            refresh_token=str(data.get("refresh_token") or "") or None,
            expires_in=int(data.get("expires_in") or get_settings().access_token_ttl_seconds),
            # Supabase withholds a session until the address is confirmed when
            # email confirmation is switched on for the project.
            email_verification_required=not access_token,
        )

    def sign_in(self, session: Session, *, email: str, password: str) -> AuthSession:
        email = normalize_email(email)
        data = self._post("/token?grant_type=password", {"email": email, "password": password})
        supabase_user = data.get("user") or {}
        user = self._mirror(session, supabase_user, email=email, full_name=None)
        user.last_login_at = datetime.now(UTC)
        session.flush()
        return AuthSession(
            user=user,
            access_token=str(data.get("access_token") or ""),
            refresh_token=str(data.get("refresh_token") or "") or None,
            expires_in=int(data.get("expires_in") or get_settings().access_token_ttl_seconds),
        )

    def verify_access_token(self, session: Session, token: str) -> User:
        # Verified locally against SUPABASE_JWT_SECRET — no network round trip
        # on every request.
        claims = decode_token(token, expected_type=None)
        try:
            user_id = uuid.UUID(str(claims["sub"]))
        except (KeyError, ValueError) as exc:
            raise AuthenticationError(
                "Invalid authentication token.", code="INVALID_TOKEN"
            ) from exc
        user = session.get(User, user_id)
        if user is None:
            email = str(claims.get("email") or "")
            if not email:
                raise AuthenticationError("Invalid authentication token.", code="INVALID_TOKEN")
            user = self._mirror(
                session, {"id": str(user_id), "email": email}, email=email, full_name=None
            )
        if user.deleted_at is not None:
            raise AuthenticationError("This account is no longer active.", code="ACCOUNT_INACTIVE")
        return user

    def request_password_reset(self, session: Session, *, email: str) -> None:
        try:
            self._post("/recover", {"email": normalize_email(email)})
        except Exception:  # noqa: BLE001 - never reveal account existence
            log.info("password_reset_request_suppressed")

    @staticmethod
    def _mirror(
        session: Session, supabase_user: dict[str, Any], *, email: str, full_name: str | None
    ) -> User:
        """Keep a local profile row in step with Supabase Auth."""
        settings = get_settings()
        raw_id = supabase_user.get("id")
        user_id = uuid.UUID(str(raw_id)) if raw_id else None
        user = session.get(User, user_id) if user_id else None
        if user is None:
            user = session.execute(
                select(User).where(func.lower(User.email) == email)
            ).scalar_one_or_none()
        if user is None:
            user = User(
                id=user_id or uuid.uuid4(),
                email=email,
                full_name=(full_name or "").strip()[:200] or None,
                password_hash=None,
                is_platform_admin=email in settings.admin_emails,
            )
            session.add(user)
        confirmed = supabase_user.get("email_confirmed_at") or supabase_user.get("confirmed_at")
        if confirmed and user.email_verified_at is None:
            user.email_verified_at = datetime.now(UTC)
        session.flush()
        return user


def get_auth_provider() -> AuthProvider:
    return (
        SupabaseAuthProvider()
        if get_settings().auth_provider == "supabase"
        else LocalAuthProvider()
    )
