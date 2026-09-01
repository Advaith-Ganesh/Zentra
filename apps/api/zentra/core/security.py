"""Password hashing, token issuance and API key handling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from zentra.config import get_settings
from zentra.errors import AuthenticationError

# OWASP-aligned Argon2id parameters (m=64MiB, t=3, p=4).
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256

API_KEY_PREFIX = "zk_live_"
API_KEY_PREFIX_LEN = 16


# --------------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    validate_password_strength(password)
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Constant-work verification. A missing hash still costs a hash operation
    so that account enumeration by timing is not trivially possible."""
    if not password_hash:
        _hasher.hash("dummy-password-for-constant-work")
        return False
    try:
        _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:  # noqa: BLE001 - never leak hashing internals
        return False
    return True


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except Exception:  # noqa: BLE001
        return False


def validate_password_strength(password: str) -> None:
    from zentra.errors import ValidationError

    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.",
            code="WEAK_PASSWORD",
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValidationError("Password is too long.", code="WEAK_PASSWORD")
    classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    if classes < 3:
        raise ValidationError(
            "Password must combine at least three of: lowercase, uppercase, digits, symbols.",
            code="WEAK_PASSWORD",
        )


# --------------------------------------------------------------------------- JWT
def _signing_secret() -> str:
    settings = get_settings()
    if settings.auth_provider == "supabase" and settings.supabase_jwt_secret:
        return settings.supabase_jwt_secret
    return settings.jwt_secret


def create_access_token(
    subject: str,
    *,
    email: str | None = None,
    ttl_seconds: int | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    ttl = ttl_seconds or settings.access_token_ttl_seconds
    payload: dict[str, Any] = {
        "sub": str(subject),
        "iss": settings.jwt_issuer,
        "aud": "authenticated",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    if email:
        payload["email"] = email
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, _signing_secret(), algorithm="HS256")


def create_refresh_token(subject: str) -> str:
    settings = get_settings()
    return create_access_token(
        subject,
        ttl_seconds=settings.refresh_token_ttl_seconds,
        extra_claims={"typ": "refresh"},
    )


def decode_token(token: str, *, expected_type: str | None = "access") -> dict[str, Any]:
    settings = get_settings()
    try:
        claims = jwt.decode(
            token,
            _signing_secret(),
            algorithms=["HS256"],
            audience="authenticated",
            options={"require": ["exp", "sub"], "verify_aud": True},
            leeway=10,
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Session has expired.", code="TOKEN_EXPIRED") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("Invalid authentication token.", code="INVALID_TOKEN") from exc

    # Supabase tokens carry iss=<project>/auth/v1; only enforce our own issuer
    # when we minted the token ourselves.
    if settings.auth_provider == "local" and claims.get("iss") != settings.jwt_issuer:
        raise AuthenticationError("Invalid authentication token.", code="INVALID_TOKEN")
    if expected_type and claims.get("typ", "access") != expected_type:
        raise AuthenticationError("Invalid authentication token.", code="INVALID_TOKEN")
    return claims


# --------------------------------------------------------------------------- API keys
def generate_api_key() -> tuple[str, str, str]:
    """Return ``(secret, prefix, hash)``.

    The raw secret is returned to the caller exactly once and never persisted.
    Only the SHA-256 hash is stored; API keys are high-entropy random values so
    a fast hash is appropriate (unlike passwords).
    """
    secret = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return secret, secret[:API_KEY_PREFIX_LEN], hash_api_key(secret)


def hash_api_key(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# --------------------------------------------------------------------------- misc tokens
def generate_url_token() -> tuple[str, str]:
    """Random token for invitations / password resets, plus its stored hash."""
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def hash_url_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def pseudonymize(value: str, *, salt: str | None = None) -> str:
    """Irreversible identifier for rate limiting / abuse tracking.

    Used so that a requester IP address is never persisted in clear text.
    """
    key = (salt or get_settings().jwt_secret).encode()
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")[:32]
