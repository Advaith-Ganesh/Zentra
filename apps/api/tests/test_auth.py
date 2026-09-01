"""Authentication and authorization."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import signup
from zentra.core.security import (
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)
from zentra.errors import AuthenticationError


# --------------------------------------------------------------- password rules
def test_password_is_hashed_with_argon2_and_verifies() -> None:
    digest = hash_password("Correct-Horse-9!x")
    assert digest.startswith("$argon2id$")
    assert "Correct-Horse-9!x" not in digest
    assert verify_password("Correct-Horse-9!x", digest) is True
    assert verify_password("wrong", digest) is False


def test_verify_against_missing_hash_is_false_not_an_error() -> None:
    assert verify_password("anything", None) is False


@pytest.mark.parametrize(
    "password",
    ["short", "alllowercaseletters", "12345678901234", "PASSWORD1234", "aA1"],
)
def test_weak_passwords_are_rejected(client: TestClient, password: str) -> None:
    response = client.post(
        "/api/v1/auth/signup",
        json={
            "email": "weak@example.io",
            "password": password,
            "organization_name": "Weak Co",
        },
    )
    assert response.status_code == 422


# ------------------------------------------------------------------- sign up
def test_signup_creates_user_organization_and_owner_membership(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/signup",
        json={
            "email": "founder@newco.io",
            "password": "Correct-Horse-9!x",
            "full_name": "Ada Lovelace",
            "organization_name": "New Co",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["access_token"]
    assert body["user"]["email"] == "founder@newco.io"
    assert body["organization"]["name"] == "New Co"
    # The password must never appear in a response.
    assert "password" not in response.text.lower()

    me = client.get("/api/v1/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["role"] == "owner"


def test_duplicate_email_is_rejected(client: TestClient) -> None:
    signup(client, email="dupe@example.io", org="First")
    response = client.post(
        "/api/v1/auth/signup",
        json={
            "email": "DUPE@example.io",
            "password": "Correct-Horse-9!x",
            "organization_name": "Second",
        },
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_IN_USE"


def test_signup_sends_a_welcome_email(client: TestClient) -> None:
    from zentra.integrations.email.provider import ConsoleEmailProvider

    signup(client, email="welcome@example.io", org="Welcome Co")
    assert any("Welcome to Zentra" in m.subject for m in ConsoleEmailProvider.outbox)


# ------------------------------------------------------------------- sign in
def test_signin_returns_a_usable_token(client: TestClient) -> None:
    account = signup(client, email="signin@example.io", org="Sign In Co")
    response = client.post(
        "/api/v1/auth/signin",
        json={"email": "signin@example.io", "password": account.password},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("signin@example.io", "Wrong-Password-1!"),
        ("nobody@example.io", "Correct-Horse-9!x"),
    ],
)
def test_bad_credentials_return_the_same_generic_error(
    client: TestClient, email: str, password: str
) -> None:
    signup(client, email="signin@example.io", org="Sign In Co")
    response = client.post("/api/v1/auth/signin", json={"email": email, "password": password})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_password_reset_does_not_reveal_whether_the_account_exists(client: TestClient) -> None:
    signup(client, email="known@example.io", org="Known Co")
    known = client.post("/api/v1/auth/password-reset", json={"email": "known@example.io"})
    unknown = client.post("/api/v1/auth/password-reset", json={"email": "nobody@example.io"})
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()


# -------------------------------------------------------------------- tokens
def test_protected_route_requires_authentication(client: TestClient) -> None:
    for path in ["/api/v1/me", "/api/v1/vendors", "/api/v1/dashboard", "/api/v1/billing"]:
        response = client.get(path)
        assert response.status_code == 401, path
        assert response.json()["error"]["code"] in ("UNAUTHENTICATED", "INVALID_TOKEN")


@pytest.mark.parametrize(
    "header",
    [
        "Bearer not-a-jwt",
        "Bearer ",
        "Basic dXNlcjpwYXNz",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.invalid",
        "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
    ],
)
def test_malformed_tokens_are_rejected(client: TestClient, header: str) -> None:
    response = client.get("/api/v1/me", headers={"Authorization": header})
    assert response.status_code == 401


def test_expired_token_is_rejected() -> None:
    token = create_access_token("00000000-0000-0000-0000-000000000001", ttl_seconds=-120)
    with pytest.raises(AuthenticationError) as exc:
        decode_token(token)
    assert exc.value.code == "TOKEN_EXPIRED"


def test_token_signed_with_another_secret_is_rejected(client: TestClient) -> None:
    import jwt

    forged = jwt.encode(
        {
            "sub": "00000000-0000-0000-0000-000000000001",
            "iss": "zentra",
            "aud": "authenticated",
            "exp": 9_999_999_999,
        },
        "attacker-secret",
        algorithm="HS256",
    )
    response = client.get("/api/v1/me", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_algorithm_none_token_is_rejected(client: TestClient) -> None:
    import base64
    import json

    def _b64(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    forged = (
        _b64({"alg": "none", "typ": "JWT"})
        + "."
        + _b64({"sub": "00000000-0000-0000-0000-000000000001", "exp": 9_999_999_999})
        + "."
    )
    assert (
        client.get("/api/v1/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    )


def test_refresh_token_cannot_be_used_as_an_access_token(client: TestClient) -> None:
    account = signup(client, email="refresh@example.io", org="Refresh Co")
    response = client.post(
        "/api/v1/auth/signin",
        json={"email": account.email, "password": account.password},
    )
    refresh = response.json()["refresh_token"]
    assert (
        client.get("/api/v1/me", headers={"Authorization": f"Bearer {refresh}"}).status_code == 401
    )


# ---------------------------------------------------------------------- roles
def test_viewer_cannot_create_a_vendor(client: TestClient, db) -> None:
    from zentra.db.models import OrganizationMember

    account = signup(client, email="viewer@example.io", org="Viewer Co")
    membership = (
        db.query(OrganizationMember).filter(OrganizationMember.user_id == account.user_id).one()
    )
    membership.role = "viewer"
    db.commit()

    response = account.post("/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PERMISSION_DENIED"


def test_analyst_cannot_delete_a_vendor(client: TestClient, db) -> None:
    from zentra.db.models import OrganizationMember

    account = signup(client, email="analyst@example.io", org="Analyst Co")
    created = account.post("/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"})
    vendor_id = created.json()["id"]

    membership = (
        db.query(OrganizationMember).filter(OrganizationMember.user_id == account.user_id).one()
    )
    membership.role = "analyst"
    db.commit()

    assert account.delete(f"/api/v1/vendors/{vendor_id}").status_code == 403


def test_admin_area_is_not_discoverable_by_a_normal_user(client: TestClient) -> None:
    account = signup(client, email="normal@example.io", org="Normal Co")
    response = account.get("/api/v1/admin/overview")
    # 404, not 403: the surface must not be discoverable.
    assert response.status_code == 404


def test_admin_flag_cannot_be_set_by_the_client(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/signup",
        json={
            "email": "wannabe@example.io",
            "password": "Correct-Horse-9!x",
            "organization_name": "Wannabe Co",
            "is_platform_admin": True,
        },
    )
    # extra="forbid" on the schema rejects the unknown field outright.
    assert response.status_code == 422
