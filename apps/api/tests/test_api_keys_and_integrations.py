"""API keys, the public API, and integration signature verification."""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.conftest import Account


# ------------------------------------------------------------------- API keys
def test_api_key_secret_is_shown_once_and_only_hashed_at_rest(
    account: Account, db, grant_plan
) -> None:
    from zentra.core.security import hash_api_key
    from zentra.db.models import ApiKey

    grant_plan(account.organization_id, "scale")
    created = account.post("/api/v1/api-keys", json={"name": "CI pipeline"}).json()
    secret = created["secret"]
    assert secret.startswith("zk_live_")
    assert len(secret) > 40

    record = db.query(ApiKey).filter(ApiKey.id == uuid.UUID(created["api_key"]["id"])).one()
    assert record.key_hash == hash_api_key(secret)
    assert secret not in record.key_hash
    assert record.key_prefix == secret[:16]

    # Listing never returns the secret again.
    listed = account.get("/api/v1/api-keys").json()
    assert "secret" not in str(listed)
    assert listed[0]["key_prefix"] == secret[:16]


def test_api_key_authenticates_and_is_scoped(
    client: TestClient, account: Account, grant_plan
) -> None:
    grant_plan(account.organization_id, "scale")
    secret = account.post("/api/v1/api-keys", json={"name": "CI"}).json()["secret"]
    account.post("/api/v1/vendors", json={"name": "Stripe", "domain": "stripe.com"})

    response = client.get("/api/v1/public/vendors", headers={"X-API-Key": secret})
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_api_key_scopes_are_enforced(client: TestClient, account: Account, grant_plan) -> None:
    grant_plan(account.organization_id, "scale")
    created = account.post(
        "/api/v1/api-keys", json={"name": "Read only", "scopes": ["vendors:read"]}
    ).json()
    secret = created["secret"]

    assert client.get("/api/v1/public/vendors", headers={"X-API-Key": secret}).status_code == 200

    denied = client.post(
        "/api/v1/public/vendors",
        headers={"X-API-Key": secret},
        json={"name": "New", "domain": "new-vendor.io"},
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "MISSING_SCOPE"


def test_unknown_scope_is_rejected(account: Account, grant_plan) -> None:
    grant_plan(account.organization_id, "scale")
    response = account.post("/api/v1/api-keys", json={"name": "Bad", "scopes": ["everything:*"]})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_SCOPE"


def test_revoked_api_key_stops_working(client: TestClient, account: Account, grant_plan) -> None:
    grant_plan(account.organization_id, "scale")
    created = account.post("/api/v1/api-keys", json={"name": "CI"}).json()
    secret = created["secret"]
    key_id = created["api_key"]["id"]

    assert client.get("/api/v1/public/vendors", headers={"X-API-Key": secret}).status_code == 200
    account.delete(f"/api/v1/api-keys/{key_id}")

    revoked = client.get("/api/v1/public/vendors", headers={"X-API-Key": secret})
    assert revoked.status_code == 401
    assert revoked.json()["error"]["code"] == "API_KEY_REVOKED"


def test_expired_api_key_is_rejected(client: TestClient, account: Account, db, grant_plan) -> None:
    from zentra.db.models import ApiKey

    grant_plan(account.organization_id, "scale")
    created = account.post("/api/v1/api-keys", json={"name": "CI"}).json()
    record = db.query(ApiKey).filter(ApiKey.id == uuid.UUID(created["api_key"]["id"])).one()
    record.expires_at = datetime.now(UTC) - timedelta(days=1)
    db.commit()

    response = client.get("/api/v1/public/vendors", headers={"X-API-Key": created["secret"]})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "API_KEY_EXPIRED"


@pytest.mark.parametrize(
    "secret",
    [
        "zk_live_definitely-not-a-real-key",
        "not-even-a-zentra-key",
        "zk_live_" + "a" * 300,
        "",
    ],
)
def test_invalid_api_keys_are_rejected(client: TestClient, secret: str) -> None:
    response = client.get("/api/v1/public/vendors", headers={"X-API-Key": secret})
    assert response.status_code == 401


def test_api_key_updates_last_used(client: TestClient, account: Account, db, grant_plan) -> None:
    grant_plan(account.organization_id, "scale")
    created = account.post("/api/v1/api-keys", json={"name": "CI"}).json()
    client.get("/api/v1/public/vendors", headers={"X-API-Key": created["secret"]})

    listed = account.get("/api/v1/api-keys").json()
    assert listed[0]["last_used_at"] is not None


def test_session_token_cannot_use_the_api_key_endpoints(account: Account, grant_plan) -> None:
    grant_plan(account.organization_id, "scale")
    response = account.get("/api/v1/public/vendors")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "API_KEY_REQUIRED"


def test_api_keys_have_a_ceiling_per_organization(account: Account, grant_plan) -> None:
    grant_plan(account.organization_id, "scale")
    statuses = [
        account.post("/api/v1/api-keys", json={"name": f"Key {i}"}).status_code for i in range(22)
    ]
    assert 422 in statuses


# ---------------------------------------------------------------------- Slack
def _slack_signature(body: bytes, secret: str, timestamp: str | None = None) -> tuple[str, str]:
    timestamp = timestamp or str(int(time.time()))
    base = b"v0:" + timestamp.encode() + b":" + body
    return timestamp, "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()


def test_slack_signature_verification_accepts_a_valid_signature() -> None:
    from zentra.integrations.slack.client import verify_slack_signature

    body = b"token=abc&command=/zentra"
    timestamp, signature = _slack_signature(body, "signing-secret")
    assert (
        verify_slack_signature(
            body=body, timestamp=timestamp, signature=signature, signing_secret="signing-secret"
        )
        is True
    )


@pytest.mark.parametrize(
    ("mutate_body", "mutate_signature", "mutate_timestamp"),
    [
        (True, False, False),
        (False, True, False),
        (False, False, True),
    ],
)
def test_slack_signature_verification_rejects_tampering(
    mutate_body: bool, mutate_signature: bool, mutate_timestamp: bool
) -> None:
    from zentra.integrations.slack.client import verify_slack_signature

    body = b"token=abc&command=/zentra"
    timestamp, signature = _slack_signature(body, "signing-secret")
    if mutate_body:
        body = b"token=abc&command=/evil"
    if mutate_signature:
        signature = "v0=" + "0" * 64
    if mutate_timestamp:
        timestamp = str(int(time.time()) - 3600)  # replay outside the window
    assert (
        verify_slack_signature(
            body=body, timestamp=timestamp, signature=signature, signing_secret="signing-secret"
        )
        is False
    )


def test_slack_signature_requires_all_parts() -> None:
    from zentra.integrations.slack.client import verify_slack_signature

    body = b"x=1"
    timestamp, signature = _slack_signature(body, "signing-secret")
    assert (
        verify_slack_signature(body=body, timestamp=None, signature=signature, signing_secret="s")
        is False
    )
    assert (
        verify_slack_signature(body=body, timestamp=timestamp, signature=None, signing_secret="s")
        is False
    )
    assert (
        verify_slack_signature(
            body=body, timestamp=timestamp, signature=signature, signing_secret=""
        )
        is False
    )
    assert (
        verify_slack_signature(
            body=body, timestamp="not-a-number", signature=signature, signing_secret="s"
        )
        is False
    )


def test_slack_endpoints_are_disabled_without_credentials(client: TestClient) -> None:
    response = client.post("/api/v1/integrations/slack/commands", data={"text": "check x.com"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "FEATURE_DISABLED"


# ---------------------------------------------------------------------- Teams
@pytest.mark.parametrize(
    "url",
    [
        "https://acme.webhook.office.com/webhookb2/abc",
        "https://prod-1.uksouth.logic.azure.com/workflows/x",
    ],
)
def test_teams_webhook_accepts_microsoft_hosts(url: str) -> None:
    from zentra.integrations.teams.client import validate_webhook_url

    assert validate_webhook_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://acme.webhook.office.com/x",  # not https
        "https://evil.example.com/webhook",
        "https://127.0.0.1/webhook",
        "https://169.254.169.254/latest/meta-data/",
        "https://webhook.office.com.evil.example/x",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "",
        "a" * 3000,
    ],
)
def test_teams_webhook_rejects_everything_else(url: str) -> None:
    from zentra.errors import ValidationError
    from zentra.integrations.teams.client import validate_webhook_url

    with pytest.raises(ValidationError):
        validate_webhook_url(url)


def test_teams_connection_stores_the_url_encrypted(account: Account, db, grant_plan) -> None:
    from zentra.core.crypto import decrypt_secret
    from zentra.db.models import IntegrationConnection

    grant_plan(account.organization_id, "growth")
    url = "https://acme.webhook.office.com/webhookb2/secret-path"
    response = account.post("/api/v1/integrations/teams", json={"webhook_url": url})
    assert response.status_code == 200

    record = (
        db.query(IntegrationConnection)
        .filter(IntegrationConnection.organization_id == account.organization_id)
        .one()
    )
    assert record.encrypted_secret != url
    assert "secret-path" not in record.encrypted_secret
    assert decrypt_secret(record.encrypted_secret) == url
    # The API never returns the secret.
    assert "secret-path" not in account.get("/api/v1/integrations").text


def test_teams_requires_the_integrations_entitlement(account: Account) -> None:
    response = account.post(
        "/api/v1/integrations/teams",
        json={"webhook_url": "https://acme.webhook.office.com/webhookb2/abc"},
    )
    assert response.status_code == 402


# ------------------------------------------------------------------ encryption
def test_secrets_round_trip_and_ciphertext_differs_each_time() -> None:
    from zentra.core.crypto import decrypt_secret, encrypt_secret

    plaintext = "xoxb-not-a-real-token"
    first = encrypt_secret(plaintext)
    second = encrypt_secret(plaintext)
    assert first != second  # Fernet includes a random IV
    assert decrypt_secret(first) == decrypt_secret(second) == plaintext


def test_tampered_ciphertext_is_rejected() -> None:
    from zentra.core.crypto import SecretDecryptionError, decrypt_secret, encrypt_secret

    ciphertext = encrypt_secret("secret")
    tampered = ciphertext[:-4] + "AAAA"
    with pytest.raises(SecretDecryptionError):
        decrypt_secret(tampered)
