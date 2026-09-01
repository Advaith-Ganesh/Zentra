"""Rate limiting and the public free scan."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import Account
from zentra.config import get_settings
from zentra.core.ratelimit import check_rate_limit, clear_redis_bucket, reset_local_state


@pytest.fixture
def limits_on(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    for bucket in (
        "public_scan",
        "public_scan_domain",
        "auth",
        "auth_email",
        "global",
        "report",
        "manual_scan",
    ):
        clear_redis_bucket(bucket)
    reset_local_state()
    yield settings
    for bucket in (
        "public_scan",
        "public_scan_domain",
        "auth",
        "auth_email",
        "global",
        "report",
        "manual_scan",
    ):
        clear_redis_bucket(bucket)
    reset_local_state()


# ------------------------------------------------------------------- primitive
def test_counter_allows_up_to_the_limit_then_denies(limits_on) -> None:
    for index in range(3):
        result = check_rate_limit("unit_test", "subject-a", 3, 60)
        assert result.allowed is True, index
        assert result.remaining == 2 - index
    denied = check_rate_limit("unit_test", "subject-a", 3, 60)
    assert denied.allowed is False
    assert denied.remaining == 0
    assert denied.retry_after >= 1
    clear_redis_bucket("unit_test")


def test_counters_are_isolated_per_subject(limits_on) -> None:
    for _ in range(3):
        check_rate_limit("unit_test_b", "subject-a", 3, 60)
    assert check_rate_limit("unit_test_b", "subject-b", 3, 60).allowed is True
    clear_redis_bucket("unit_test_b")


def test_limiter_degrades_gracefully_when_redis_is_unavailable(monkeypatch, limits_on) -> None:
    """A Redis outage must not take the product offline, but must not remove
    protection from unauthenticated endpoints either."""
    import zentra.core.ratelimit as ratelimit

    class _Broken:
        def pipeline(self):
            raise ConnectionError("redis down")

    monkeypatch.setattr(ratelimit, "get_redis", lambda: _Broken())
    allowed = [check_rate_limit("fallback", "subject", 2, 60).allowed for _ in range(4)]
    # The in-process fallback still enforces the limit.
    assert allowed == [True, True, False, False]


# ---------------------------------------------------------------- public scan
def test_public_scan_returns_a_useful_but_redacted_result(client: TestClient) -> None:
    response = client.post("/api/v1/public/scan", json={"domain": "public-demo-vendor.io"})
    assert response.status_code == 200
    body = response.json()

    assert body["domain"] == "public-demo-vendor.io"
    assert body["headline"] and body["explanation"] and body["recommended_action"]
    assert "not legal, regulatory" in body["disclaimer"]
    assert len(body["top_findings"]) <= 3
    assert body["categories"]

    # Nothing internal leaks out.
    serialized = response.text.lower()
    for leak in (
        "api_key",
        "apikey",
        "sk_live",
        "shodan",
        "hibp",
        "ssllabs",
        "evidence",
        "traceback",
    ):
        assert leak not in serialized
    for category in body["categories"]:
        assert set(category) == {"display_name", "assessed", "status", "points", "max_points"}


@pytest.mark.parametrize(
    "domain",
    [
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.1",
        "internal.local",
        "::1",
        "not a domain",
    ],
)
def test_public_scan_rejects_unsafe_targets(client: TestClient, domain: str) -> None:
    response = client.post("/api/v1/public/scan", json={"domain": domain})
    assert response.status_code == 422, domain


def test_public_scan_rejects_oversized_input(client: TestClient) -> None:
    response = client.post("/api/v1/public/scan", json={"domain": "a" * 5000 + ".com"})
    assert response.status_code == 422


def test_public_scan_is_rate_limited(client: TestClient, limits_on) -> None:
    limit, _ = limits_on.rate("public_scan")
    statuses = [
        client.post("/api/v1/public/scan", json={"domain": f"vendor-{i}.io"}).status_code
        for i in range(limit + 2)
    ]
    assert statuses[:limit] == [200] * limit
    assert statuses[limit] == 429

    denied = client.post("/api/v1/public/scan", json={"domain": "another-vendor.io"})
    assert denied.status_code == 429
    assert "Retry-After" in denied.headers
    assert denied.json()["error"]["code"] == "RATE_LIMITED"


def test_public_scan_does_not_require_authentication(client: TestClient) -> None:
    response = client.post("/api/v1/public/scan", json={"domain": "anonymous-vendor.io"})
    assert response.status_code == 200


def test_public_scan_result_is_recorded_without_a_raw_ip(client: TestClient, db) -> None:
    from zentra.db.models import PublicScan

    client.post("/api/v1/public/scan", json={"domain": "recorded-vendor.io"})
    record = db.query(PublicScan).filter(PublicScan.domain == "recorded-vendor.io").one()
    assert record.requester_hash
    assert "." not in record.requester_hash  # not an IPv4 address
    assert record.requester_hash != "testclient"


# ------------------------------------------------------------- authentication
def test_authentication_attempts_are_rate_limited(client: TestClient, limits_on) -> None:
    limit, _ = limits_on.rate("auth")
    statuses = []
    for _ in range(limit + 2):
        statuses.append(
            client.post(
                "/api/v1/auth/signin",
                json={"email": "victim@example.io", "password": "Guess-Me-1234!"},
            ).status_code
        )
    assert 429 in statuses
    assert statuses.index(429) <= limit


# --------------------------------------------------------------- manual scans
def test_manual_scan_triggers_are_rate_limited(
    client: TestClient, account: Account, limits_on, grant_plan
) -> None:
    grant_plan(account.organization_id, "scale")
    limit, _ = limits_on.rate("manual_scan")
    vendor_ids = [
        account.post(
            "/api/v1/vendors", json={"name": f"V{i}", "domain": f"scan-limit-{i}.io"}
        ).json()["id"]
        for i in range(3)
    ]
    statuses = []
    for index in range(limit + 3):
        vendor_id = vendor_ids[index % len(vendor_ids)]
        statuses.append(account.post(f"/api/v1/vendors/{vendor_id}/scan", json={}).status_code)
    assert 429 in statuses


def test_report_generation_is_rate_limited(account: Account, limits_on, grant_plan) -> None:
    grant_plan(account.organization_id, "growth")
    limit, _ = limits_on.rate("report")
    statuses = [
        account.post("/api/v1/reports", json={"title": f"Report {i}"}).status_code
        for i in range(limit + 2)
    ]
    assert 429 in statuses


def test_rate_limit_headers_are_present_on_allowed_requests(account: Account, limits_on) -> None:
    response = account.get("/api/v1/vendors")
    assert response.status_code == 200
    assert "X-RateLimit-Limit" in response.headers
    assert "X-RateLimit-Remaining" in response.headers


def test_health_endpoints_are_not_rate_limited(client: TestClient, limits_on) -> None:
    for _ in range(50):
        assert client.get("/health").status_code == 200
