"""Graceful degradation, observability and error handling."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from tests.conftest import Account


# ---------------------------------------------------------------------- health
def test_health_is_cheap_and_touches_no_dependency(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readiness_reports_dependency_state(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code in (200, 503)
    checks = response.json()["checks"]
    assert set(checks) == {"database", "redis"}


def test_readiness_returns_503_when_the_database_is_down(client: TestClient, monkeypatch) -> None:
    import zentra.main as main

    monkeypatch.setattr(main, "db_ping", lambda *a, **k: False)
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"]["database"] == "unavailable"


def test_liveness_still_ok_when_dependencies_are_down(client: TestClient, monkeypatch) -> None:
    import zentra.main as main

    monkeypatch.setattr(main, "db_ping", lambda *a, **k: False)
    monkeypatch.setattr(main, "redis_available", lambda *a, **k: False)
    assert client.get("/health").status_code == 200


# ------------------------------------------------------------------ error shape
def test_every_error_uses_the_standard_envelope(client: TestClient, account: Account) -> None:
    cases = [
        client.get("/api/v1/me"),  # 401
        account.get(f"/api/v1/vendors/{uuid.uuid4()}"),  # 404
        account.post("/api/v1/vendors", json={"name": "x"}),  # 422
    ]
    for response in cases:
        body = response.json()
        assert set(body) == {"error"}
        assert {"code", "message", "request_id"} <= set(body["error"])
        assert isinstance(body["error"]["code"], str)
        assert body["error"]["request_id"]


def test_request_id_is_echoed_and_correlates(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "my-correlation-id"})
    assert response.headers["X-Request-ID"] == "my-correlation-id"


def test_request_id_is_generated_when_absent(client: TestClient) -> None:
    assert len(client.get("/health").headers["X-Request-ID"]) == 32


def test_unhandled_exception_returns_a_safe_message_without_a_traceback(
    client: TestClient, account: Account, monkeypatch
) -> None:
    from zentra.api.v1 import vendors as vendors_router

    def _explode(*args, **kwargs):
        raise RuntimeError("database password is hunter2")

    monkeypatch.setattr(vendors_router.vendors_service, "list_vendors", _explode)
    response = account.get("/api/v1/vendors")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "INTERNAL_ERROR"
    assert "hunter2" not in response.text
    assert "Traceback" not in response.text
    assert "RuntimeError" not in response.text or "debug_error_type" in response.text


def test_404_for_an_unknown_route(client: TestClient) -> None:
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_405_for_a_wrong_method(client: TestClient) -> None:
    response = client.delete("/health")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "METHOD_NOT_ALLOWED"


def test_malformed_json_is_a_422_not_a_500(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/signin",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422


def test_oversized_request_body_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/signin",
        content=b"x" * 2_000_000,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


# ------------------------------------------------------------ security headers
def test_security_headers_are_applied(client: TestClient) -> None:
    headers = client.get("/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Cache-Control"] == "no-store"


def test_cors_allows_only_configured_origins(client: TestClient) -> None:
    allowed = client.options(
        "/api/v1/vendors",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"

    denied = client.options(
        "/api/v1/vendors",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert denied.headers.get("access-control-allow-origin") != "https://evil.example"


# ------------------------------------------------------ provider/worker failure
def test_scan_records_a_failure_rather_than_vanishing(account: Account, db, monkeypatch) -> None:
    from zentra.db.models import Scan
    from zentra.services import scans as scans_service

    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "failing-vendor.io"}
    ).json()["id"]
    scan = (
        db.query(Scan)
        .filter(Scan.vendor_id == uuid.UUID(vendor_id))
        .order_by(Scan.created_at.desc())
        .first()
    )

    def _explode(*args, **kwargs):
        raise RuntimeError("scanner subsystem down")

    monkeypatch.setattr(scans_service, "run_scan", _explode)
    result = scans_service.execute_scan(db, scan.id)
    db.commit()

    assert result.status == "failed"
    assert result.completed_at is not None
    assert "scanner subsystem down" not in (result.error_message or "")

    listed = account.get(f"/api/v1/vendors/{vendor_id}/scans").json()
    assert listed[0]["status"] == "failed"
    assert listed[0]["error_message"]


def test_a_failed_scan_does_not_overwrite_a_previous_good_score(
    account: Account, db, monkeypatch
) -> None:
    from zentra.db.models import Scan, Vendor
    from zentra.services import scans as scans_service

    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "resilient-vendor.io"}
    ).json()["id"]
    first = db.query(Scan).filter(Scan.vendor_id == uuid.UUID(vendor_id)).one()
    scans_service.execute_scan(db, first.id)
    db.commit()
    good_score = db.get(Vendor, uuid.UUID(vendor_id)).current_score

    vendor = db.get(Vendor, uuid.UUID(vendor_id))
    second = scans_service.queue_scan(db, vendor=vendor, trigger="manual")
    db.commit()
    monkeypatch.setattr(
        scans_service, "run_scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down"))
    )
    scans_service.execute_scan(db, second.id)
    db.commit()

    assert db.get(Vendor, uuid.UUID(vendor_id)).current_score == good_score


def test_stuck_scans_are_reaped(db) -> None:
    from datetime import UTC, datetime, timedelta

    from zentra.db.models import Scan, User, Vendor
    from zentra.services.organizations import create_organization
    from zentra.workers.tasks import reap_stuck_scans

    user = User(email="reaper@example.io", full_name="Reaper")
    db.add(user)
    db.flush()
    organization = create_organization(db, name="Reaper Co", owner=user)
    vendor = Vendor(organization_id=organization.id, name="V", domain="stuck-vendor.io")
    db.add(vendor)
    db.flush()
    scan = Scan(
        organization_id=organization.id,
        vendor_id=vendor.id,
        status="running",
        started_at=datetime.now(UTC) - timedelta(hours=2),
    )
    db.add(scan)
    db.commit()

    result = reap_stuck_scans()
    assert result["reaped"] >= 1
    db.expire_all()
    assert db.get(Scan, scan.id).status == "failed"
    assert db.get(Scan, scan.id).error_code == "WORKER_LOST"


def test_email_failure_does_not_break_the_alert_flow(
    account: Account, db, monkeypatch, grant_plan
) -> None:
    from zentra.db.models import Scan, Vendor
    from zentra.integrations.email import service as email_service
    from zentra.services import alerts as alerts_service

    grant_plan(account.organization_id, "growth")
    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "email-fail-vendor.io"}
    ).json()["id"]
    from zentra.services import scans as scans_service

    scan = db.query(Scan).filter(Scan.vendor_id == uuid.UUID(vendor_id)).one()
    scans_service.execute_scan(db, scan.id)
    db.commit()

    monkeypatch.setattr(
        alerts_service,
        "_recipients",
        lambda *a, **k: ["someone@example.io"],
    )
    monkeypatch.setattr(
        email_service,
        "send_risk_alert",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("smtp down")),
    )

    vendor = db.get(Vendor, uuid.UUID(vendor_id))
    # A fresh scan row so this alert has its own dedupe key.
    later = scans_service.queue_scan(db, vendor=vendor, trigger="manual")
    db.commit()
    alert = alerts_service.evaluate_score_change(
        db, vendor=vendor, scan=later, old_score=5, new_score=60
    )
    assert alert is not None
    alerts_service.deliver_pending(db, alert=alert)
    db.commit()

    assert alert.notification_status == "failed"
    # The alert itself is still recorded and visible in the product.
    assert any(a["id"] == str(alert.id) for a in account.get("/api/v1/alerts").json())


def test_alerts_are_suppressed_on_a_plan_without_them(account: Account, db) -> None:
    from zentra.db.models import Scan, Vendor
    from zentra.services import alerts as alerts_service
    from zentra.services import scans as scans_service

    vendor_id = account.post(
        "/api/v1/vendors", json={"name": "Vendor", "domain": "free-plan-vendor.io"}
    ).json()["id"]
    scan = db.query(Scan).filter(Scan.vendor_id == uuid.UUID(vendor_id)).one()
    scans_service.execute_scan(db, scan.id)
    db.commit()

    vendor = db.get(Vendor, uuid.UUID(vendor_id))
    later = scans_service.queue_scan(db, vendor=vendor, trigger="manual")
    db.commit()
    alert = alerts_service.evaluate_score_change(
        db, vendor=vendor, scan=later, old_score=5, new_score=60
    )
    assert alert is not None
    alerts_service.deliver_pending(db, alert=alert)
    db.commit()
    assert alert.notification_status == "suppressed"


# ------------------------------------------------------------------- logging
def test_sensitive_values_are_redacted_from_logs() -> None:
    from zentra.logging import redaction_processor

    event = {
        "event": "test",
        "password": "hunter2",
        "api_key": "zk_live_abcdefghijklmnop",
        "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        "note": "stripe key sk_live_abcdefghijklmnop leaked",
        "slack": "xoxb-1234567890-abcdef",
        "nested": {"secret": "s3cr3t", "safe": "keep me"},
        "vendor": "stripe.com",
    }
    scrubbed = redaction_processor(None, "info", event)
    assert scrubbed["password"] == "[redacted]"
    assert scrubbed["api_key"] == "[redacted]"
    assert scrubbed["authorization"] == "[redacted]"
    assert "sk_live_" not in scrubbed["note"]
    assert "xoxb-" not in scrubbed["slack"]
    assert scrubbed["nested"]["secret"] == "[redacted]"
    assert scrubbed["nested"]["safe"] == "keep me"
    assert scrubbed["vendor"] == "stripe.com"


def test_audit_log_records_key_actions(account: Account, db) -> None:
    from zentra.db.models import AuditLog

    account.post("/api/v1/vendors", json={"name": "Audited", "domain": "audited-vendor.io"})
    actions = {
        row.action
        for row in db.query(AuditLog)
        .filter(AuditLog.organization_id == account.organization_id)
        .all()
    }
    assert {"user.signed_up", "organization.created", "vendor.created", "scan.triggered"} <= actions


def test_audit_entries_carry_a_request_id(account: Account, db) -> None:
    from zentra.db.models import AuditLog

    account.post("/api/v1/vendors", json={"name": "Traced", "domain": "traced-vendor.io"})
    row = db.query(AuditLog).filter(AuditLog.action == "vendor.created").one()
    assert row.request_id


# --------------------------------------------------------------- configuration
def test_production_configuration_rejects_unsafe_settings() -> None:
    from zentra.config import Settings

    with pytest.raises(ValueError) as exc:
        Settings(
            environment="production",
            debug=True,
            use_mock_scanners=True,
            jwt_secret="short",
            cors_allowed_origins="*",
            rate_limit_enabled=False,
            secrets_encryption_key="",
        )
    message = str(exc.value)
    for expected in [
        "DEBUG must be false",
        "USE_MOCK_SCANNERS must be false",
        "JWT_SECRET",
        "SECRETS_ENCRYPTION_KEY",
        "RATE_LIMIT_ENABLED",
        "wildcard",
    ]:
        assert expected in message


def test_production_configuration_accepts_a_safe_setup() -> None:
    from zentra.config import Settings

    settings = Settings(
        environment="production",
        debug=False,
        use_mock_scanners=False,
        rate_limit_enabled=True,
        jwt_secret="a" * 64,
        secrets_encryption_key="sHRxYnPTt9EHwSGtQ1c1qE1MMBLNwoFbcHXCoI0uZQY=",
        cors_allowed_origins="https://app.zentra.example",
        auth_provider="local",
    )
    assert settings.is_production
    assert settings.cors_origins == ["https://app.zentra.example"]
