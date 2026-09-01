"""Entitlements, Stripe webhooks and plan enforcement."""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from tests.conftest import Account
from zentra.core.entitlements import (
    PLANS,
    Feature,
    Plan,
    build_entitlements,
    effective_plan,
)
from zentra.errors import EntitlementError


class _FakeOrg:
    vendor_limit = 0


class _FakeSubscription:
    def __init__(self, plan: str, status: str = "active") -> None:
        self.plan = plan
        self.status = status
        self.report_pack_credits = 0


# ------------------------------------------------------------- entitlement rules
def test_no_subscription_falls_back_to_free() -> None:
    assert effective_plan(None) is Plan.FREE


@pytest.mark.parametrize("status", ["canceled", "incomplete", "incomplete_expired", "unpaid"])
def test_inactive_subscription_drops_to_free(status: str) -> None:
    assert effective_plan(_FakeSubscription("scale", status)) is Plan.FREE


@pytest.mark.parametrize("status", ["active", "trialing", "past_due"])
def test_active_statuses_keep_the_paid_plan(status: str) -> None:
    assert effective_plan(_FakeSubscription("growth", status)) is Plan.GROWTH


def test_plan_vendor_limits() -> None:
    assert PLANS[Plan.STARTER].vendor_limit == 10
    assert PLANS[Plan.GROWTH].vendor_limit == 50
    assert PLANS[Plan.SCALE].vendor_limit == -1


def test_vendor_capacity_is_enforced() -> None:
    entitlements = build_entitlements(_FakeOrg(), _FakeSubscription("starter"), vendors_used=10)
    assert entitlements.at_vendor_limit is True
    with pytest.raises(EntitlementError) as exc:
        entitlements.require_vendor_capacity(1)
    assert exc.value.code == "VENDOR_LIMIT_REACHED"
    assert exc.value.details["vendor_limit"] == 10


def test_unlimited_plan_never_hits_a_vendor_limit() -> None:
    entitlements = build_entitlements(_FakeOrg(), _FakeSubscription("scale"), vendors_used=10_000)
    assert entitlements.at_vendor_limit is False
    entitlements.require_vendor_capacity(500)


def test_feature_gating_per_plan() -> None:
    starter = build_entitlements(_FakeOrg(), _FakeSubscription("starter"), 0)
    growth = build_entitlements(_FakeOrg(), _FakeSubscription("growth"), 0)
    scale = build_entitlements(_FakeOrg(), _FakeSubscription("scale"), 0)

    assert starter.has(Feature.PDF_REPORTS) is False
    assert growth.has(Feature.PDF_REPORTS) is True
    assert growth.has(Feature.PUBLIC_API) is False
    assert scale.has(Feature.PUBLIC_API) is True
    assert scale.has(Feature.WHITE_LABEL_REPORTS) is True
    assert growth.has(Feature.WHITE_LABEL_REPORTS) is False


def test_report_pack_credit_unlocks_pdf_reports_on_a_lower_plan() -> None:
    subscription = _FakeSubscription("starter")
    subscription.report_pack_credits = 1
    entitlements = build_entitlements(_FakeOrg(), subscription, 0)
    assert entitlements.has(Feature.PDF_REPORTS) is True


def test_entitlement_error_names_the_plans_that_include_the_feature() -> None:
    starter = build_entitlements(_FakeOrg(), _FakeSubscription("starter"), 0)
    with pytest.raises(EntitlementError) as exc:
        starter.require(Feature.PUBLIC_API)
    assert "scale" in exc.value.details["required_plans"]


# ------------------------------------------------------------------- API surface
def test_free_plan_vendor_limit_is_enforced_by_the_api(account: Account) -> None:
    for index in range(3):
        response = account.post(
            "/api/v1/vendors", json={"name": f"V{index}", "domain": f"vendor{index}.io"}
        )
        assert response.status_code == 201

    blocked = account.post("/api/v1/vendors", json={"name": "V4", "domain": "vendor4.io"})
    assert blocked.status_code == 402
    assert blocked.json()["error"]["code"] == "VENDOR_LIMIT_REACHED"


def test_upgrading_raises_the_vendor_limit(account: Account, grant_plan) -> None:
    for index in range(3):
        account.post("/api/v1/vendors", json={"name": f"V{index}", "domain": f"vendor{index}.io"})
    assert (
        account.post("/api/v1/vendors", json={"name": "V4", "domain": "vendor4.io"}).status_code
        == 402
    )

    grant_plan(account.organization_id, "growth")
    assert (
        account.post("/api/v1/vendors", json={"name": "V4", "domain": "vendor4.io"}).status_code
        == 201
    )


def test_pdf_reports_require_growth(account: Account, grant_plan) -> None:
    blocked = account.post("/api/v1/reports", json={})
    assert blocked.status_code == 402
    assert blocked.json()["error"]["details"]["feature"] == "pdf_reports"

    grant_plan(account.organization_id, "growth")
    assert account.post("/api/v1/reports", json={}).status_code == 202


def test_api_keys_require_scale(account: Account, grant_plan) -> None:
    grant_plan(account.organization_id, "growth")
    assert account.post("/api/v1/api-keys", json={"name": "CI"}).status_code == 402

    grant_plan(account.organization_id, "scale")
    created = account.post("/api/v1/api-keys", json={"name": "CI"})
    assert created.status_code == 201


def test_billing_endpoint_reports_server_derived_entitlements(account: Account) -> None:
    billing = account.get("/api/v1/billing").json()
    assert billing["plan"] == "free"
    assert billing["entitlements"]["vendor_limit"] == 3
    assert billing["entitlements"]["vendors_used"] == 0
    assert any(p["plan"] == "growth" for p in billing["available_plans"])


def test_billing_usage_counter_tracks_vendors(account: Account) -> None:
    account.post("/api/v1/vendors", json={"name": "V", "domain": "counted-vendor.io"})
    entitlements = account.get("/api/v1/billing").json()["entitlements"]
    assert entitlements["vendors_used"] == 1
    assert entitlements["vendors_remaining"] == 2


def test_checkout_requires_stripe_configuration(account: Account) -> None:
    response = account.post("/api/v1/billing/checkout", json={"plan": "growth"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "BILLING_NOT_CONFIGURED"


# ------------------------------------------------------------------- webhooks
def _signed(payload: dict, secret: str) -> tuple[bytes, str]:
    import hashlib
    import hmac

    body = json.dumps(payload).encode()
    timestamp = str(int(time.time()))
    signed_payload = f"{timestamp}.".encode() + body
    signature = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return body, f"t={timestamp},v1={signature}"


@pytest.fixture
def stripe_secret(monkeypatch) -> str:
    from zentra.config import get_settings

    secret = "whsec_" + "a" * 32
    settings = get_settings()
    monkeypatch.setattr(settings, "stripe_webhook_secret", secret)
    monkeypatch.setattr(settings, "stripe_secret_key", "sk_test_" + "b" * 24)
    monkeypatch.setattr(settings, "stripe_growth_price_id", "price_growth_test")
    return secret


def test_webhook_without_a_signature_is_rejected(client: TestClient, stripe_secret: str) -> None:
    response = client.post("/api/v1/webhooks/stripe", json={"id": "evt_1", "type": "ping"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_SIGNATURE"


def test_webhook_with_a_forged_signature_is_rejected(
    client: TestClient, stripe_secret: str
) -> None:
    body, _ = _signed({"id": "evt_1", "type": "ping"}, stripe_secret)
    response = client.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"stripe-signature": "t=1,v1=deadbeef", "content-type": "application/json"},
    )
    assert response.status_code == 401


def test_webhook_signed_with_the_wrong_secret_is_rejected(
    client: TestClient, stripe_secret: str
) -> None:
    body, signature = _signed({"id": "evt_1", "type": "ping"}, "whsec_" + "z" * 32)
    response = client.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"stripe-signature": signature, "content-type": "application/json"},
    )
    assert response.status_code == 401


def test_subscription_webhook_upgrades_the_plan(
    client: TestClient, account: Account, db, stripe_secret: str
) -> None:
    from zentra.db.models import Subscription

    subscription = (
        db.query(Subscription).filter(Subscription.organization_id == account.organization_id).one()
    )
    subscription.stripe_customer_id = "cus_test_123"
    db.commit()

    event = {
        "id": "evt_upgrade_1",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_test_123",
                "customer": "cus_test_123",
                "status": "active",
                "cancel_at_period_end": False,
                "current_period_end": int(time.time()) + 86_400 * 30,
                "items": {"data": [{"price": {"id": "price_growth_test"}}]},
            }
        },
    }
    body, signature = _signed(event, stripe_secret)
    response = client.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"stripe-signature": signature, "content-type": "application/json"},
    )
    assert response.status_code == 200
    assert response.json()["result"] == "processed"

    billing = account.get("/api/v1/billing").json()
    assert billing["plan"] == "growth"
    assert billing["entitlements"]["vendor_limit"] == 50


def test_duplicate_webhook_event_is_a_no_op(
    client: TestClient, account: Account, db, stripe_secret: str
) -> None:
    from zentra.db.models import Subscription

    subscription = (
        db.query(Subscription).filter(Subscription.organization_id == account.organization_id).one()
    )
    subscription.stripe_customer_id = "cus_dupe_1"
    db.commit()

    event = {
        "id": "evt_dupe_1",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_dupe_1",
                "customer": "cus_dupe_1",
                "status": "active",
                "items": {"data": [{"price": {"id": "price_growth_test"}}]},
            }
        },
    }
    body, signature = _signed(event, stripe_secret)
    headers = {"stripe-signature": signature, "content-type": "application/json"}

    first = client.post("/api/v1/webhooks/stripe", content=body, headers=headers)
    second = client.post("/api/v1/webhooks/stripe", content=body, headers=headers)
    assert first.json()["result"] == "processed"
    assert second.json()["result"] == "duplicate"


def test_subscription_deleted_downgrades_and_enforces_the_free_limit(
    client: TestClient, account: Account, db, grant_plan, stripe_secret: str
) -> None:
    from zentra.db.models import Subscription

    grant_plan(account.organization_id, "growth")
    subscription = (
        db.query(Subscription).filter(Subscription.organization_id == account.organization_id).one()
    )
    subscription.stripe_customer_id = "cus_cancel_1"
    subscription.stripe_subscription_id = "sub_cancel_1"
    db.commit()

    for index in range(4):
        account.post("/api/v1/vendors", json={"name": f"V{index}", "domain": f"cancel{index}.io"})

    event = {
        "id": "evt_cancel_1",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {"id": "sub_cancel_1", "customer": "cus_cancel_1", "status": "canceled"}
        },
    }
    body, signature = _signed(event, stripe_secret)
    client.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"stripe-signature": signature, "content-type": "application/json"},
    )

    billing = account.get("/api/v1/billing").json()
    assert billing["plan"] == "free"
    # Existing vendors are kept, but no new ones can be added over the limit.
    assert (
        account.post("/api/v1/vendors", json={"name": "V5", "domain": "cancel5.io"}).status_code
        == 402
    )
    # And paid features are gone.
    assert account.post("/api/v1/reports", json={}).status_code == 402


def test_payment_failure_marks_the_subscription_past_due(
    client: TestClient, account: Account, db, stripe_secret: str
) -> None:
    from zentra.db.models import Subscription

    subscription = (
        db.query(Subscription).filter(Subscription.organization_id == account.organization_id).one()
    )
    subscription.stripe_customer_id = "cus_pastdue_1"
    subscription.plan = "growth"
    db.commit()

    event = {
        "id": "evt_failed_1",
        "type": "invoice.payment_failed",
        "data": {"object": {"customer": "cus_pastdue_1"}},
    }
    body, signature = _signed(event, stripe_secret)
    client.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"stripe-signature": signature, "content-type": "application/json"},
    )
    billing = account.get("/api/v1/billing").json()
    assert billing["status"] == "past_due"
    # past_due keeps access during Stripe's dunning window.
    assert billing["plan"] == "growth"


def test_report_pack_purchase_adds_a_credit(
    client: TestClient, account: Account, db, stripe_secret: str
) -> None:
    from zentra.db.models import Subscription

    subscription = (
        db.query(Subscription).filter(Subscription.organization_id == account.organization_id).one()
    )
    subscription.stripe_customer_id = "cus_pack_1"
    db.commit()

    event = {
        "id": "evt_pack_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_pack_1",
                "client_reference_id": str(account.organization_id),
                "metadata": {
                    "zentra_organization_id": str(account.organization_id),
                    "zentra_product": "report_pack",
                },
            }
        },
    }
    body, signature = _signed(event, stripe_secret)
    client.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"stripe-signature": signature, "content-type": "application/json"},
    )
    # The credit unlocks PDF reports on the free plan.
    assert account.get("/api/v1/billing").json()["entitlements"]["report_pack_credits"] == 1
    assert account.post("/api/v1/reports", json={}).status_code == 202


def test_webhook_for_an_unknown_customer_is_ignored_safely(
    client: TestClient, stripe_secret: str
) -> None:
    event = {
        "id": "evt_unknown_1",
        "type": "customer.subscription.updated",
        "data": {"object": {"id": "sub_x", "customer": "cus_does_not_exist", "status": "active"}},
    }
    body, signature = _signed(event, stripe_secret)
    response = client.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"stripe-signature": signature, "content-type": "application/json"},
    )
    assert response.status_code == 200


def test_unhandled_event_types_are_acknowledged_not_processed(
    client: TestClient, stripe_secret: str
) -> None:
    event = {"id": "evt_other_1", "type": "customer.created", "data": {"object": {}}}
    body, signature = _signed(event, stripe_secret)
    response = client.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"stripe-signature": signature, "content-type": "application/json"},
    )
    assert response.json()["result"] == "ignored"
