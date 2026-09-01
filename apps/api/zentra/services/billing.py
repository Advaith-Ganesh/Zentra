"""Stripe subscription management.

Two rules govern this module:

1. **The backend never trusts the frontend for subscription state.** Plan and
   status are only ever written from a verified Stripe webhook or a direct
   Stripe API read — never from a request body.
2. **Webhook processing is idempotent.** Every event is recorded in
   ``webhook_events`` with a unique ``(provider, event_id)`` constraint, so a
   redelivered event is a no-op.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zentra.config import get_settings
from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.core.entitlements import PLANS, Plan, plan_for_price_id, price_id_for_plan
from zentra.db.models import Organization, Subscription, User, WebhookEvent
from zentra.errors import (
    AuthenticationError,
    ProviderError,
    ValidationError,
)
from zentra.logging import get_logger

log = get_logger("zentra.billing")

HANDLED_EVENTS = frozenset(
    {
        "checkout.session.completed",
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.payment_failed",
        "invoice.paid",
    }
)


def stripe_configured() -> bool:
    return bool(get_settings().stripe_secret_key)


def _stripe() -> Any:
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise ValidationError(
            "Billing is not configured for this deployment.", code="BILLING_NOT_CONFIGURED"
        )
    import stripe

    stripe.api_key = settings.stripe_secret_key
    stripe.max_network_retries = 2
    return stripe


def ensure_subscription(session: Session, organization: Organization) -> Subscription:
    subscription = session.execute(
        select(Subscription).where(Subscription.organization_id == organization.id)
    ).scalar_one_or_none()
    if subscription is None:
        subscription = Subscription(organization_id=organization.id, plan="free", status="active")
        session.add(subscription)
        session.flush()
    return subscription


def ensure_customer(session: Session, *, organization: Organization, user: User) -> str:
    """Create (or reuse) the Stripe customer for an organization."""
    subscription = ensure_subscription(session, organization)
    if subscription.stripe_customer_id:
        return subscription.stripe_customer_id

    stripe = _stripe()
    try:
        customer = stripe.Customer.create(
            email=user.email,
            name=organization.name,
            metadata={
                "zentra_organization_id": str(organization.id),
                "zentra_organization_slug": organization.slug,
            },
            idempotency_key=f"zentra-customer-{organization.id}",
        )
    except Exception as exc:
        log.error("stripe_customer_failed", error_type=type(exc).__name__)
        raise ProviderError("Billing provider is unavailable.") from exc

    subscription.stripe_customer_id = customer["id"]
    session.flush()
    return str(customer["id"])


def create_checkout_session(
    session: Session,
    *,
    organization: Organization,
    user: User,
    plan: Plan | None,
    product: str = "subscription",
    success_url: str | None = None,
    cancel_url: str | None = None,
) -> dict[str, str]:
    settings = get_settings()
    stripe = _stripe()
    customer_id = ensure_customer(session, organization=organization, user=user)

    if product == "report_pack":
        price_id = settings.stripe_report_pack_price_id
        mode = "payment"
        if not price_id:
            raise ValidationError(
                "The report pack is not configured for this deployment.",
                code="PRICE_NOT_CONFIGURED",
            )
    else:
        if plan is None:
            raise ValidationError("A plan is required.", code="PLAN_REQUIRED")
        price_id = price_id_for_plan(plan)
        mode = "subscription"
        if not price_id:
            raise ValidationError(
                f"The {plan.value} plan is not configured for this deployment.",
                code="PRICE_NOT_CONFIGURED",
            )

    # Only accept redirect URLs on our own app origin.
    success = _safe_redirect(success_url, f"{settings.app_url}/dashboard/billing?checkout=success")
    cancel = _safe_redirect(cancel_url, f"{settings.app_url}/dashboard/billing?checkout=cancelled")

    try:
        checkout = stripe.checkout.Session.create(
            mode=mode,
            customer=customer_id,
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success + "&session_id={CHECKOUT_SESSION_ID}"
            if "?" in success
            else success + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=cancel,
            client_reference_id=str(organization.id),
            metadata={
                "zentra_organization_id": str(organization.id),
                "zentra_product": product,
                "zentra_plan": plan.value if plan else "",
            },
            allow_promotion_codes=True,
        )
    except Exception as exc:
        log.error("stripe_checkout_failed", error_type=type(exc).__name__)
        raise ProviderError("Billing provider is unavailable.") from exc

    audit.record(
        session,
        action=AuditAction.CHECKOUT_STARTED,
        organization_id=organization.id,
        actor_user_id=user.id,
        resource_type="subscription",
        metadata={"product": product, "plan": plan.value if plan else None},
    )
    return {"checkout_url": str(checkout["url"]), "session_id": str(checkout["id"])}


def create_portal_session(
    session: Session, *, organization: Organization, user: User, return_url: str | None = None
) -> str:
    settings = get_settings()
    stripe = _stripe()
    subscription = ensure_subscription(session, organization)
    if not subscription.stripe_customer_id:
        raise ValidationError(
            "This organization does not have a billing account yet.",
            code="NO_BILLING_ACCOUNT",
        )
    destination = _safe_redirect(return_url, f"{settings.app_url}/dashboard/billing")
    try:
        portal = stripe.billing_portal.Session.create(
            customer=subscription.stripe_customer_id, return_url=destination
        )
    except Exception as exc:
        log.error("stripe_portal_failed", error_type=type(exc).__name__)
        raise ProviderError("Billing provider is unavailable.") from exc
    return str(portal["url"])


def _safe_redirect(candidate: str | None, fallback: str) -> str:
    """Only permit redirects back to the configured app origin."""
    if not candidate:
        return fallback
    settings = get_settings()
    if candidate.startswith(settings.app_url) and len(candidate) <= 500:
        return candidate
    log.warning("rejected_redirect_url")
    return fallback


# --------------------------------------------------------------------- webhooks
def _as_dict(value: Any) -> dict[str, Any]:
    """Convert a Stripe SDK resource to a plain dict, recursively."""
    if hasattr(value, "to_dict_recursive"):
        return dict(value.to_dict_recursive())
    if hasattr(value, "to_dict"):
        return dict(value.to_dict())
    return dict(value)


def verify_webhook(payload: bytes, signature: str | None) -> dict[str, Any]:
    """Verify a Stripe webhook signature and return the parsed event."""
    settings = get_settings()
    if not settings.stripe_webhook_secret:
        raise ValidationError("Stripe webhooks are not configured.", code="WEBHOOK_NOT_CONFIGURED")
    if not signature:
        raise AuthenticationError("Missing Stripe signature.", code="INVALID_SIGNATURE")
    import stripe

    try:
        event = stripe.Webhook.construct_event(payload, signature, settings.stripe_webhook_secret)
    except ValueError as exc:
        raise ValidationError("Malformed webhook payload.", code="INVALID_PAYLOAD") from exc
    except stripe.SignatureVerificationError as exc:
        log.warning("stripe_webhook_bad_signature")
        raise AuthenticationError(
            "Stripe signature verification failed.", code="INVALID_SIGNATURE"
        ) from exc
    # Stripe's SDK returns a rich object; work with a plain dict internally so
    # nothing downstream depends on the SDK's resource types.
    return _as_dict(event)


def process_webhook(session: Session, event: dict[str, Any]) -> str:
    """Apply a verified Stripe event. Returns a short status string."""
    event_id = str(event.get("id", ""))
    event_type = str(event.get("type", ""))
    if not event_id:
        raise ValidationError("Webhook event has no id.", code="INVALID_PAYLOAD")

    # Idempotency ledger. The unique constraint is the source of truth, so two
    # concurrent deliveries cannot both proceed.
    ledger = WebhookEvent(provider="stripe", event_id=event_id, event_type=event_type)
    session.add(ledger)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        log.info("stripe_webhook_duplicate", event_id=event_id, event_type=event_type)
        return "duplicate"

    if event_type not in HANDLED_EVENTS:
        ledger.status = "ignored"
        ledger.processed_at = datetime.now(UTC)
        session.flush()
        return "ignored"

    obj = (event.get("data") or {}).get("object") or {}
    try:
        if event_type == "checkout.session.completed":
            _handle_checkout_completed(session, obj)
        elif event_type in (
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
        ):
            _handle_subscription_event(session, obj, deleted=event_type.endswith("deleted"))
        elif event_type == "invoice.payment_failed":
            _handle_payment_failed(session, obj)
        elif event_type == "invoice.paid":
            _handle_invoice_paid(session, obj)
    except Exception as exc:
        ledger.status = "failed"
        ledger.error_message = type(exc).__name__
        session.flush()
        log.error("stripe_webhook_failed", event_type=event_type, error_type=type(exc).__name__)
        raise

    ledger.status = "processed"
    ledger.processed_at = datetime.now(UTC)
    session.flush()
    return "processed"


def _subscription_for_customer(session: Session, customer_id: str) -> Subscription | None:
    if not customer_id:
        return None
    return session.execute(
        select(Subscription).where(Subscription.stripe_customer_id == customer_id)
    ).scalar_one_or_none()


def _subscription_for_org_id(session: Session, org_id: str | None) -> Subscription | None:
    if not org_id:
        return None
    try:
        identifier = uuid.UUID(org_id)
    except ValueError:
        return None
    return session.execute(
        select(Subscription).where(Subscription.organization_id == identifier)
    ).scalar_one_or_none()


def _handle_checkout_completed(session: Session, obj: dict[str, Any]) -> None:
    metadata = obj.get("metadata") or {}
    subscription = _subscription_for_org_id(
        session, metadata.get("zentra_organization_id") or obj.get("client_reference_id")
    ) or _subscription_for_customer(session, str(obj.get("customer") or ""))
    if subscription is None:
        log.warning("stripe_checkout_unmatched")
        return

    if not subscription.stripe_customer_id and obj.get("customer"):
        subscription.stripe_customer_id = str(obj["customer"])

    if metadata.get("zentra_product") == "report_pack":
        subscription.report_pack_credits += 1
        session.flush()
        log.info(
            "report_pack_purchased",
            organization_id=str(subscription.organization_id),
            credits=subscription.report_pack_credits,
        )
        return

    stripe_subscription_id = obj.get("subscription")
    if stripe_subscription_id:
        subscription.stripe_subscription_id = str(stripe_subscription_id)
        # Read the authoritative state back from Stripe rather than inferring it.
        _sync_from_stripe(session, subscription)
    session.flush()


def _handle_subscription_event(session: Session, obj: dict[str, Any], *, deleted: bool) -> None:
    subscription = _subscription_for_customer(session, str(obj.get("customer") or ""))
    if subscription is None:
        subscription = _subscription_for_org_id(
            session, (obj.get("metadata") or {}).get("zentra_organization_id")
        )
    if subscription is None:
        log.warning("stripe_subscription_unmatched")
        return

    previous_plan = subscription.plan
    if deleted:
        subscription.plan = Plan.FREE.value
        subscription.status = "canceled"
        subscription.canceled_at = datetime.now(UTC)
        subscription.stripe_subscription_id = None
        subscription.cancel_at_period_end = False
    else:
        _apply_subscription_object(subscription, obj)

    _apply_vendor_limit(session, subscription)
    session.flush()
    _record_change(session, subscription, previous_plan)


def _apply_subscription_object(subscription: Subscription, obj: dict[str, Any]) -> None:
    subscription.stripe_subscription_id = str(obj.get("id") or "") or None
    subscription.status = str(obj.get("status") or "active")
    subscription.cancel_at_period_end = bool(obj.get("cancel_at_period_end"))

    items = ((obj.get("items") or {}).get("data")) or []
    price_id = ""
    period_start = obj.get("current_period_start")
    period_end = obj.get("current_period_end")
    if items:
        price_id = str(((items[0] or {}).get("price") or {}).get("id") or "")
        # Newer Stripe API versions carry the period on the item.
        period_start = items[0].get("current_period_start", period_start)
        period_end = items[0].get("current_period_end", period_end)

    plan = plan_for_price_id(price_id)
    if plan is not None:
        subscription.plan = plan.value
    elif subscription.status not in ("active", "trialing", "past_due"):
        subscription.plan = Plan.FREE.value

    subscription.current_period_start = _timestamp(period_start)
    subscription.current_period_end = _timestamp(period_end)
    if obj.get("canceled_at"):
        subscription.canceled_at = _timestamp(obj.get("canceled_at"))


def _handle_payment_failed(session: Session, obj: dict[str, Any]) -> None:
    subscription = _subscription_for_customer(session, str(obj.get("customer") or ""))
    if subscription is None:
        return
    subscription.status = "past_due"
    session.flush()
    log.warning("subscription_past_due", organization_id=str(subscription.organization_id))
    _notify_plan_change(session, subscription)


def _handle_invoice_paid(session: Session, obj: dict[str, Any]) -> None:
    subscription = _subscription_for_customer(session, str(obj.get("customer") or ""))
    if subscription is None:
        return
    if subscription.status == "past_due":
        subscription.status = "active"
        session.flush()


def _sync_from_stripe(session: Session, subscription: Subscription) -> None:
    """Fetch the live subscription from Stripe and apply it."""
    if not subscription.stripe_subscription_id:
        return
    try:
        stripe = _stripe()
        remote = stripe.Subscription.retrieve(subscription.stripe_subscription_id)
    except Exception as exc:  # noqa: BLE001
        log.warning("stripe_subscription_fetch_failed", error_type=type(exc).__name__)
        return
    previous_plan = subscription.plan
    _apply_subscription_object(subscription, _as_dict(remote))
    _apply_vendor_limit(session, subscription)
    session.flush()
    _record_change(session, subscription, previous_plan)


def _apply_vendor_limit(session: Session, subscription: Subscription) -> None:
    organization = session.get(Organization, subscription.organization_id)
    if organization is None:
        return
    try:
        plan = Plan(subscription.plan)
    except ValueError:
        plan = Plan.FREE
    organization.plan = plan.value
    organization.vendor_limit = PLANS[plan].vendor_limit


def _record_change(session: Session, subscription: Subscription, previous_plan: str) -> None:
    if previous_plan == subscription.plan:
        return
    audit.record(
        session,
        action=AuditAction.SUBSCRIPTION_CHANGED,
        organization_id=subscription.organization_id,
        actor_type="system",
        resource_type="subscription",
        resource_id=subscription.id,
        metadata={
            "from_plan": previous_plan,
            "to_plan": subscription.plan,
            "status": subscription.status,
        },
    )
    log.info(
        "subscription_changed",
        organization_id=str(subscription.organization_id),
        from_plan=previous_plan,
        to_plan=subscription.plan,
        status=subscription.status,
    )
    _notify_plan_change(session, subscription)


def _notify_plan_change(session: Session, subscription: Subscription) -> None:
    try:
        from zentra.integrations.email.service import send_subscription_changed
        from zentra.services.alerts import _recipients

        organization = session.get(Organization, subscription.organization_id)
        if organization is None:
            return
        recipients = _recipients(session, organization.id)
        if recipients:
            send_subscription_changed(
                to=recipients,
                organization=organization,
                plan=subscription.plan,
                status=subscription.status,
            )
    except Exception as exc:  # noqa: BLE001 - never fail a webhook on email
        log.warning("plan_change_email_failed", error_type=type(exc).__name__)


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, int | float) and value > 0:
        return datetime.fromtimestamp(value, tz=UTC)
    return None


def available_plans() -> list[dict[str, Any]]:
    settings = get_settings()
    out = []
    for plan, definition in PLANS.items():
        if plan is Plan.FREE:
            continue
        out.append(
            {
                "plan": plan.value,
                "name": definition.display_name,
                "price_pence": definition.price_pence,
                "price_display": f"£{definition.price_pence // 100}/month",
                "currency": definition.currency,
                "vendor_limit": definition.vendor_limit,
                "unlimited_vendors": definition.vendor_limit == -1,
                "description": definition.description,
                "features": sorted(f.value for f in definition.features),
                "purchasable": bool(price_id_for_plan(plan)),
            }
        )
    out.append(
        {
            "plan": "report_pack",
            "name": "Report pack",
            "price_pence": 9900,
            "price_display": "£99 one-off",
            "currency": "GBP",
            "description": "One-off pack that unlocks PDF vendor risk register exports.",
            "features": ["pdf_reports"],
            "purchasable": bool(settings.stripe_report_pack_price_id),
        }
    )
    return out
