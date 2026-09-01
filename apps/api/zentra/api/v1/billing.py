"""Billing endpoints and the Stripe webhook."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, Response, status

from zentra.api.schemas import (
    BillingResponse,
    CheckoutRequest,
    CheckoutResponse,
    PortalResponse,
)
from zentra.auth.deps import CurrentPrincipal, DbSession, Principal, require_role
from zentra.core.entitlements import Plan
from zentra.logging import get_logger
from zentra.services import billing as billing_service
from zentra.services.organizations import entitlements_for

log = get_logger("zentra.api.billing")

router = APIRouter(prefix="/billing", tags=["Billing"])


@router.get(
    "",
    response_model=BillingResponse,
    summary="Current plan, entitlements and available upgrades",
    description=(
        "Entitlements are always derived server-side from the subscription record. "
        "Clients must not infer entitlements from anything else."
    ),
)
async def get_billing(principal: CurrentPrincipal, session: DbSession) -> BillingResponse:
    entitlements = entitlements_for(session, principal.organization)
    subscription = billing_service.ensure_subscription(session, principal.organization)
    return BillingResponse(
        plan=entitlements.plan.value,
        status=subscription.status,
        entitlements=entitlements.to_dict(),
        current_period_end=subscription.current_period_end,
        cancel_at_period_end=subscription.cancel_at_period_end,
        stripe_configured=billing_service.stripe_configured(),
        available_plans=billing_service.available_plans(),
    )


@router.post(
    "/checkout",
    response_model=CheckoutResponse,
    summary="Start a Stripe Checkout session",
    responses={400: {"description": "Billing or the requested price is not configured."}},
)
async def create_checkout(
    payload: CheckoutRequest,
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
) -> CheckoutResponse:
    plan = Plan(payload.plan) if payload.plan else None
    result = billing_service.create_checkout_session(
        session,
        organization=principal.organization,
        user=principal.user,
        plan=plan,
        product=payload.product,
        success_url=payload.success_url,
        cancel_url=payload.cancel_url,
    )
    return CheckoutResponse(**result)


@router.post(
    "/portal",
    response_model=PortalResponse,
    summary="Open the Stripe customer portal",
)
async def create_portal(
    principal: Annotated[Principal, Depends(require_role("admin"))], session: DbSession
) -> PortalResponse:
    url = billing_service.create_portal_session(
        session, organization=principal.organization, user=principal.user
    )
    return PortalResponse(portal_url=url)


webhook_router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


@webhook_router.post(
    "/stripe",
    status_code=status.HTTP_200_OK,
    summary="Stripe webhook receiver",
    description=(
        "Verifies the Stripe signature, then applies the event exactly once. "
        "Redelivered events are acknowledged without re-applying."
    ),
    responses={401: {"description": "Signature verification failed."}},
)
async def stripe_webhook(
    request: Request,
    session: DbSession,
    stripe_signature: Annotated[str | None, Header(alias="stripe-signature")] = None,
) -> Response:
    # The raw body is required for signature verification: it must not be
    # re-serialized from a parsed model.
    payload = await request.body()
    if len(payload) > 1_000_000:
        return Response(status_code=413)
    event = billing_service.verify_webhook(payload, stripe_signature)
    result = billing_service.process_webhook(session, event)
    log.info(
        "stripe_webhook_handled",
        event_type=str(event.get("type")),
        result=result,
    )
    return Response(
        content=f'{{"received":true,"result":"{result}"}}',
        media_type="application/json",
        status_code=200,
    )
