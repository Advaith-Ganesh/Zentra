"""Plan definitions and entitlement enforcement.

Every plan-gated decision in Zentra routes through this module. Nothing else
should ever compare against a plan name directly, and the frontend's view of
the plan is never trusted — the API re-derives entitlements from the
subscription row on each request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from zentra.errors import EntitlementError

if TYPE_CHECKING:  # pragma: no cover
    from zentra.db.models import Organization, Subscription

UNLIMITED = -1


class Plan(StrEnum):
    FREE = "free"
    STARTER = "starter"
    GROWTH = "growth"
    SCALE = "scale"


class Feature(StrEnum):
    CONTINUOUS_MONITORING = "continuous_monitoring"
    ALERTS = "alerts"
    PDF_REPORTS = "pdf_reports"
    WHITE_LABEL_REPORTS = "white_label_reports"
    PUBLIC_API = "public_api"
    MULTI_USER = "multi_user"
    INTEGRATIONS = "integrations"
    BENCHMARKING = "benchmarking"
    REMEDIATION_TRACKING = "remediation_tracking"


@dataclass(frozen=True)
class PlanDefinition:
    plan: Plan
    display_name: str
    price_pence: int
    currency: str
    vendor_limit: int
    member_limit: int
    api_rate_per_minute: int
    scan_interval_hours: int
    features: frozenset[Feature] = field(default_factory=frozenset)
    description: str = ""

    @property
    def is_unlimited_vendors(self) -> bool:
        return self.vendor_limit == UNLIMITED


PLANS: dict[Plan, PlanDefinition] = {
    Plan.FREE: PlanDefinition(
        plan=Plan.FREE,
        display_name="Free",
        price_pence=0,
        currency="GBP",
        vendor_limit=3,
        member_limit=1,
        api_rate_per_minute=0,
        scan_interval_hours=168,
        features=frozenset({Feature.REMEDIATION_TRACKING}),
        description="Evaluate Zentra with up to 3 vendors and weekly rescans.",
    ),
    Plan.STARTER: PlanDefinition(
        plan=Plan.STARTER,
        display_name="Starter",
        price_pence=2900,
        currency="GBP",
        vendor_limit=10,
        member_limit=2,
        api_rate_per_minute=0,
        scan_interval_hours=24,
        features=frozenset({Feature.REMEDIATION_TRACKING}),
        description="10 vendors, daily risk scores and a monthly summary email.",
    ),
    Plan.GROWTH: PlanDefinition(
        plan=Plan.GROWTH,
        display_name="Growth",
        price_pence=7900,
        currency="GBP",
        vendor_limit=50,
        member_limit=10,
        api_rate_per_minute=60,
        scan_interval_hours=24,
        features=frozenset(
            {
                Feature.CONTINUOUS_MONITORING,
                Feature.ALERTS,
                Feature.PDF_REPORTS,
                Feature.MULTI_USER,
                Feature.INTEGRATIONS,
                Feature.BENCHMARKING,
                Feature.REMEDIATION_TRACKING,
            }
        ),
        description="50 vendors, continuous monitoring, alerts and PDF risk registers.",
    ),
    Plan.SCALE: PlanDefinition(
        plan=Plan.SCALE,
        display_name="Scale",
        price_pence=24900,
        currency="GBP",
        vendor_limit=UNLIMITED,
        member_limit=UNLIMITED,
        api_rate_per_minute=300,
        scan_interval_hours=12,
        features=frozenset(
            {
                Feature.CONTINUOUS_MONITORING,
                Feature.ALERTS,
                Feature.PDF_REPORTS,
                Feature.WHITE_LABEL_REPORTS,
                Feature.PUBLIC_API,
                Feature.MULTI_USER,
                Feature.INTEGRATIONS,
                Feature.BENCHMARKING,
                Feature.REMEDIATION_TRACKING,
            }
        ),
        description="Unlimited vendors, API access, white-label reports and multi-user access.",
    ),
}

# Subscription statuses that still grant paid entitlements. `past_due` keeps
# access during Stripe's dunning window; anything else drops to Free.
ACTIVE_STATUSES = frozenset({"active", "trialing", "past_due"})


@dataclass(frozen=True)
class Entitlements:
    plan: Plan
    definition: PlanDefinition
    status: str
    vendor_limit: int
    vendors_used: int
    report_pack_credits: int = 0

    @property
    def vendors_remaining(self) -> int:
        if self.vendor_limit == UNLIMITED:
            return UNLIMITED
        return max(self.vendor_limit - self.vendors_used, 0)

    @property
    def at_vendor_limit(self) -> bool:
        return self.vendor_limit != UNLIMITED and self.vendors_used >= self.vendor_limit

    def has(self, feature: Feature) -> bool:
        if feature is Feature.PDF_REPORTS and self.report_pack_credits > 0:
            return True
        return feature in self.definition.features

    def require(self, feature: Feature) -> None:
        if not self.has(feature):
            raise EntitlementError(
                f"{self.definition.display_name} does not include "
                f"{feature.value.replace('_', ' ')}. Upgrade your plan to enable it.",
                details={
                    "feature": feature.value,
                    "current_plan": self.plan.value,
                    "required_plans": [p.value for p, d in PLANS.items() if feature in d.features],
                },
            )

    def require_vendor_capacity(self, additional: int = 1) -> None:
        if self.vendor_limit == UNLIMITED:
            return
        if self.vendors_used + additional > self.vendor_limit:
            raise EntitlementError(
                f"Your {self.definition.display_name} plan includes "
                f"{self.vendor_limit} vendors and you are using {self.vendors_used}. "
                "Upgrade to add more.",
                code="VENDOR_LIMIT_REACHED",
                details={
                    "vendor_limit": self.vendor_limit,
                    "vendors_used": self.vendors_used,
                    "current_plan": self.plan.value,
                },
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "plan": self.plan.value,
            "plan_name": self.definition.display_name,
            "status": self.status,
            "vendor_limit": self.vendor_limit,
            "vendors_used": self.vendors_used,
            "vendors_remaining": self.vendors_remaining,
            "unlimited_vendors": self.vendor_limit == UNLIMITED,
            "member_limit": self.definition.member_limit,
            "scan_interval_hours": self.definition.scan_interval_hours,
            "report_pack_credits": self.report_pack_credits,
            "features": sorted(f.value for f in Feature if self.has(f)),
        }


def effective_plan(subscription: Subscription | None) -> Plan:
    """The plan a subscription actually grants right now."""
    if subscription is None:
        return Plan.FREE
    if subscription.status not in ACTIVE_STATUSES:
        return Plan.FREE
    try:
        return Plan(subscription.plan)
    except ValueError:
        return Plan.FREE


def build_entitlements(
    organization: Organization,
    subscription: Subscription | None,
    vendors_used: int,
) -> Entitlements:
    plan = effective_plan(subscription)
    definition = PLANS[plan]
    # An organization row may carry a manually granted higher limit (used for
    # bespoke MSSP deals); never lower than the plan's own limit.
    limit = definition.vendor_limit
    if limit != UNLIMITED and organization.vendor_limit > limit:
        limit = organization.vendor_limit
    return Entitlements(
        plan=plan,
        definition=definition,
        status=subscription.status if subscription else "none",
        vendor_limit=limit,
        vendors_used=vendors_used,
        report_pack_credits=subscription.report_pack_credits if subscription else 0,
    )


def plan_for_price_id(price_id: str) -> Plan | None:
    """Map a Stripe price ID back to a plan using configured environment values."""
    from zentra.config import get_settings

    settings = get_settings()
    mapping = {
        settings.stripe_starter_price_id: Plan.STARTER,
        settings.stripe_growth_price_id: Plan.GROWTH,
        settings.stripe_scale_price_id: Plan.SCALE,
    }
    mapping.pop("", None)
    return mapping.get(price_id)


def price_id_for_plan(plan: Plan) -> str:
    from zentra.config import get_settings

    settings = get_settings()
    mapping = {
        Plan.STARTER: settings.stripe_starter_price_id,
        Plan.GROWTH: settings.stripe_growth_price_id,
        Plan.SCALE: settings.stripe_scale_price_id,
    }
    return mapping.get(plan, "")
