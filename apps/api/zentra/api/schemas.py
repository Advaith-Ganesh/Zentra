"""Pydantic request/response models for the public API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from zentra.core.domains import normalize_domain
from zentra.errors import InvalidDomainError


class ZentraModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


# ------------------------------------------------------------------ auth
class SignUpRequest(ZentraModel):
    email: EmailStr = Field(description="Work email address.")
    password: str = Field(min_length=12, max_length=256, description="At least 12 characters.")
    full_name: str | None = Field(default=None, max_length=200)
    organization_name: str = Field(min_length=1, max_length=200)
    industry: str | None = Field(default=None, max_length=100)
    company_size: str | None = Field(default=None, max_length=50)


class SignInRequest(ZentraModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class PasswordResetRequest(ZentraModel):
    email: EmailStr


class AuthResponse(ZentraModel):
    access_token: str
    refresh_token: str | None = None
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - a scheme name, not a secret
    expires_in: int
    email_verification_required: bool = False
    user: UserResponse
    organization: OrganizationResponse | None = None


class UserResponse(ZentraModel):
    id: uuid.UUID
    email: str
    full_name: str | None = None
    is_platform_admin: bool = False
    email_verified: bool = False
    created_at: datetime


class MembershipResponse(ZentraModel):
    id: uuid.UUID
    user_id: uuid.UUID
    email: str
    full_name: str | None = None
    role: str
    status: str
    created_at: datetime


class OrganizationResponse(ZentraModel):
    id: uuid.UUID
    name: str
    slug: str
    org_type: str
    industry: str | None = None
    company_size: str | None = None
    country: str | None = None
    plan: str
    branding: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class OrganizationUpdateRequest(ZentraModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    industry: str | None = Field(default=None, max_length=100)
    company_size: str | None = Field(default=None, max_length=50)
    country: str | None = Field(default=None, max_length=2)
    benchmark_opt_in: bool | None = None
    alert_score_delta: int | None = Field(default=None, ge=1, le=100)


class MeResponse(ZentraModel):
    user: UserResponse
    organization: OrganizationResponse
    role: str
    entitlements: dict[str, Any]
    feature_flags: dict[str, bool]
    organizations: list[OrganizationSummary] = Field(default_factory=list)


class OrganizationSummary(ZentraModel):
    id: uuid.UUID
    name: str
    slug: str
    role: str


class InviteRequest(ZentraModel):
    email: EmailStr
    role: Literal["admin", "analyst", "viewer"] = "viewer"


class AcceptInviteRequest(ZentraModel):
    token: str = Field(min_length=10, max_length=200)


# ------------------------------------------------------------------ vendors
class VendorCreateRequest(ZentraModel):
    name: str = Field(min_length=1, max_length=200)
    domain: str = Field(min_length=3, max_length=253, examples=["stripe.com"])
    description: str | None = Field(default=None, max_length=2000)
    category: str | None = Field(default=None, max_length=100)
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    owner_label: str | None = Field(default=None, max_length=200)
    scan_interval_hours: int | None = Field(default=None, ge=1, le=720)

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        try:
            return normalize_domain(value)
        except InvalidDomainError as exc:
            raise ValueError(exc.message) from exc


class VendorUpdateRequest(ZentraModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    category: str | None = Field(default=None, max_length=100)
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    owner_label: str | None = Field(default=None, max_length=200)
    status: Literal["active", "paused", "archived"] | None = None
    scan_interval_hours: int | None = Field(default=None, ge=1, le=720)


class VendorResponse(ZentraModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    domain: str
    description: str | None = None
    category: str | None = None
    criticality: str
    owner_label: str | None = None
    status: str
    current_score: int | None = None
    current_risk_level: str | None = None
    previous_score: int | None = None
    current_confidence: float | None = None
    score_trend: int | None = None
    last_scanned_at: datetime | None = None
    next_scan_at: datetime | None = None
    scan_interval_hours: int
    is_demo: bool = False
    created_at: datetime
    updated_at: datetime


class VendorListResponse(ZentraModel):
    items: list[VendorResponse]
    total: int
    limit: int
    offset: int


class VendorScoreResponse(ZentraModel):
    vendor_id: uuid.UUID
    score: int | None
    risk_level: str | None
    confidence: float | None
    coverage: float | None
    previous_score: int | None = None
    trend: int | None = None
    last_scanned_at: datetime | None = None
    breakdown: dict[str, Any] | None = None
    verdict: dict[str, Any] | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)


# ------------------------------------------------------------------ scans
class ScanResponse(ZentraModel):
    id: uuid.UUID
    vendor_id: uuid.UUID
    trigger: str
    status: str
    score: int | None = None
    risk_level: str | None = None
    confidence: float | None = None
    coverage: float | None = None
    checks_total: int
    checks_succeeded: int
    error_code: str | None = None
    error_message: str | None = None
    queued_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class ScanDetailResponse(ScanResponse):
    score_breakdown: dict[str, Any] | None = None
    verdict: dict[str, Any] | None = None
    results: list[ScanResultResponse] = Field(default_factory=list)


class ScanResultResponse(ZentraModel):
    id: uuid.UUID
    check_type: str
    status: str
    severity: str
    summary: str
    details: dict[str, Any]
    evidence: list[Any]
    source: str
    confidence: float
    provider_status: str | None = None
    checked_at: datetime


class TriggerScanRequest(ZentraModel):
    idempotency_key: str | None = Field(default=None, max_length=128)


# ------------------------------------------------------------------ findings
class FindingResponse(ZentraModel):
    id: uuid.UUID
    vendor_id: uuid.UUID
    check_type: str
    severity: str
    title: str
    description: str
    recommendation: str
    evidence: list[Any]
    source: str
    confidence: float
    status: str
    assigned_to: uuid.UUID | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None = None


class FindingUpdateRequest(ZentraModel):
    status: Literal["open", "in_progress", "resolved", "accepted_risk"] | None = None
    note: str | None = Field(default=None, max_length=2000)
    assigned_to: uuid.UUID | None = None
    unassign: bool = False


class FindingHistoryResponse(ZentraModel):
    id: uuid.UUID
    from_status: str | None
    to_status: str
    note: str | None
    actor_user_id: uuid.UUID | None
    created_at: datetime


# ------------------------------------------------------------------ reports
class ReportCreateRequest(ZentraModel):
    kind: Literal["vendor_risk_register", "single_vendor", "executive_summary"] = (
        "vendor_risk_register"
    )
    title: str | None = Field(default=None, max_length=200)
    vendor_ids: list[uuid.UUID] | None = Field(default=None, max_length=500)
    include_resolved_findings: bool = False
    idempotency_key: str | None = Field(default=None, max_length=128)


class ReportResponse(ZentraModel):
    id: uuid.UUID
    kind: str
    title: str
    status: str
    summary: dict[str, Any] | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None
    download_url: str | None = None
    file_size: int | None = None


# ------------------------------------------------------------------ billing
class BillingResponse(ZentraModel):
    plan: str
    status: str
    entitlements: dict[str, Any]
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False
    stripe_configured: bool
    available_plans: list[dict[str, Any]]


class CheckoutRequest(ZentraModel):
    plan: Literal["starter", "growth", "scale"] | None = None
    product: Literal["subscription", "report_pack"] = "subscription"
    success_url: str | None = Field(default=None, max_length=500)
    cancel_url: str | None = Field(default=None, max_length=500)


class CheckoutResponse(ZentraModel):
    checkout_url: str
    session_id: str


class PortalResponse(ZentraModel):
    portal_url: str


# ------------------------------------------------------------------ api keys
class ApiKeyCreateRequest(ZentraModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] | None = Field(default=None, max_length=10)
    expires_in_days: int | None = Field(default=None, ge=1, le=730)


class ApiKeyResponse(ZentraModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: list[str]
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime


class ApiKeyCreatedResponse(ZentraModel):
    api_key: ApiKeyResponse
    #: Returned exactly once. Zentra stores only a hash and cannot show it again.
    secret: str


# ------------------------------------------------------------------ alerts
class AlertResponse(ZentraModel):
    id: uuid.UUID
    vendor_id: uuid.UUID | None
    scan_id: uuid.UUID | None
    kind: str
    severity: str
    title: str
    message: str
    old_score: int | None = None
    new_score: int | None = None
    score_delta: int | None = None
    notification_status: str
    acknowledged_at: datetime | None = None
    created_at: datetime


# ------------------------------------------------------------------ dashboard
class DashboardResponse(ZentraModel):
    summary: dict[str, Any]
    vendors_needing_attention: list[VendorResponse]
    recent_alerts: list[AlertResponse]
    recent_scans: list[ScanResponse]
    entitlements: dict[str, Any]


# ------------------------------------------------------------------ public scan
class PublicScanRequest(ZentraModel):
    domain: str = Field(min_length=3, max_length=253, examples=["example.com"])

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        try:
            return normalize_domain(value)
        except InvalidDomainError as exc:
            raise ValueError(exc.message) from exc


class PublicScanFinding(ZentraModel):
    title: str
    summary: str
    severity: str
    recommendation: str | None = None


class PublicScanResponse(ZentraModel):
    domain: str
    score: int | None
    risk_level: str | None
    confidence: float
    coverage: float
    headline: str
    explanation: str
    recommended_action: str
    top_findings: list[PublicScanFinding]
    categories: list[dict[str, Any]]
    disclaimer: str
    scanned_at: datetime


# ------------------------------------------------------------------ integrations
class TeamsConnectRequest(ZentraModel):
    webhook_url: str = Field(min_length=10, max_length=2000)
    label: str | None = Field(default=None, max_length=100)


class IntegrationResponse(ZentraModel):
    id: uuid.UUID
    provider: str
    display_name: str | None
    status: str
    created_at: datetime


# ------------------------------------------------------------------ benchmark
class BenchmarkResponse(ZentraModel):
    available: bool
    cohort_label: str | None = None
    sample_size: int = 0
    your_average_score: float | None = None
    cohort_median: float | None = None
    cohort_p25: float | None = None
    cohort_p75: float | None = None
    message: str


class HealthResponse(ZentraModel):
    status: str
    version: str
    environment: str


class ReadinessResponse(ZentraModel):
    status: str
    checks: dict[str, str]


MeResponse.model_rebuild()
AuthResponse.model_rebuild()
