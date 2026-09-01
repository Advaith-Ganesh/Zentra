"""The API-key authenticated public API (Scale plan).

These endpoints mirror the dashboard API but are documented and versioned as a
stable integration surface. Authentication is by API key only.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Path, Query, Request, status

from zentra.api.middleware import client_identifier
from zentra.api.schemas import (
    ReportResponse,
    ScanResponse,
    VendorCreateRequest,
    VendorListResponse,
    VendorResponse,
)
from zentra.api.v1.vendors import _vendor_response
from zentra.auth.deps import CurrentPrincipal, DbSession
from zentra.config import get_settings
from zentra.core.entitlements import Feature
from zentra.core.feature_flags import Flag
from zentra.core.feature_flags import require as require_flag
from zentra.core.ratelimit import check_rate_limit
from zentra.errors import NotFoundError, PermissionDeniedError, RateLimitedError
from zentra.services import reports as reports_service
from zentra.services import scans as scans_service
from zentra.services import vendors as vendors_service
from zentra.services.organizations import entitlements_for

router = APIRouter(prefix="/public", tags=["Public API (API key)"])


def _require_api_access(principal, session) -> None:
    require_flag(Flag.PUBLIC_API)
    if principal.kind != "api_key":
        raise PermissionDeniedError(
            "These endpoints require an API key. Send it in the X-API-Key header.",
            code="API_KEY_REQUIRED",
        )
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.PUBLIC_API)


def _enforce_plan_rate_limit(request: Request, principal, session) -> None:
    entitlements = entitlements_for(session, principal.organization)
    per_minute = entitlements.definition.api_rate_per_minute or get_settings().rate("api")[0]
    result = check_rate_limit("public_api", client_identifier(request), per_minute, 60)
    if not result.allowed:
        raise RateLimitedError(
            f"Your plan allows {per_minute} API requests per minute.",
            retry_after=result.retry_after,
        )


@router.get(
    "/vendors",
    response_model=VendorListResponse,
    summary="List vendors",
    description="Requires an API key with the `vendors:read` scope.",
)
async def api_list_vendors(
    request: Request,
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> VendorListResponse:
    _require_api_access(principal, session)
    _enforce_plan_rate_limit(request, principal, session)
    principal.require_scope("vendors:read")
    items, total = vendors_service.list_vendors(
        session, principal.organization.id, limit=limit, offset=offset
    )
    return VendorListResponse(
        items=[_vendor_response(v) for v in items], total=total, limit=limit, offset=offset
    )


@router.post(
    "/vendors",
    response_model=VendorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a vendor and queue its first scan",
    description="Requires an API key with the `vendors:write` scope.",
)
async def api_create_vendor(
    payload: VendorCreateRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: DbSession,
) -> VendorResponse:
    _require_api_access(principal, session)
    _enforce_plan_rate_limit(request, principal, session)
    principal.require_scope("vendors:write")
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require_vendor_capacity(1)
    vendor = vendors_service.create_vendor(
        session,
        organization=principal.organization,
        name=payload.name,
        domain=payload.domain,
        description=payload.description,
        category=payload.category,
        criticality=payload.criticality,
    )
    scan = scans_service.queue_scan(session, vendor=vendor, trigger="api")
    session.commit()
    from zentra.workers.dispatch import dispatch_scan

    dispatch_scan(scan.id)
    session.refresh(vendor)
    return _vendor_response(vendor)


@router.post(
    "/vendors/{vendor_id}/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a scan",
    description="Requires an API key with the `scans:write` scope.",
)
async def api_trigger_scan(
    vendor_id: Annotated[uuid.UUID, Path()],
    request: Request,
    principal: CurrentPrincipal,
    session: DbSession,
) -> ScanResponse:
    _require_api_access(principal, session)
    _enforce_plan_rate_limit(request, principal, session)
    principal.require_scope("scans:write")
    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)
    scan = scans_service.queue_scan(session, vendor=vendor, trigger="api")
    session.commit()
    from zentra.workers.dispatch import dispatch_scan

    dispatch_scan(scan.id)
    session.refresh(scan)
    return ScanResponse.model_validate(scan)


@router.get(
    "/vendors/{vendor_id}/report",
    response_model=ReportResponse,
    summary="Generate a single-vendor risk report",
    description="Requires an API key with the `reports:read` scope.",
)
async def api_vendor_report(
    vendor_id: Annotated[uuid.UUID, Path()],
    request: Request,
    principal: CurrentPrincipal,
    session: DbSession,
) -> ReportResponse:
    _require_api_access(principal, session)
    _enforce_plan_rate_limit(request, principal, session)
    principal.require_scope("reports:read")
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.PDF_REPORTS)
    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)

    report = reports_service.create_report(
        session,
        organization=principal.organization,
        actor=None,
        kind="single_vendor",
        title=f"Vendor Risk Report — {vendor.name}",
        vendor_ids=[vendor.id],
    )
    session.commit()
    from zentra.workers.dispatch import dispatch_report

    dispatch_report(report.id)
    session.refresh(report)
    export = reports_service.latest_export(session, report)
    if report.status == "failed":
        raise NotFoundError("The report could not be generated.", code="REPORT_FAILED")
    return ReportResponse(
        id=report.id,
        kind=report.kind,
        title=report.title,
        status=report.status,
        summary=report.summary,
        created_at=report.created_at,
        completed_at=report.completed_at,
        download_url=f"/api/v1/reports/{report.id}/download" if export else None,
        file_size=export.file_size if export else None,
    )
