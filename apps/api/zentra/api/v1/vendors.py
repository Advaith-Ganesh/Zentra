"""Vendor, scan and finding endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query, Request, status

from zentra.api.middleware import client_identifier
from zentra.api.schemas import (
    FindingHistoryResponse,
    FindingResponse,
    FindingUpdateRequest,
    ScanDetailResponse,
    ScanResponse,
    ScanResultResponse,
    TriggerScanRequest,
    VendorCreateRequest,
    VendorListResponse,
    VendorResponse,
    VendorScoreResponse,
    VendorUpdateRequest,
)
from zentra.auth.deps import CurrentPrincipal, DbSession, Principal, require_role
from zentra.config import get_settings
from zentra.core.entitlements import Feature
from zentra.core.ratelimit import check_rate_limit
from zentra.errors import RateLimitedError
from zentra.logging import get_logger
from zentra.services import findings as findings_service
from zentra.services import scans as scans_service
from zentra.services import vendors as vendors_service
from zentra.services.organizations import entitlements_for

log = get_logger("zentra.api.vendors")

router = APIRouter(prefix="/vendors", tags=["Vendors"])

VendorId = Annotated[uuid.UUID, Path(description="Vendor identifier.")]


def _vendor_response(vendor: Any) -> VendorResponse:
    trend = None
    if vendor.current_score is not None and vendor.previous_score is not None:
        trend = vendor.current_score - vendor.previous_score
    return VendorResponse(
        id=vendor.id,
        organization_id=vendor.organization_id,
        name=vendor.name,
        domain=vendor.domain,
        description=vendor.description,
        category=vendor.category,
        criticality=vendor.criticality,
        owner_label=vendor.owner_label,
        status=vendor.status,
        current_score=vendor.current_score,
        current_risk_level=vendor.current_risk_level,
        previous_score=vendor.previous_score,
        current_confidence=float(vendor.current_confidence)
        if vendor.current_confidence is not None
        else None,
        score_trend=trend,
        last_scanned_at=vendor.last_scanned_at,
        next_scan_at=vendor.next_scan_at,
        scan_interval_hours=vendor.scan_interval_hours,
        is_demo=vendor.is_demo,
        created_at=vendor.created_at,
        updated_at=vendor.updated_at,
    )


@router.get(
    "",
    response_model=VendorListResponse,
    summary="List vendors",
    description="Returns vendors in the caller's organization, with search, filter and sort.",
)
async def list_vendors(
    principal: CurrentPrincipal,
    session: DbSession,
    search: Annotated[str | None, Query(max_length=100)] = None,
    status_filter: Annotated[
        str, Query(alias="status", pattern="^(active|paused|archived|all)$")
    ] = "active",
    risk_level: Annotated[list[str] | None, Query()] = None,
    criticality: Annotated[list[str] | None, Query()] = None,
    sort: Annotated[
        str, Query(pattern="^(name|current_score|last_scanned_at|created_at|criticality)$")
    ] = "current_score",
    direction: Annotated[str, Query(pattern="^(asc|desc)$")] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> VendorListResponse:
    principal.require_scope("vendors:read")
    allowed_levels = {"low", "medium", "high", "critical"}
    items, total = vendors_service.list_vendors(
        session,
        principal.organization.id,
        search=search,
        status=status_filter,
        risk_levels=[r for r in (risk_level or []) if r in allowed_levels] or None,
        criticality=[c for c in (criticality or []) if c in allowed_levels] or None,
        sort=sort,  # type: ignore[arg-type]
        direction=direction,  # type: ignore[arg-type]
        limit=limit,
        offset=offset,
    )
    return VendorListResponse(
        items=[_vendor_response(v) for v in items], total=total, limit=limit, offset=offset
    )


@router.post(
    "",
    response_model=VendorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a vendor",
    description=(
        "Creates a vendor and queues its initial scan. Enforces the "
        "organization's plan vendor limit."
    ),
    responses={
        402: {"description": "Plan vendor limit reached."},
        409: {"description": "This domain is already tracked in your organization."},
        422: {"description": "The domain is not a valid public domain name."},
    },
)
async def create_vendor(
    payload: VendorCreateRequest,
    principal: Annotated[Principal, Depends(require_role("analyst"))],
    session: DbSession,
) -> VendorResponse:
    principal.require_scope("vendors:write")
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require_vendor_capacity(1)

    vendor = vendors_service.create_vendor(
        session,
        organization=principal.organization,
        name=payload.name,
        domain=payload.domain,
        actor=principal.user if principal.kind == "user" else None,
        description=payload.description,
        category=payload.category,
        criticality=payload.criticality,
        owner_label=payload.owner_label,
        scan_interval_hours=payload.scan_interval_hours
        or entitlements.definition.scan_interval_hours,
    )
    scan = scans_service.queue_scan(
        session,
        vendor=vendor,
        trigger="initial",
        actor=principal.user if principal.kind == "user" else None,
    )
    session.commit()
    _dispatch(scan.id)
    session.refresh(vendor)
    return _vendor_response(vendor)


@router.get("/{vendor_id}", response_model=VendorResponse, summary="Get a vendor")
async def get_vendor(
    vendor_id: VendorId, principal: CurrentPrincipal, session: DbSession
) -> VendorResponse:
    principal.require_scope("vendors:read")
    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)
    return _vendor_response(vendor)


@router.patch("/{vendor_id}", response_model=VendorResponse, summary="Update a vendor")
async def update_vendor(
    vendor_id: VendorId,
    payload: VendorUpdateRequest,
    principal: Annotated[Principal, Depends(require_role("analyst"))],
    session: DbSession,
) -> VendorResponse:
    principal.require_scope("vendors:write")
    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)
    vendors_service.update_vendor(
        session,
        vendor=vendor,
        actor=principal.user if principal.kind == "user" else None,
        **payload.model_dump(exclude_none=True),
    )
    return _vendor_response(vendor)


@router.post("/{vendor_id}/archive", response_model=VendorResponse, summary="Archive a vendor")
async def archive_vendor(
    vendor_id: VendorId,
    principal: Annotated[Principal, Depends(require_role("analyst"))],
    session: DbSession,
) -> VendorResponse:
    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)
    vendors_service.archive_vendor(
        session, vendor=vendor, actor=principal.user if principal.kind == "user" else None
    )
    return _vendor_response(vendor)


@router.delete(
    "/{vendor_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Delete a vendor",
)
async def delete_vendor(
    vendor_id: VendorId,
    principal: Annotated[Principal, Depends(require_role("admin"))],
    session: DbSession,
) -> None:
    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)
    vendors_service.delete_vendor(
        session, vendor=vendor, actor=principal.user if principal.kind == "user" else None
    )


@router.get(
    "/{vendor_id}/score",
    response_model=VendorScoreResponse,
    summary="Get a vendor's current score, breakdown and history",
    description=(
        "The score breakdown is computed server-side. Clients must render this "
        "payload rather than recomputing any part of the score."
    ),
)
async def vendor_score(
    vendor_id: VendorId, principal: CurrentPrincipal, session: DbSession
) -> VendorScoreResponse:
    principal.require_scope("vendors:read")
    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)
    latest = scans_service.latest_completed_scan(session, vendor.id)
    trend = None
    if vendor.current_score is not None and vendor.previous_score is not None:
        trend = vendor.current_score - vendor.previous_score
    return VendorScoreResponse(
        vendor_id=vendor.id,
        score=vendor.current_score,
        risk_level=vendor.current_risk_level,
        confidence=float(vendor.current_confidence) if vendor.current_confidence else None,
        coverage=float(latest.coverage) if latest and latest.coverage is not None else None,
        previous_score=vendor.previous_score,
        trend=trend,
        last_scanned_at=vendor.last_scanned_at,
        breakdown=latest.score_breakdown if latest else None,
        verdict=latest.verdict if latest else None,
        history=scans_service.score_history(session, vendor.id),
    )


@router.get(
    "/{vendor_id}/scans", response_model=list[ScanResponse], summary="List a vendor's scans"
)
async def list_vendor_scans(
    vendor_id: VendorId,
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ScanResponse]:
    principal.require_scope("vendors:read")
    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)
    scans = scans_service.list_scans(
        session, principal.organization.id, vendor_id=vendor.id, limit=limit, offset=offset
    )
    return [ScanResponse.model_validate(s) for s in scans]


@router.post(
    "/{vendor_id}/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a scan",
    description=(
        "Queues an asynchronous scan. Scans never run inside the request; poll "
        "the returned scan until its status is `completed`, `partial` or `failed`."
    ),
    responses={429: {"description": "Manual scan rate limit reached."}},
)
async def trigger_scan(
    vendor_id: VendorId,
    payload: TriggerScanRequest,
    request: Request,
    principal: Annotated[Principal, Depends(require_role("analyst"))],
    session: DbSession,
) -> ScanResponse:
    principal.require_scope("scans:write")
    settings = get_settings()
    limit, window = settings.rate("manual_scan")
    result = check_rate_limit("manual_scan", client_identifier(request), limit, window)
    if not result.allowed:
        raise RateLimitedError(
            "You have triggered too many manual scans. Scheduled scans continue as normal.",
            retry_after=result.retry_after,
        )

    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)
    scan = scans_service.queue_scan(
        session,
        vendor=vendor,
        trigger="api" if principal.kind == "api_key" else "manual",
        actor=principal.user if principal.kind == "user" else None,
        idempotency_key=payload.idempotency_key,
    )
    session.commit()
    _dispatch(scan.id)
    session.refresh(scan)
    return ScanResponse.model_validate(scan)


@router.get("/{vendor_id}/findings", response_model=list[FindingResponse], summary="List findings")
async def list_vendor_findings(
    vendor_id: VendorId,
    principal: CurrentPrincipal,
    session: DbSession,
    status_filter: Annotated[list[str] | None, Query(alias="status")] = None,
    severity: Annotated[list[str] | None, Query()] = None,
) -> list[FindingResponse]:
    principal.require_scope("vendors:read")
    vendor = vendors_service.get_vendor(session, principal.organization.id, vendor_id)
    valid_statuses = {"open", "in_progress", "resolved", "accepted_risk"}
    valid_severities = {"info", "low", "medium", "high", "critical"}
    items = findings_service.list_findings(
        session,
        principal.organization.id,
        vendor_id=vendor.id,
        statuses=[s for s in (status_filter or []) if s in valid_statuses] or None,
        severities=[s for s in (severity or []) if s in valid_severities] or None,
    )
    return [FindingResponse.model_validate(f) for f in items]


def _dispatch(scan_id: uuid.UUID) -> None:
    """Hand the scan to the worker.

    Falls back to running it inline only when Celery's broker is unreachable
    *and* we are not in production, so local development still works without a
    worker process.
    """
    from zentra.workers.dispatch import dispatch_scan

    dispatch_scan(scan_id)


# --------------------------------------------------------------------- scans
scans_router = APIRouter(prefix="/scans", tags=["Scans"])


@scans_router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get a scan with its normalized check results",
)
async def get_scan(
    scan_id: Annotated[uuid.UUID, Path()],
    principal: CurrentPrincipal,
    session: DbSession,
) -> ScanDetailResponse:
    principal.require_scope("vendors:read")
    scan = scans_service.get_scan(session, principal.organization.id, scan_id)
    results = scans_service.scan_results(session, scan)
    detail = ScanDetailResponse.model_validate(scan)
    detail.results = [
        ScanResultResponse(
            id=r.id,
            check_type=r.check_type,
            status=r.status,
            severity=r.severity,
            summary=r.summary,
            details=r.details,
            evidence=r.evidence,
            source=r.source,
            confidence=float(r.confidence),
            provider_status=r.provider_status,
            checked_at=r.checked_at,
        )
        for r in results
    ]
    return detail


# ------------------------------------------------------------------ findings
findings_router = APIRouter(prefix="/findings", tags=["Findings"])


@findings_router.get(
    "", response_model=list[FindingResponse], summary="List findings across all vendors"
)
async def list_all_findings(
    principal: CurrentPrincipal,
    session: DbSession,
    status_filter: Annotated[list[str] | None, Query(alias="status")] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[FindingResponse]:
    principal.require_scope("vendors:read")
    items = findings_service.list_findings(
        session,
        principal.organization.id,
        statuses=status_filter,
        severities=severity,
        limit=limit,
        offset=offset,
    )
    return [FindingResponse.model_validate(f) for f in items]


@findings_router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Update a finding's remediation status",
    description="Every change is recorded in the finding's immutable history.",
)
async def update_finding(
    finding_id: Annotated[uuid.UUID, Path()],
    payload: FindingUpdateRequest,
    principal: Annotated[Principal, Depends(require_role("analyst"))],
    session: DbSession,
) -> FindingResponse:
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.REMEDIATION_TRACKING)
    finding = findings_service.get_finding(session, principal.organization.id, finding_id)
    findings_service.update_finding(
        session,
        finding=finding,
        actor=principal.user,
        status=payload.status,
        note=payload.note,
        assigned_to=payload.assigned_to,
        unassign=payload.unassign,
    )
    return FindingResponse.model_validate(finding)


@findings_router.get(
    "/{finding_id}/history",
    response_model=list[FindingHistoryResponse],
    summary="Get a finding's status history",
)
async def finding_history(
    finding_id: Annotated[uuid.UUID, Path()],
    principal: CurrentPrincipal,
    session: DbSession,
) -> list[FindingHistoryResponse]:
    finding = findings_service.get_finding(session, principal.organization.id, finding_id)
    return [
        FindingHistoryResponse.model_validate(h)
        for h in findings_service.finding_history(session, finding)
    ]
