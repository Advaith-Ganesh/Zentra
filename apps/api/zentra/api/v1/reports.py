"""Report generation and download endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request, Response, status

from zentra.api.middleware import client_identifier
from zentra.api.schemas import ReportCreateRequest, ReportResponse
from zentra.auth.deps import CurrentPrincipal, DbSession, Principal, require_role
from zentra.config import get_settings
from zentra.core import audit
from zentra.core.audit import AuditAction
from zentra.core.entitlements import Feature
from zentra.core.ratelimit import check_rate_limit
from zentra.errors import NotFoundError, RateLimitedError
from zentra.services import reports as reports_service
from zentra.services.organizations import entitlements_for

router = APIRouter(prefix="/reports", tags=["Reports"])


def _response(
    report, download_url: str | None = None, file_size: int | None = None
) -> ReportResponse:
    return ReportResponse(
        id=report.id,
        kind=report.kind,
        title=report.title,
        status=report.status,
        summary=report.summary,
        error_message=report.error_message,
        created_at=report.created_at,
        completed_at=report.completed_at,
        download_url=download_url,
        file_size=file_size,
    )


@router.get("", response_model=list[ReportResponse], summary="List reports")
async def list_reports(principal: CurrentPrincipal, session: DbSession) -> list[ReportResponse]:
    principal.require_scope("reports:read")
    out = []
    for report in reports_service.list_reports(session, principal.organization.id):
        export = reports_service.latest_export(session, report)
        out.append(
            _response(
                report,
                f"/api/v1/reports/{report.id}/download" if export else None,
                export.file_size if export else None,
            )
        )
    return out


@router.post(
    "",
    response_model=ReportResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Generate a vendor risk register PDF",
    description=(
        "Queues generation and returns immediately. Poll the report until its status is "
        "`completed`, then download it. Requires the Growth plan or a report pack."
    ),
    responses={
        402: {"description": "PDF reports are not included in the current plan."},
        429: {"description": "Report generation rate limit reached."},
    },
)
async def create_report(
    payload: ReportCreateRequest,
    request: Request,
    principal: Annotated[Principal, Depends(require_role("analyst"))],
    session: DbSession,
) -> ReportResponse:
    settings = get_settings()
    entitlements = entitlements_for(session, principal.organization)
    entitlements.require(Feature.PDF_REPORTS)

    limit, window = settings.rate("report")
    result = check_rate_limit("report", client_identifier(request), limit, window)
    if not result.allowed:
        raise RateLimitedError(
            "Too many reports requested. Please wait before generating another.",
            retry_after=result.retry_after,
        )

    report = reports_service.create_report(
        session,
        organization=principal.organization,
        actor=principal.user if principal.kind == "user" else None,
        kind=payload.kind,
        title=payload.title,
        vendor_ids=payload.vendor_ids,
        include_resolved_findings=payload.include_resolved_findings,
        idempotency_key=payload.idempotency_key,
    )
    session.commit()

    from zentra.workers.dispatch import dispatch_report

    dispatch_report(report.id)
    session.refresh(report)
    return _response(report)


@router.get("/{report_id}", response_model=ReportResponse, summary="Get a report's status")
async def get_report(
    report_id: Annotated[uuid.UUID, Path()],
    principal: CurrentPrincipal,
    session: DbSession,
) -> ReportResponse:
    principal.require_scope("reports:read")
    report = reports_service.get_report(session, principal.organization.id, report_id)
    export = reports_service.latest_export(session, report)
    return _response(
        report,
        f"/api/v1/reports/{report.id}/download" if export else None,
        export.file_size if export else None,
    )


@router.get(
    "/{report_id}/download",
    summary="Download a generated report PDF",
    response_class=Response,
    responses={
        200: {"content": {"application/pdf": {}}, "description": "The report PDF."},
        404: {"description": "Report not found, or not generated yet."},
    },
)
async def download_report(
    report_id: Annotated[uuid.UUID, Path()],
    principal: CurrentPrincipal,
    session: DbSession,
) -> Response:
    principal.require_scope("reports:read")
    report = reports_service.get_report(session, principal.organization.id, report_id)
    export = reports_service.latest_export(session, report)
    if report.status != "completed" or export is None:
        raise NotFoundError("This report has not finished generating yet.", code="REPORT_NOT_READY")
    content = reports_service.read_export(session, export=export)
    audit.record(
        session,
        action=AuditAction.REPORT_DOWNLOADED,
        organization_id=principal.organization.id,
        actor_user_id=principal.user.id if principal.kind == "user" else None,
        actor_api_key_id=principal.api_key.id if principal.api_key else None,
        actor_type=principal.kind,
        resource_type="report",
        resource_id=report.id,
    )
    safe_name = f"zentra-vendor-risk-register-{report.created_at.date().isoformat()}.pdf"
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "Content-Length": str(len(content)),
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
        },
    )
