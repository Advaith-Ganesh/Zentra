"""Unauthenticated public endpoints: the free scan.

Everything here is reachable without an account, so it is the most hostile
surface in the product. Controls applied:

* aggressive rate limiting, per requester and per target domain;
* strict domain validation and the full SSRF guard before any network activity;
* a reduced check set (no exposure or CVE lookup, which cost provider quota);
* a redacted response — no provider internals, no raw evidence, no
  infrastructure detail that would help an attacker.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, Request, status

from zentra.api.middleware import client_ip
from zentra.api.schemas import PublicScanFinding, PublicScanRequest, PublicScanResponse
from zentra.auth.deps import DbSession
from zentra.config import get_settings
from zentra.core.domains import normalize_domain
from zentra.core.ratelimit import check_rate_limit
from zentra.core.security import pseudonymize
from zentra.db.models import PublicScan
from zentra.errors import RateLimitedError, UnsafeTargetError
from zentra.logging import get_logger
from zentra.scanners.orchestration import run_scan
from zentra.scoring.verdict import STANDARD_DISCLAIMER

log = get_logger("zentra.api.public")

router = APIRouter(prefix="/public", tags=["Public"])

#: Findings shown to anonymous users, at most.
PUBLIC_FINDING_LIMIT = 3


@router.post(
    "/scan",
    response_model=PublicScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Run a free, limited vendor scan",
    description=(
        "No account required. Runs a reduced set of passive checks against a public domain "
        "and returns a risk score with a plain-English explanation. Heavily rate limited."
    ),
    responses={
        400: {"description": "The domain resolves to a network Zentra will not contact."},
        422: {"description": "The domain is not a valid public domain name."},
        429: {"description": "Free scan rate limit reached."},
    },
)
async def public_scan(
    payload: PublicScanRequest, request: Request, session: DbSession
) -> PublicScanResponse:
    settings = get_settings()
    limit, window = settings.rate("public_scan")
    requester = pseudonymize(client_ip(request))

    result = check_rate_limit("public_scan", requester, limit, window)
    if not result.allowed:
        log.info("public_scan_rate_limited")
        raise RateLimitedError(
            "You have used your free scans for now. Create an account to keep monitoring "
            "vendors continuously.",
            retry_after=result.retry_after,
        )
    # A second bucket per target domain stops one domain being hammered from
    # many source addresses.
    domain = normalize_domain(payload.domain)
    domain_result = check_rate_limit("public_scan_domain", domain, 10, window)
    if not domain_result.allowed:
        raise RateLimitedError(
            "This domain has been scanned several times recently. Please try again later.",
            retry_after=domain_result.retry_after,
        )

    try:
        outcome = await asyncio.wait_for(run_scan(domain, limited=True), timeout=90)
    except TimeoutError as exc:
        raise UnsafeTargetError(
            "The scan could not be completed in time. Please try again.",
            code="SCAN_TIMEOUT",
            status_code=504,
        ) from exc

    score = outcome.score
    verdict = outcome.verdict

    findings = [
        PublicScanFinding(
            title=str(item.get("title") or item.get("summary") or "")[:200],
            summary=str(item.get("summary") or "")[:400],
            severity=str(item.get("severity") or "info"),
            recommendation=str(item.get("recommendation") or "")[:300] or None,
        )
        for item in score.top_findings[:PUBLIC_FINDING_LIMIT]
    ]
    # Categories are surfaced without per-check detail, evidence or provider
    # names — enough to show value, not enough to be an attacker's recon tool.
    categories = [
        {
            "display_name": category.display_name,
            "assessed": category.assessed,
            "status": category.status,
            "points": category.to_dict()["points"],
            "max_points": category.max_points,
        }
        for category in score.categories
    ]

    session.add(
        PublicScan(
            domain=domain,
            requester_hash=requester,
            score=score.score if score.is_scorable else None,
            risk_level=score.risk_level.value if score.risk_level else None,
            result={
                "coverage": float(score.coverage),
                "confidence": float(score.confidence),
                "headline": verdict.headline,
                "finding_count": len(score.top_findings),
            },
        )
    )

    log.info(
        "public_scan_completed",
        domain=domain,
        score=score.score if score.is_scorable else None,
        risk_level=score.risk_level.value if score.risk_level else None,
    )

    return PublicScanResponse(
        domain=domain,
        score=score.score if score.is_scorable else None,
        risk_level=score.risk_level.value if score.risk_level else None,
        confidence=float(score.confidence),
        coverage=float(score.coverage),
        headline=verdict.headline,
        explanation=verdict.explanation,
        recommended_action=verdict.recommended_action,
        top_findings=findings,
        categories=categories,
        disclaimer=STANDARD_DISCLAIMER,
        scanned_at=datetime.now(UTC),
    )
