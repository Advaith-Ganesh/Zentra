"""Scan orchestration.

Runs every scanner for a domain, in parallel where they are independent, and
returns normalized results plus a score and a verdict. One scanner failing can
never fail the scan: :meth:`BaseScanner.execute` already converts any error
into a normalized ``ERROR`` result.

Two passes are needed because CVE lookup depends on technology signals
discovered in the first pass. Nothing else is sequential.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from zentra.config import get_settings
from zentra.core.domains import normalize_domain
from zentra.logging import get_logger
from zentra.scanners.base import CheckResult, CheckStatus, CheckType, ScanContext
from zentra.scanners.registry import build_dependent_scanners, build_primary_scanners
from zentra.scoring.engine import ScoreResult, calculate_score
from zentra.scoring.verdict import Verdict, build_verdict

log = get_logger("zentra.orchestration")


@dataclass
class ScanOutcome:
    domain: str
    results: list[CheckResult]
    score: ScoreResult
    verdict: Verdict
    duration_ms: int
    scanners_run: list[str] = field(default_factory=list)
    scanners_failed: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        """``completed`` when every scanner produced a conclusive check."""
        if not self.results:
            return "failed"
        if self.scanners_failed:
            return "partial"
        return "completed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "scanners_run": self.scanners_run,
            "scanners_failed": self.scanners_failed,
            "score": self.score.to_dict(),
            "verdict": self.verdict.to_dict(),
            "results": [r.to_dict() for r in self.results],
        }


def _technology_inputs(
    results: list[CheckResult],
) -> tuple[list[tuple[str, str | None]], list[str]]:
    """Extract technology names/versions and referenced CVE IDs from pass one."""
    technologies: list[tuple[str, str | None]] = []
    cve_ids: list[str] = []
    for result in results:
        if result.check_type is CheckType.TECHNOLOGY_STACK:
            for tech in result.details.get("technologies") or []:
                if isinstance(tech, dict) and tech.get("name"):
                    technologies.append((str(tech["name"]), tech.get("version")))
        elif result.check_type is CheckType.INTERNET_EXPOSURE:
            for cve in result.details.get("referenced_cves") or []:
                if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                    cve_ids.append(cve.upper())
    return technologies, cve_ids


async def run_scan(
    domain: str,
    *,
    vendor_id: str | None = None,
    organization_id: str | None = None,
    scan_id: str | None = None,
    limited: bool = False,
) -> ScanOutcome:
    """Execute a full scan for ``domain`` and return the scored outcome."""
    settings = get_settings()
    started = time.perf_counter()
    # Re-validate here: this is the last gate before any network activity, and
    # the orchestrator is reachable from the worker as well as the API.
    normalized = normalize_domain(domain)
    context = ScanContext(
        domain=normalized,
        vendor_id=vendor_id,
        organization_id=organization_id,
        scan_id=scan_id,
        limited=limited,
    )

    log.info(
        "scan_started",
        domain=normalized,
        scan_id=scan_id,
        vendor_id=vendor_id,
        organization_id=organization_id,
        limited=limited,
    )

    primary = build_primary_scanners(limited=limited)
    budget = settings.scanner_total_timeout_seconds
    results: list[CheckResult] = []
    scanners_run: list[str] = []
    scanners_failed: list[str] = []

    async def _guarded(scanner: Any) -> tuple[str, list[CheckResult]]:
        return scanner.name, await scanner.execute(context)

    try:
        primary_output = await asyncio.wait_for(
            asyncio.gather(*(_guarded(s) for s in primary), return_exceptions=True),
            timeout=budget,
        )
    except TimeoutError:
        primary_output = []
        for scanner in primary:
            scanners_failed.append(scanner.name)
            results.append(scanner.error_result(TimeoutError(), provider_status="timeout"))
        log.warning("scan_primary_timeout", domain=normalized, scan_id=scan_id)

    for index, item in enumerate(primary_output):
        scanner = primary[index]
        if isinstance(item, BaseException):
            # Should be unreachable: execute() normalizes. Belt and braces.
            scanners_failed.append(scanner.name)
            results.append(scanner.error_result(Exception(type(item).__name__)))
            continue
        name, checks = item
        scanners_run.append(name)
        results.extend(checks)
        if all(c.status is CheckStatus.ERROR for c in checks):
            scanners_failed.append(name)

    technologies, cve_ids = _technology_inputs(results)
    dependent = build_dependent_scanners(
        limited=limited, technologies=technologies, known_cve_ids=cve_ids
    )
    if dependent:
        remaining = max(budget - (time.perf_counter() - started), 5.0)
        try:
            dependent_output = await asyncio.wait_for(
                asyncio.gather(*(_guarded(s) for s in dependent), return_exceptions=True),
                timeout=remaining,
            )
        except TimeoutError:
            dependent_output = []
            for scanner in dependent:
                scanners_failed.append(scanner.name)
                results.append(scanner.error_result(TimeoutError(), provider_status="timeout"))

        for index, item in enumerate(dependent_output):
            scanner = dependent[index]
            if isinstance(item, BaseException):
                scanners_failed.append(scanner.name)
                results.append(scanner.error_result(Exception(type(item).__name__)))
                continue
            name, checks = item
            scanners_run.append(name)
            results.extend(checks)
            if all(c.status is CheckStatus.ERROR for c in checks):
                scanners_failed.append(name)

    score = calculate_score(results)
    verdict = build_verdict(score, results)
    duration_ms = int((time.perf_counter() - started) * 1000)

    log.info(
        "scan_completed",
        domain=normalized,
        scan_id=scan_id,
        score=score.score if score.is_scorable else None,
        risk_level=score.risk_level.value if score.risk_level else None,
        coverage=score.coverage,
        confidence=score.confidence,
        duration_ms=duration_ms,
        scanners_failed=scanners_failed,
    )

    return ScanOutcome(
        domain=normalized,
        results=results,
        score=score,
        verdict=verdict,
        duration_ms=duration_ms,
        scanners_run=scanners_run,
        scanners_failed=sorted(set(scanners_failed)),
    )
