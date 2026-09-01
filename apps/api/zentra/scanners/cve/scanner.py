"""CVE exposure scanner.

Depends on technology signals produced earlier in the scan. When no technology
version is known, this scanner reports ``UNKNOWN`` — an absence of evidence,
not evidence of safety, and not evidence of risk either.
"""

from __future__ import annotations

from typing import Any

from zentra.scanners.base import (
    BaseScanner,
    CheckResult,
    CheckStatus,
    CheckType,
    Evidence,
    ScanContext,
    Severity,
)
from zentra.scanners.cve.provider import CveProvider, get_cve_provider
from zentra.scanners.provider import ProviderStatus

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "unknown": Severity.INFO,
}


class CVEScanner(BaseScanner):
    """Correlates declared technology versions with published vulnerabilities."""

    name = "cve"
    display_name = "Known vulnerabilities"
    check_types = (CheckType.CVE_EXPOSURE,)
    timeout_seconds = 60.0
    included_in_public_scan = False

    def __init__(self, provider: CveProvider | None = None, **options: object) -> None:
        super().__init__(**options)
        self.provider = provider or get_cve_provider()

    async def run(self, context: ScanContext) -> list[CheckResult]:
        # Inputs come from the orchestrator via options, so this scanner never
        # performs its own fingerprinting.
        technologies: list[tuple[str, str | None]] = list(self.options.get("technologies") or [])
        known_cve_ids: list[str] = list(self.options.get("known_cve_ids") or [])
        source = self.provider.source_label

        if not technologies and not known_cve_ids:
            return [
                self.not_assessed(
                    CheckType.CVE_EXPOSURE,
                    (
                        "Known-vulnerability exposure was not assessed: the vendor's servers "
                        "do not publicly declare which software they run."
                    ),
                    reason="no_technology_signals",
                )
            ]

        result = await self.provider.lookup(context.domain, technologies, known_cve_ids)

        if result.status in (
            ProviderStatus.UNAVAILABLE,
            ProviderStatus.RATE_LIMITED,
            ProviderStatus.NOT_CONFIGURED,
        ):
            return [self.error_result(None, provider_status=result.status.value)]

        report = result.data
        if report is None or not report.vulnerabilities:
            skipped = report.technologies_skipped_unknown_version if report else []
            summary = (
                "No published vulnerabilities were matched to the software versions this "
                "vendor discloses."
            )
            if skipped:
                summary += (
                    f" {len(skipped)} technology signal(s) could not be checked because no "
                    "version is disclosed."
                )
            return [
                CheckResult(
                    check_type=CheckType.CVE_EXPOSURE,
                    status=CheckStatus.PASS,
                    severity=Severity.INFO,
                    summary=summary,
                    source=source,
                    details={
                        "assessed": True,
                        "vulnerability_count": 0,
                        "technologies_queried": report.technologies_queried if report else [],
                        "technologies_skipped_unknown_version": skipped,
                        "last_checked_at": report.last_checked_at if report else None,
                    },
                    # Partial coverage: we only checked what was disclosed.
                    confidence=0.5 if skipped else 0.7,
                )
            ]

        worst = max(
            (v.severity for v in report.vulnerabilities),
            key=lambda s: _SEVERITY_MAP[s].rank,
        )
        severity = _SEVERITY_MAP[worst]
        status = CheckStatus.FAIL if severity.rank >= Severity.HIGH.rank else CheckStatus.WARN
        vulns: list[dict[str, Any]] = [
            {
                "cve_id": v.cve_id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "description": v.description,
                "published_date": v.published_date,
                "source": v.source,
                "technology": v.technology,
                "technology_version": v.technology_version,
                "confidence": v.confidence,
                "reference_url": v.reference_url,
            }
            for v in sorted(
                report.vulnerabilities,
                key=lambda v: (-(v.cvss_score or 0), v.cve_id),
            )[:25]
        ]
        confidence = max((v.confidence for v in report.vulnerabilities), default=0.5)

        return [
            CheckResult(
                check_type=CheckType.CVE_EXPOSURE,
                status=status,
                severity=severity,
                summary=(
                    f"{len(report.vulnerabilities)} published vulnerability record(s) match "
                    f"software versions this vendor discloses; the most serious is rated "
                    f"{worst}."
                ),
                title=f"Published vulnerabilities affect disclosed software ({worst})",
                recommendation=(
                    "Share the CVE references with the vendor and ask whether their deployment "
                    "is patched. A disclosed version matching a CVE is an indicator, not proof "
                    "of exploitability — the vendor may have backported fixes."
                ),
                source=source,
                details={
                    "assessed": True,
                    "vulnerability_count": len(report.vulnerabilities),
                    "highest_severity": worst,
                    "vulnerabilities": vulns,
                    "technologies_queried": report.technologies_queried,
                    "technologies_skipped_unknown_version": (
                        report.technologies_skipped_unknown_version
                    ),
                    "last_checked_at": report.last_checked_at,
                },
                evidence=[
                    Evidence(
                        v.cve_id,
                        f"{v.severity} (CVSS {v.cvss_score}) — {v.technology} "
                        f"{v.technology_version or 'version unknown'}",
                        v.source,
                    )
                    for v in report.vulnerabilities[:5]
                ],
                confidence=confidence,
            )
        ]
