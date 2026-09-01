"""Internet-exposure scanner.

Passive only: the data comes from a third-party index of what is already
publicly visible. Zentra never connects to the discovered services.
"""

from __future__ import annotations

from zentra.scanners.base import (
    BaseScanner,
    CheckResult,
    CheckStatus,
    CheckType,
    Evidence,
    ScanContext,
    Severity,
)
from zentra.scanners.provider import ProviderStatus
from zentra.scanners.shodan.provider import (
    CRITICAL_PORTS,
    SENSITIVE_PORTS,
    ExposureProvider,
    get_exposure_provider,
)


class ShodanScanner(BaseScanner):
    """Reports publicly reachable services associated with the vendor's domain."""

    name = "exposure"
    display_name = "Internet exposure"
    check_types = (CheckType.INTERNET_EXPOSURE,)
    timeout_seconds = 45.0
    included_in_public_scan = False

    def __init__(self, provider: ExposureProvider | None = None, **options: object) -> None:
        super().__init__(**options)
        self.provider = provider or get_exposure_provider()

    async def run(self, context: ScanContext) -> list[CheckResult]:
        result = await self.provider.lookup(context.domain)
        source = self.provider.source_label

        if result.status is ProviderStatus.NOT_CONFIGURED:
            return [
                CheckResult(
                    check_type=CheckType.INTERNET_EXPOSURE,
                    status=CheckStatus.UNKNOWN,
                    severity=Severity.INFO,
                    summary=(
                        "Internet exposure was not assessed: no exposure-intelligence "
                        "credential is configured for this deployment."
                    ),
                    source=source,
                    details={"assessed": False, "reason": "provider_not_configured"},
                    confidence=0.0,
                    provider_status=result.status.value,
                )
            ]
        if result.status in (
            ProviderStatus.RATE_LIMITED,
            ProviderStatus.UNAVAILABLE,
            ProviderStatus.INVALID_TARGET,
        ):
            return [self.error_result(None, provider_status=result.status.value)]

        report = result.data
        if report is None or not report.services:
            return [
                CheckResult(
                    check_type=CheckType.INTERNET_EXPOSURE,
                    status=CheckStatus.PASS,
                    severity=Severity.INFO,
                    summary=(
                        "No unexpected internet-facing services were found for this vendor's "
                        "primary address."
                    ),
                    source=source,
                    details={
                        "assessed": True,
                        "open_ports": [],
                        "ip_assessed": report.ip_address if report else None,
                        "provider_timestamp": result.provider_timestamp,
                    },
                    confidence=0.8,
                )
            ]

        sensitive = [s for s in report.services if s.port in SENSITIVE_PORTS]
        critical = [s for s in sensitive if s.port in CRITICAL_PORTS]
        # Service banners are useful evidence but are not published verbatim in
        # customer-facing summaries beyond product/version.
        service_summary = [
            {
                "port": s.port,
                "transport": s.transport,
                "service": s.service,
                "product": s.product,
                "version": s.version,
                "sensitive": s.port in SENSITIVE_PORTS,
                "label": SENSITIVE_PORTS.get(s.port),
            }
            for s in sorted(report.services, key=lambda x: x.port)
        ]
        details = {
            "assessed": True,
            "open_ports": report.open_ports,
            "services": service_summary,
            "sensitive_ports": sorted({s.port for s in sensitive}),
            "organization": report.organization,
            "country": report.country,
            "ip_assessed": report.ip_address,
            "provider_timestamp": result.provider_timestamp,
            "referenced_cves": report.all_vulns[:25],
        }
        evidence = [
            Evidence(
                f"Port {s.port}/{s.transport}",
                " ".join(filter(None, [s.product, s.version])) or (s.service or "open"),
                source,
            )
            for s in sorted(report.services, key=lambda x: x.port)[:8]
        ]

        if critical:
            names = ", ".join(sorted({SENSITIVE_PORTS[s.port] for s in critical}))
            return [
                CheckResult(
                    check_type=CheckType.INTERNET_EXPOSURE,
                    status=CheckStatus.FAIL,
                    severity=Severity.HIGH,
                    summary=(
                        f"Administrative or database services are reachable from the public "
                        f"internet ({names})."
                    ),
                    title="Sensitive services exposed to the internet",
                    recommendation=(
                        "Ask the vendor to confirm these services are intended to be public. "
                        "Databases and remote-administration services should normally sit "
                        "behind a VPN or IP allow-list."
                    ),
                    source=source,
                    details=details,
                    evidence=evidence,
                    confidence=0.85,
                )
            ]
        if sensitive:
            names = ", ".join(sorted({SENSITIVE_PORTS[s.port] for s in sensitive}))
            return [
                CheckResult(
                    check_type=CheckType.INTERNET_EXPOSURE,
                    status=CheckStatus.WARN,
                    severity=Severity.MEDIUM,
                    summary=f"Some administrative services are publicly reachable ({names}).",
                    title="Administrative services exposed to the internet",
                    recommendation=(
                        "Ask the vendor whether these services need to be internet-facing and "
                        "whether access is restricted."
                    ),
                    source=source,
                    details=details,
                    evidence=evidence,
                    confidence=0.85,
                )
            ]
        return [
            CheckResult(
                check_type=CheckType.INTERNET_EXPOSURE,
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                summary=(
                    f"Only expected web services are publicly reachable "
                    f"({', '.join(str(p) for p in report.open_ports)})."
                ),
                source=source,
                details=details,
                evidence=evidence,
                confidence=0.85,
            )
        ]
