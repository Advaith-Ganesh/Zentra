"""Technology fingerprint and HTTP security header scanner."""

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
from zentra.scanners.technology.provider import (
    SECURITY_HEADERS,
    TechnologyProvider,
    get_technology_provider,
)


class TechnologyScanner(BaseScanner):
    """Identifies publicly declared technologies and checks HTTP security headers."""

    name = "technology"
    display_name = "Web technology and security headers"
    check_types = (CheckType.TECHNOLOGY_STACK, CheckType.HTTP_SECURITY_HEADERS)
    timeout_seconds = 40.0
    included_in_public_scan = True

    def __init__(self, provider: TechnologyProvider | None = None, **options: object) -> None:
        super().__init__(**options)
        self.provider = provider or get_technology_provider()

    async def run(self, context: ScanContext) -> list[CheckResult]:
        result = await self.provider.profile(context.domain)
        source = self.provider.source_label

        if result.status is not ProviderStatus.OK or result.data is None:
            return [self.error_result(None, provider_status=result.status.value)]

        profile = result.data
        technologies = [
            {
                "name": t.name,
                "version": t.version,
                "version_known": t.version is not None,
                "category": t.category,
                "confidence": t.confidence,
                "evidence": t.evidence,
            }
            for t in profile.technologies
        ]

        if technologies:
            declared = ", ".join(
                f"{t['name']}{' ' + str(t['version']) if t['version'] else ''}"
                for t in technologies
            )
            tech_summary = f"Publicly declared technologies: {declared}."
        else:
            tech_summary = "The vendor's servers do not publicly declare their technology stack."

        tech_check = CheckResult(
            check_type=CheckType.TECHNOLOGY_STACK,
            # Identifying technology is informational, never a failure by itself.
            status=CheckStatus.PASS if technologies else CheckStatus.UNKNOWN,
            severity=Severity.INFO,
            summary=tech_summary,
            source=source,
            details={
                "technologies": technologies,
                "server_header": profile.server_header,
                "url": profile.url,
                "assessed": True,
            },
            evidence=[
                Evidence(t.name, t.version or "version not disclosed", source)
                for t in profile.technologies[:6]
            ],
            confidence=0.6 if technologies else 0.0,
        )

        missing = profile.missing_security_headers
        header_details = {
            "present": {k: bool(v) for k, v in profile.security_headers.items()},
            "missing": missing,
            "missing_labels": [SECURITY_HEADERS[h] for h in missing if h in SECURITY_HEADERS],
            "assessed": True,
        }
        if not missing:
            header_check = CheckResult(
                check_type=CheckType.HTTP_SECURITY_HEADERS,
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                summary="The vendor's website sets all the browser security headers we check.",
                source=source,
                details=header_details,
                confidence=0.9,
            )
        else:
            critical_missing = {"strict-transport-security", "content-security-policy"} & set(
                missing
            )
            severity = Severity.MEDIUM if critical_missing else Severity.LOW
            header_check = CheckResult(
                check_type=CheckType.HTTP_SECURITY_HEADERS,
                status=CheckStatus.WARN,
                severity=severity,
                summary=(
                    f"The vendor's website is missing {len(missing)} browser security "
                    f"header(s): "
                    + ", ".join(SECURITY_HEADERS[h] for h in missing if h in SECURITY_HEADERS)
                    + "."
                ),
                title="Missing browser security headers",
                recommendation=(
                    "Ask the vendor to add the missing response headers. These are low-effort "
                    "changes that reduce the impact of common browser-based attacks."
                ),
                source=source,
                details=header_details,
                evidence=[
                    Evidence(SECURITY_HEADERS[h], "not set", source)
                    for h in missing
                    if h in SECURITY_HEADERS
                ][:5],
                confidence=0.9,
            )

        return [tech_check, header_check]
