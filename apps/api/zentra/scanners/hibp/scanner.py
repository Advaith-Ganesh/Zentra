"""Breach-history scanner."""

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
from zentra.scanners.hibp.provider import BreachProvider, get_breach_provider
from zentra.scanners.provider import ProviderStatus

RECENT_BREACH_DAYS = 730


class HIBPScanner(BaseScanner):
    """Looks up publicly catalogued breaches associated with the vendor's domain."""

    name = "hibp"
    display_name = "Breach history"
    check_types = (CheckType.BREACH_HISTORY,)
    timeout_seconds = 45.0
    included_in_public_scan = True

    def __init__(self, provider: BreachProvider | None = None, **options: object) -> None:
        super().__init__(**options)
        self.provider = provider or get_breach_provider()

    async def run(self, context: ScanContext) -> list[CheckResult]:
        result = await self.provider.lookup(context.domain)
        source = self.provider.source_label

        if result.status is ProviderStatus.NOT_CONFIGURED:
            return [
                CheckResult(
                    check_type=CheckType.BREACH_HISTORY,
                    status=CheckStatus.UNKNOWN,
                    severity=Severity.INFO,
                    summary=(
                        "Breach history was not assessed: no breach-intelligence credential is "
                        "configured for this deployment."
                    ),
                    source=source,
                    details={"assessed": False, "reason": "provider_not_configured"},
                    confidence=0.0,
                    provider_status=result.status.value,
                )
            ]
        if result.status in (ProviderStatus.RATE_LIMITED, ProviderStatus.UNAVAILABLE):
            return [
                CheckResult(
                    check_type=CheckType.BREACH_HISTORY,
                    status=CheckStatus.ERROR,
                    severity=Severity.INFO,
                    summary=(
                        "Breach history could not be checked because the breach-intelligence "
                        "provider was unavailable. This is not an indication that the vendor "
                        "is free of breaches."
                    ),
                    source=source,
                    details={"assessed": False, "reason": result.status.value},
                    confidence=0.0,
                    provider_status=result.status.value,
                )
            ]

        history = result.data
        if history is None or history.count == 0:
            return [
                CheckResult(
                    check_type=CheckType.BREACH_HISTORY,
                    status=CheckStatus.PASS,
                    severity=Severity.INFO,
                    summary=(
                        "No publicly catalogued data breach is associated with this vendor's "
                        "domain."
                    ),
                    source=source,
                    details={"breach_count": 0, "assessed": True},
                    confidence=0.9,
                )
            ]

        recent = history.recent(RECENT_BREACH_DAYS)
        credentials = history.exposes_credentials
        # Store only breach metadata — never account-level data.
        catalogue = [
            {
                "name": b.name,
                "title": b.title,
                "breach_date": b.breach_date,
                "accounts_affected": b.pwn_count,
                "data_types": b.data_classes,
                "verified": b.is_verified,
            }
            for b in history.breaches[:20]
        ]
        evidence = [
            Evidence(
                b.title,
                f"{b.breach_date or 'date unknown'} — {b.pwn_count:,} accounts",
                source,
            )
            for b in history.breaches[:5]
        ]

        if credentials and recent:
            severity, status = Severity.CRITICAL, CheckStatus.FAIL
            summary = (
                f"This vendor's domain appears in {history.count} publicly catalogued "
                f"breach(es), including a recent incident that exposed credentials."
            )
        elif credentials:
            severity, status = Severity.HIGH, CheckStatus.FAIL
            summary = (
                f"This vendor's domain appears in {history.count} publicly catalogued "
                "breach(es), at least one of which exposed credentials."
            )
        elif recent:
            severity, status = Severity.HIGH, CheckStatus.FAIL
            summary = (
                f"This vendor's domain appears in {history.count} publicly catalogued "
                f"breach(es), including {len(recent)} in the last two years."
            )
        else:
            severity, status = Severity.MEDIUM, CheckStatus.WARN
            summary = (
                f"This vendor's domain appears in {history.count} publicly catalogued "
                "breach(es), all more than two years old."
            )

        return [
            CheckResult(
                check_type=CheckType.BREACH_HISTORY,
                status=status,
                severity=severity,
                summary=summary,
                title="Vendor domain appears in known data breaches",
                recommendation=(
                    "Ask the vendor what happened, what data was affected, and what they "
                    "changed afterwards. If credentials were exposed, confirm that any shared "
                    "accounts your business holds with them have had passwords rotated and "
                    "multi-factor authentication enabled."
                ),
                source=source,
                details={
                    "breach_count": history.count,
                    "recent_breach_count": len(recent),
                    "credentials_exposed": credentials,
                    "breaches": catalogue,
                    "assessed": True,
                },
                evidence=evidence,
                confidence=0.95,
            )
        ]
