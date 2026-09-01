"""Scanner contract, providers and orchestration."""

from __future__ import annotations

import asyncio

import pytest

from zentra.scanners.base import (
    BaseScanner,
    CheckResult,
    CheckStatus,
    CheckType,
    ScanContext,
    Severity,
)
from zentra.scanners.dns_sec.provider import DnsRecords, MockDnsProvider
from zentra.scanners.dns_sec.scanner import DNSScanner
from zentra.scanners.hibp.provider import BreachHistory, MockBreachProvider
from zentra.scanners.hibp.scanner import HIBPScanner
from zentra.scanners.orchestration import run_scan
from zentra.scanners.provider import ProviderResult, ProviderStatus
from zentra.scanners.shodan.provider import ExposedService, ExposureReport, MockExposureProvider
from zentra.scanners.shodan.scanner import ShodanScanner
from zentra.scanners.ssl_labs.provider import MockTlsProvider, TlsAssessment
from zentra.scanners.ssl_labs.scanner import SSLScanner


def result_for(results: list[CheckResult], check_type: CheckType) -> CheckResult:
    return next(r for r in results if r.check_type is check_type)


# --------------------------------------------------------------- base contract
class _ExplodingScanner(BaseScanner):
    name = "exploding"
    display_name = "Exploding scanner"
    check_types = (CheckType.TLS_CERTIFICATE,)
    max_attempts = 1

    async def run(self, context: ScanContext) -> list[CheckResult]:
        raise RuntimeError("provider exploded")


class _HangingScanner(BaseScanner):
    name = "hanging"
    display_name = "Hanging scanner"
    check_types = (CheckType.DNS_SPF,)
    timeout_seconds = 0.05
    max_attempts = 1

    async def run(self, context: ScanContext) -> list[CheckResult]:
        await asyncio.sleep(5)
        return []


class _FlakyScanner(BaseScanner):
    name = "flaky"
    display_name = "Flaky scanner"
    check_types = (CheckType.DNS_SPF,)
    max_attempts = 3
    retry_backoff_seconds = 0.001

    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    async def run(self, context: ScanContext) -> list[CheckResult]:
        self.attempts += 1
        if self.attempts < 3:
            raise ConnectionError("transient")
        return [
            CheckResult(
                check_type=CheckType.DNS_SPF,
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                summary="ok",
                source="flaky",
            )
        ]


async def test_scanner_exception_becomes_an_error_result_not_a_failure() -> None:
    results = await _ExplodingScanner().execute(ScanContext(domain="example.com"))
    assert len(results) == 1
    assert results[0].status is CheckStatus.ERROR
    assert results[0].severity is Severity.INFO
    assert results[0].confidence == 0.0
    # The customer-facing summary must not leak the internal exception message.
    assert "exploded" not in results[0].summary


async def test_scanner_timeout_is_bounded_and_normalized() -> None:
    results = await _HangingScanner().execute(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.ERROR
    assert results[0].is_conclusive is False


async def test_scanner_retries_transient_failures() -> None:
    scanner = _FlakyScanner()
    results = await scanner.execute(ScanContext(domain="example.com"))
    assert scanner.attempts == 3
    assert results[0].status is CheckStatus.PASS


async def test_unsafe_target_is_not_retried() -> None:
    from zentra.errors import UnsafeTargetError

    class _Blocked(BaseScanner):
        name = "blocked"
        check_types = (CheckType.TLS_CERTIFICATE,)
        max_attempts = 3
        retry_backoff_seconds = 0.001

        def __init__(self) -> None:
            super().__init__()
            self.attempts = 0

        async def run(self, context: ScanContext) -> list[CheckResult]:
            self.attempts += 1
            raise UnsafeTargetError("blocked")

    scanner = _Blocked()
    await scanner.execute(ScanContext(domain="example.com"))
    assert scanner.attempts == 1


# ------------------------------------------------------------------- TLS
async def test_expired_certificate_is_reported_as_critical() -> None:
    provider = MockTlsProvider()
    provider.SCRIPTED = {"expired.example.com": "expired"}
    results = await SSLScanner(provider=provider).run(ScanContext(domain="expired.example.com"))
    certificate = result_for(results, CheckType.TLS_CERTIFICATE)
    assert certificate.status is CheckStatus.FAIL
    assert certificate.severity is Severity.CRITICAL
    assert certificate.recommendation


async def test_weak_tls_protocols_are_reported() -> None:
    provider = MockTlsProvider()
    provider.SCRIPTED = {"weak.example.com": "weak_protocol"}
    results = await SSLScanner(provider=provider).run(ScanContext(domain="weak.example.com"))
    configuration = result_for(results, CheckType.TLS_CONFIGURATION)
    assert configuration.is_problem
    assert "TLS 1.0" in configuration.details["weak_protocols"]


async def test_healthy_certificate_passes() -> None:
    provider = MockTlsProvider()
    provider.SCRIPTED = {"good.example.com": "excellent"}
    results = await SSLScanner(provider=provider).run(ScanContext(domain="good.example.com"))
    assert result_for(results, CheckType.TLS_CERTIFICATE).status is CheckStatus.PASS
    assert result_for(results, CheckType.TLS_CONFIGURATION).status is CheckStatus.PASS


async def test_tls_provider_outage_is_an_error_not_a_failure() -> None:
    class _Down(MockTlsProvider):
        async def assess(self, domain: str) -> ProviderResult[TlsAssessment]:
            return ProviderResult.unavailable("down")

    results = await SSLScanner(provider=_Down()).run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.ERROR
    assert results[0].severity is Severity.INFO


async def test_no_https_service_is_unknown_not_failure() -> None:
    class _Invalid(MockTlsProvider):
        async def assess(self, domain: str) -> ProviderResult[TlsAssessment]:
            return ProviderResult(status=ProviderStatus.INVALID_TARGET, error="no https")

    results = await SSLScanner(provider=_Invalid()).run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.UNKNOWN
    assert results[0].confidence == 0.0


# ------------------------------------------------------------------- DNS
async def test_missing_spf_and_dmarc_are_failures() -> None:
    class _Bare(MockDnsProvider):
        async def lookup(self, domain: str) -> ProviderResult[DnsRecords]:
            return ProviderResult(status=ProviderStatus.OK, data=DnsRecords())

    results = await DNSScanner(provider=_Bare()).run(ScanContext(domain="example.com"))
    assert result_for(results, CheckType.DNS_SPF).status is CheckStatus.FAIL
    assert result_for(results, CheckType.DNS_DMARC).status is CheckStatus.FAIL


async def test_dkim_absence_is_unknown_never_missing() -> None:
    """DKIM selectors are not enumerable from DNS, so absence proves nothing."""

    class _NoDkim(MockDnsProvider):
        async def lookup(self, domain: str) -> ProviderResult[DnsRecords]:
            return ProviderResult(
                status=ProviderStatus.OK,
                data=DnsRecords(
                    txt=["v=spf1 -all"],
                    dmarc_txt=["v=DMARC1; p=reject"],
                    dkim_selectors_checked=["google", "selector1"],
                ),
            )

    results = await DNSScanner(provider=_NoDkim()).run(ScanContext(domain="example.com"))
    dkim = result_for(results, CheckType.DNS_DKIM)
    assert dkim.status is CheckStatus.UNKNOWN
    assert dkim.confidence == 0.0
    assert dkim.details["dkim_status"] == "not_assessed"
    assert "not mean DKIM is missing" in dkim.summary


async def test_dkim_found_passes() -> None:
    class _WithDkim(MockDnsProvider):
        async def lookup(self, domain: str) -> ProviderResult[DnsRecords]:
            return ProviderResult(
                status=ProviderStatus.OK,
                data=DnsRecords(
                    txt=["v=spf1 -all"],
                    dmarc_txt=["v=DMARC1; p=reject"],
                    dkim={"google": "v=DKIM1; k=rsa; p=AAA"},
                ),
            )

    results = await DNSScanner(provider=_WithDkim()).run(ScanContext(domain="example.com"))
    assert result_for(results, CheckType.DNS_DKIM).status is CheckStatus.PASS


async def test_dmarc_monitor_only_is_a_low_severity_warning() -> None:
    class _Monitor(MockDnsProvider):
        async def lookup(self, domain: str) -> ProviderResult[DnsRecords]:
            return ProviderResult(
                status=ProviderStatus.OK,
                data=DnsRecords(txt=["v=spf1 ~all"], dmarc_txt=["v=DMARC1; p=none"]),
            )

    results = await DNSScanner(provider=_Monitor()).run(ScanContext(domain="example.com"))
    dmarc = result_for(results, CheckType.DNS_DMARC)
    assert dmarc.status is CheckStatus.WARN
    assert dmarc.severity is Severity.LOW
    assert dmarc.details["dmarc_policy"] == "none"


async def test_strict_spf_and_enforced_dmarc_pass() -> None:
    class _Strong(MockDnsProvider):
        async def lookup(self, domain: str) -> ProviderResult[DnsRecords]:
            return ProviderResult(
                status=ProviderStatus.OK,
                data=DnsRecords(
                    txt=["v=spf1 include:_spf.example.com -all"],
                    dmarc_txt=["v=DMARC1; p=reject; rua=mailto:a@example.com"],
                    caa=['0 issue "letsencrypt.org"'],
                ),
            )

    results = await DNSScanner(provider=_Strong()).run(ScanContext(domain="example.com"))
    assert result_for(results, CheckType.DNS_SPF).status is CheckStatus.PASS
    assert result_for(results, CheckType.DNS_DMARC).status is CheckStatus.PASS
    assert result_for(results, CheckType.DNS_CAA).status is CheckStatus.PASS


# ------------------------------------------------------------------- breach
async def test_no_breach_found_passes_with_partial_confidence() -> None:
    class _Clean(MockBreachProvider):
        async def lookup(self, domain: str) -> ProviderResult[BreachHistory]:
            return ProviderResult(
                status=ProviderStatus.NOT_FOUND, data=BreachHistory(domain=domain)
            )

    results = await HIBPScanner(provider=_Clean()).run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.PASS
    assert results[0].details["assessed"] is True


async def test_breach_provider_unavailable_is_never_treated_as_clean() -> None:
    class _Down(MockBreachProvider):
        async def lookup(self, domain: str) -> ProviderResult[BreachHistory]:
            return ProviderResult.unavailable("down")

    results = await HIBPScanner(provider=_Down()).run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.ERROR
    assert results[0].details["assessed"] is False
    assert "not an indication that the vendor is free of breaches" in results[0].summary


async def test_missing_breach_credential_is_not_assessed() -> None:
    class _NoKey(MockBreachProvider):
        async def lookup(self, domain: str) -> ProviderResult[BreachHistory]:
            return ProviderResult.not_configured("HIBP")

    results = await HIBPScanner(provider=_NoKey()).run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.UNKNOWN
    assert results[0].details["reason"] == "provider_not_configured"


async def test_credential_breach_is_critical_and_stores_only_metadata() -> None:
    provider = MockBreachProvider()
    provider.SCRIPTED = {"breached.example.com": "credential_breach"}
    results = await HIBPScanner(provider=provider).run(ScanContext(domain="breached.example.com"))
    finding = results[0]
    assert finding.status is CheckStatus.FAIL
    assert finding.severity is Severity.CRITICAL
    assert finding.details["credentials_exposed"] is True
    for breach in finding.details["breaches"]:
        # Only catalogue metadata, never account-level data.
        assert set(breach) <= {
            "name",
            "title",
            "breach_date",
            "accounts_affected",
            "data_types",
            "verified",
        }


# ------------------------------------------------------------------- exposure
async def test_exposed_database_is_high_severity() -> None:
    class _Exposed(MockExposureProvider):
        async def lookup(self, domain: str) -> ProviderResult[ExposureReport]:
            return ProviderResult(
                status=ProviderStatus.OK,
                data=ExposureReport(
                    domain=domain,
                    ip_address="93.184.216.34",
                    services=[
                        ExposedService(port=443, product="nginx"),
                        ExposedService(port=6379, product="Redis"),
                    ],
                ),
            )

    results = await ShodanScanner(provider=_Exposed()).run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.FAIL
    assert results[0].severity is Severity.HIGH
    assert 6379 in results[0].details["sensitive_ports"]


async def test_only_web_ports_passes() -> None:
    class _WebOnly(MockExposureProvider):
        async def lookup(self, domain: str) -> ProviderResult[ExposureReport]:
            return ProviderResult(
                status=ProviderStatus.OK,
                data=ExposureReport(
                    domain=domain,
                    services=[ExposedService(port=443), ExposedService(port=80)],
                ),
            )

    results = await ShodanScanner(provider=_WebOnly()).run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.PASS


# ------------------------------------------------------------------- CVE
async def test_cve_scanner_makes_no_claim_without_technology_signals() -> None:
    from zentra.scanners.cve.scanner import CVEScanner

    results = await CVEScanner().run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.UNKNOWN
    assert results[0].details["reason"] == "no_technology_signals"


async def test_cve_scanner_skips_technologies_without_a_known_version() -> None:
    from zentra.scanners.cve.provider import MockCveProvider
    from zentra.scanners.cve.scanner import CVEScanner

    provider = MockCveProvider()
    provider.SCRIPTED = {"example.com": "none"}
    scanner = CVEScanner(provider=provider, technologies=[("nginx", None), ("Apache", "2.4.49")])
    results = await scanner.run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.PASS
    assert "nginx" in results[0].details["technologies_skipped_unknown_version"]


async def test_cve_findings_carry_provenance() -> None:
    from zentra.scanners.cve.provider import MockCveProvider
    from zentra.scanners.cve.scanner import CVEScanner

    provider = MockCveProvider()
    provider.SCRIPTED = {"example.com": "critical"}
    scanner = CVEScanner(provider=provider, technologies=[("Apache", "2.4.49")])
    results = await scanner.run(ScanContext(domain="example.com"))
    assert results[0].status is CheckStatus.FAIL
    for vulnerability in results[0].details["vulnerabilities"]:
        assert vulnerability["cve_id"].startswith("CVE-")
        assert vulnerability["source"]
        assert vulnerability["published_date"]
        assert 0 < vulnerability["confidence"] <= 1


# ---------------------------------------------------------------- orchestration
async def test_full_scan_produces_a_scored_outcome() -> None:
    outcome = await run_scan("example-vendor.com")
    assert outcome.status in ("completed", "partial")
    assert outcome.results
    assert outcome.verdict.headline
    assert outcome.score.to_dict()["categories"]


async def test_mock_scan_results_are_deterministic() -> None:
    first = await run_scan("deterministic-vendor.com")
    second = await run_scan("deterministic-vendor.com")
    assert first.score.score == second.score.score
    assert first.score.risk_level == second.score.risk_level


async def test_limited_scan_omits_expensive_providers() -> None:
    outcome = await run_scan("example-vendor.com", limited=True)
    performed = {r.check_type for r in outcome.results}
    assert CheckType.INTERNET_EXPOSURE not in performed
    assert CheckType.CVE_EXPOSURE not in performed
    assert CheckType.TLS_CERTIFICATE in performed


async def test_one_failing_scanner_does_not_fail_the_scan(monkeypatch) -> None:
    from zentra.scanners import registry

    monkeypatch.setitem(registry.PRIMARY_SCANNERS, "ssl", lambda **_: _ExplodingScanner())
    outcome = await run_scan("example-vendor.com")
    assert outcome.status == "partial"
    assert "exploding" in outcome.scanners_failed
    # The rest of the scan still produced results.
    assert len(outcome.results) > 1


async def test_scan_rejects_an_unsafe_domain_before_any_network_activity() -> None:
    from zentra.errors import InvalidDomainError

    for domain in ["localhost", "169.254.169.254", "internal.local"]:
        with pytest.raises(InvalidDomainError):
            await run_scan(domain)
