"""Email-authentication DNS scanner (SPF, DMARC, DKIM, CAA).

DKIM honesty note: there is no DNS record that enumerates a domain's DKIM
selectors. We probe a short list of selectors used by common mail platforms; a
miss means we could not assess DKIM, which is reported as ``UNKNOWN`` and
carries no risk weight. Reporting it as "missing" would be a fabricated
finding.
"""

from __future__ import annotations

import re

from zentra.scanners.base import (
    BaseScanner,
    CheckResult,
    CheckStatus,
    CheckType,
    Evidence,
    ScanContext,
    Severity,
)
from zentra.scanners.dns_sec.provider import DnsProvider, DnsRecords, get_dns_provider
from zentra.scanners.provider import ProviderStatus

_SPF_RE = re.compile(r"^v=spf1\b", re.IGNORECASE)
_DMARC_RE = re.compile(r"^v=DMARC1\b", re.IGNORECASE)
_SPF_ALL_RE = re.compile(r"(?P<qualifier>[-~+?])all\b", re.IGNORECASE)


class DNSScanner(BaseScanner):
    """Assesses the domain's email-spoofing protections."""

    name = "dns"
    display_name = "DNS and email security"
    check_types = (
        CheckType.DNS_SPF,
        CheckType.DNS_DMARC,
        CheckType.DNS_DKIM,
        CheckType.DNS_CAA,
    )
    timeout_seconds = 45.0
    included_in_public_scan = True

    def __init__(self, provider: DnsProvider | None = None, **options: object) -> None:
        super().__init__(**options)
        self.provider = provider or get_dns_provider()

    async def run(self, context: ScanContext) -> list[CheckResult]:
        result = await self.provider.lookup(context.domain)
        source = self.provider.source_label

        if result.status is not ProviderStatus.OK or result.data is None:
            return [self.error_result(None, provider_status=result.status.value)]

        records = result.data
        checks = [
            self._spf(records, source),
            self._dmarc(records, source),
            self._dkim(records, source),
        ]
        if not context.limited:
            checks.append(self._caa(records, source))
        return checks

    # ------------------------------------------------------------------ SPF
    def _spf(self, records: DnsRecords, source: str) -> CheckResult:
        spf = next((r for r in records.txt if _SPF_RE.match(r.strip())), None)
        details = {
            "spf_present": spf is not None,
            "spf_record": spf,
            "errors": records.errors,
        }
        if spf is None:
            return CheckResult(
                check_type=CheckType.DNS_SPF,
                status=CheckStatus.FAIL,
                severity=Severity.MEDIUM,
                summary=(
                    "The vendor has no SPF record, so anyone can send email that appears to "
                    "come from their domain."
                ),
                title="No SPF record published",
                recommendation=(
                    "Ask the vendor to publish an SPF record listing the servers permitted to "
                    "send their email. This reduces the risk of phishing that impersonates them."
                ),
                source=source,
                details=details,
            )

        match = _SPF_ALL_RE.search(spf)
        qualifier = match.group("qualifier") if match else None
        details["spf_all_qualifier"] = qualifier
        evidence = [Evidence("SPF record", spf[:255], source)]

        if qualifier == "-":
            return CheckResult(
                check_type=CheckType.DNS_SPF,
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                summary="The vendor publishes a strict SPF record.",
                source=source,
                details=details,
                evidence=evidence,
            )
        if qualifier == "~":
            return CheckResult(
                check_type=CheckType.DNS_SPF,
                status=CheckStatus.WARN,
                severity=Severity.LOW,
                summary=(
                    "The vendor's SPF record uses a soft fail, so spoofed email is marked "
                    "rather than rejected."
                ),
                title="SPF record uses soft fail",
                recommendation=(
                    "Low priority. The vendor could tighten SPF from ~all to -all once they "
                    "are confident every legitimate sender is listed."
                ),
                source=source,
                details=details,
                evidence=evidence,
            )
        return CheckResult(
            check_type=CheckType.DNS_SPF,
            status=CheckStatus.WARN,
            severity=Severity.MEDIUM,
            summary=(
                "The vendor's SPF record does not restrict unlisted senders, which weakens "
                "protection against email spoofing."
            ),
            title="SPF record is permissive",
            recommendation="Ask the vendor to end their SPF record with -all or ~all.",
            source=source,
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------ DMARC
    def _dmarc(self, records: DnsRecords, source: str) -> CheckResult:
        dmarc = next((r for r in records.dmarc_txt if _DMARC_RE.match(r.strip())), None)
        details: dict[str, object] = {
            "dmarc_present": dmarc is not None,
            "dmarc_record": dmarc,
            "dmarc_policy": None,
        }
        if dmarc is None:
            return CheckResult(
                check_type=CheckType.DNS_DMARC,
                status=CheckStatus.FAIL,
                severity=Severity.MEDIUM,
                summary=(
                    "The vendor has no DMARC record, so recipients have no instruction on how "
                    "to handle email that fails authentication."
                ),
                title="No DMARC record published",
                recommendation=(
                    "Ask the vendor to publish a DMARC record. Starting at p=none for "
                    "monitoring and moving to p=quarantine or p=reject is the standard path."
                ),
                source=source,
                details=details,
            )

        tags = {}
        for part in dmarc.split(";"):
            if "=" in part:
                key, _, value = part.partition("=")
                tags[key.strip().lower()] = value.strip()
        policy = tags.get("p", "none").lower()
        details["dmarc_policy"] = policy
        details["dmarc_pct"] = tags.get("pct", "100")
        details["dmarc_rua"] = bool(tags.get("rua"))
        evidence = [Evidence("DMARC record", dmarc[:255], source)]

        if policy in ("reject", "quarantine"):
            return CheckResult(
                check_type=CheckType.DNS_DMARC,
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                summary=f"The vendor enforces DMARC with a policy of {policy}.",
                source=source,
                details=details,
                evidence=evidence,
            )
        return CheckResult(
            check_type=CheckType.DNS_DMARC,
            status=CheckStatus.WARN,
            severity=Severity.LOW,
            summary=(
                "The vendor publishes DMARC in monitoring mode only (p=none), so spoofed "
                "email is still delivered."
            ),
            title="DMARC is not enforced",
            recommendation=(
                "Ask the vendor when they plan to move DMARC to p=quarantine or p=reject."
            ),
            source=source,
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------ DKIM
    def _dkim(self, records: DnsRecords, source: str) -> CheckResult:
        if records.dkim:
            selector, record = next(iter(records.dkim.items()))
            return CheckResult(
                check_type=CheckType.DNS_DKIM,
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                summary=f"A DKIM signing key was found (selector '{selector}').",
                source=source,
                details={
                    "dkim_status": "found",
                    "selector": selector,
                    "selectors_checked": records.dkim_selectors_checked,
                },
                evidence=[Evidence(f"DKIM selector {selector}", record[:180], source)],
            )
        # No selector found. DKIM selectors are not enumerable from DNS, so this
        # is genuinely inconclusive — never reported as a failure.
        return CheckResult(
            check_type=CheckType.DNS_DKIM,
            status=CheckStatus.UNKNOWN,
            severity=Severity.INFO,
            summary=(
                "DKIM could not be assessed. DKIM keys are published under a selector name "
                "that cannot be discovered from DNS, so absence here does not mean DKIM is "
                "missing."
            ),
            source=source,
            details={
                "dkim_status": "not_assessed",
                "selectors_checked": records.dkim_selectors_checked,
                "assessed": False,
            },
            confidence=0.0,
            provider_status="not_assessed",
        )

    # ------------------------------------------------------------------ CAA
    def _caa(self, records: DnsRecords, source: str) -> CheckResult:
        if records.caa:
            return CheckResult(
                check_type=CheckType.DNS_CAA,
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                summary="The vendor restricts which authorities may issue certificates (CAA).",
                source=source,
                details={"caa_present": True, "caa_records": records.caa[:5]},
                evidence=[Evidence("CAA record", records.caa[0][:180], source)],
            )
        return CheckResult(
            check_type=CheckType.DNS_CAA,
            status=CheckStatus.WARN,
            severity=Severity.LOW,
            summary=(
                "The vendor has no CAA record, so any certificate authority may issue "
                "certificates for their domain."
            ),
            title="No CAA record published",
            recommendation=(
                "Optional hardening. A CAA record limits which certificate authorities can "
                "issue for the domain."
            ),
            source=source,
            details={"caa_present": False},
        )
