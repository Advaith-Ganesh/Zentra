"""TLS/SSL scanner."""

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
from zentra.scanners.ssl_labs.provider import TlsAssessment, TlsProvider, get_tls_provider

#: Certificate lifetime thresholds, in days.
EXPIRY_CRITICAL_DAYS = 0
EXPIRY_HIGH_DAYS = 7
EXPIRY_WARN_DAYS = 30

_GRADE_SEVERITY: dict[str, Severity] = {
    "A+": Severity.INFO,
    "A": Severity.INFO,
    "A-": Severity.LOW,
    "B": Severity.LOW,
    "C": Severity.MEDIUM,
    "D": Severity.HIGH,
    "E": Severity.HIGH,
    "F": Severity.HIGH,
    "T": Severity.HIGH,  # certificate not trusted
    "M": Severity.HIGH,  # hostname mismatch
}


class SSLScanner(BaseScanner):
    """Assesses the certificate and the TLS configuration of a domain."""

    name = "ssl"
    display_name = "TLS/SSL configuration"
    check_types = (CheckType.TLS_CERTIFICATE, CheckType.TLS_CONFIGURATION)
    timeout_seconds = 200.0
    included_in_public_scan = True

    def __init__(self, provider: TlsProvider | None = None, **options: object) -> None:
        super().__init__(**options)
        self.provider = provider or get_tls_provider()

    async def run(self, context: ScanContext) -> list[CheckResult]:
        result = await self.provider.assess(context.domain)
        source = self.provider.source_label

        if result.status is ProviderStatus.INVALID_TARGET:
            return [
                CheckResult(
                    check_type=CheckType.TLS_CERTIFICATE,
                    status=CheckStatus.UNKNOWN,
                    severity=Severity.INFO,
                    summary=(
                        "No HTTPS service could be assessed for this domain. "
                        "This may be expected if the domain does not host a website."
                    ),
                    source=source,
                    details={"assessed": False, "reason": result.error},
                    confidence=0.0,
                    provider_status=result.status.value,
                )
            ]
        if not result.ok or result.data is None:
            return [
                self.error_result(None, provider_status=result.status.value),
            ]

        assessment = result.data
        return [
            self._certificate_check(assessment, source, result.provider_timestamp),
            self._configuration_check(assessment, source, result.provider_timestamp),
        ]

    # ------------------------------------------------------------------ checks
    def _certificate_check(
        self, a: TlsAssessment, source: str, provider_ts: str | None
    ) -> CheckResult:
        evidence: list[Evidence] = []
        if a.certificate_expires_at:
            evidence.append(Evidence("Certificate expires", a.certificate_expires_at, source))
        if a.certificate_issuer:
            evidence.append(Evidence("Issuer", a.certificate_issuer, source))

        days = a.days_until_expiry
        blocking = [
            w
            for w in a.weaknesses
            if w
            in {
                "Certificate expired",
                "Hostname mismatch",
                "Self-signed certificate",
                "Certificate revoked",
                "No chain of trust",
                "Certificate not yet valid",
                "Insecure key",
                "Insecure signature",
                "Blacklisted certificate",
                "Bad common name",
            }
        ]

        if blocking:
            return CheckResult(
                check_type=CheckType.TLS_CERTIFICATE,
                status=CheckStatus.FAIL,
                severity=Severity.CRITICAL if "Certificate expired" in blocking else Severity.HIGH,
                summary=(
                    "The vendor's TLS certificate has a serious problem: "
                    + "; ".join(blocking).lower()
                    + "."
                ),
                title="TLS certificate is not trustworthy",
                recommendation=(
                    "Ask the vendor to reissue and install a valid certificate from a trusted "
                    "certificate authority, and confirm it covers this hostname."
                ),
                source=source,
                details={
                    "issues": blocking,
                    "expires_at": a.certificate_expires_at,
                    "days_until_expiry": days,
                    "issuer": a.certificate_issuer,
                    "provider_timestamp": provider_ts,
                },
                evidence=evidence,
                confidence=1.0,
            )

        if days is not None and days <= EXPIRY_CRITICAL_DAYS:
            return CheckResult(
                check_type=CheckType.TLS_CERTIFICATE,
                status=CheckStatus.FAIL,
                severity=Severity.CRITICAL,
                summary="The vendor's TLS certificate has expired.",
                title="Expired TLS certificate",
                recommendation=(
                    "Contact the vendor and ask them to renew the certificate. Until it is "
                    "renewed, browsers and API clients will show security warnings."
                ),
                source=source,
                details={"expires_at": a.certificate_expires_at, "days_until_expiry": days},
                evidence=evidence,
            )
        if days is not None and days <= EXPIRY_HIGH_DAYS:
            return CheckResult(
                check_type=CheckType.TLS_CERTIFICATE,
                status=CheckStatus.WARN,
                severity=Severity.HIGH,
                summary=f"The vendor's TLS certificate expires in {days} days.",
                title="TLS certificate expiring imminently",
                recommendation="Ask the vendor to confirm their certificate renewal process.",
                source=source,
                details={"expires_at": a.certificate_expires_at, "days_until_expiry": days},
                evidence=evidence,
            )
        if days is not None and days <= EXPIRY_WARN_DAYS:
            return CheckResult(
                check_type=CheckType.TLS_CERTIFICATE,
                status=CheckStatus.WARN,
                severity=Severity.LOW,
                summary=f"The vendor's TLS certificate expires in {days} days.",
                title="TLS certificate expiring soon",
                recommendation="No action needed yet; re-check if it is not renewed shortly.",
                source=source,
                details={"expires_at": a.certificate_expires_at, "days_until_expiry": days},
                evidence=evidence,
            )

        return CheckResult(
            check_type=CheckType.TLS_CERTIFICATE,
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            summary=(
                "The vendor's TLS certificate is valid"
                + (f" and expires in {days} days." if days is not None else ".")
            ),
            source=source,
            details={
                "expires_at": a.certificate_expires_at,
                "days_until_expiry": days,
                "issuer": a.certificate_issuer,
            },
            evidence=evidence,
        )

    def _configuration_check(
        self, a: TlsAssessment, source: str, provider_ts: str | None
    ) -> CheckResult:
        evidence: list[Evidence] = []
        if a.grade:
            evidence.append(Evidence("TLS grade", a.grade, source))
        if a.protocols:
            evidence.append(Evidence("Supported protocols", ", ".join(a.protocols), source))
        if a.weak_ciphers:
            evidence.append(Evidence("Weak cipher suites", ", ".join(a.weak_ciphers[:5]), source))

        config_weaknesses = [
            w
            for w in a.weaknesses
            if w
            not in {
                "Certificate expired",
                "Hostname mismatch",
                "Self-signed certificate",
                "Certificate revoked",
                "No chain of trust",
                "Certificate not yet valid",
            }
        ]
        details = {
            "grade": a.grade,
            "protocols": a.protocols,
            "weak_protocols": a.weak_protocols,
            "weak_ciphers": a.weak_ciphers,
            "forward_secrecy": a.forward_secrecy,
            "weaknesses": config_weaknesses,
            "endpoint_count": a.endpoint_count,
            "provider_timestamp": provider_ts,
            "provider_metadata": a.provider_metadata,
        }

        if a.grade is None:
            return self.not_assessed(
                CheckType.TLS_CONFIGURATION,
                "The TLS configuration could not be graded.",
                reason="no_grade_returned",
            )

        severity = _GRADE_SEVERITY.get(a.grade, Severity.MEDIUM)
        if a.weak_protocols and severity.rank < Severity.MEDIUM.rank:
            severity = Severity.MEDIUM
        if a.weak_ciphers and severity.rank < Severity.MEDIUM.rank:
            severity = Severity.MEDIUM

        if severity.rank >= Severity.HIGH.rank:
            status = CheckStatus.FAIL
        elif severity.rank >= Severity.LOW.rank:
            status = CheckStatus.WARN
        else:
            status = CheckStatus.PASS

        if status is CheckStatus.PASS:
            summary = f"The vendor's TLS configuration is strong (grade {a.grade})."
            recommendation = None
            title = None
        else:
            problems: list[str] = []
            if a.weak_protocols:
                problems.append(
                    "supports outdated protocol versions (" + ", ".join(a.weak_protocols) + ")"
                )
            if a.weak_ciphers:
                problems.append("offers weak cipher suites")
            if a.forward_secrecy is False:
                problems.append("does not provide forward secrecy")
            if config_weaknesses:
                problems.append("has known weaknesses: " + ", ".join(config_weaknesses[:3]).lower())
            detail = "; ".join(problems) if problems else f"scores grade {a.grade}"
            summary = f"The vendor's TLS configuration {detail}."
            title = f"Weak TLS configuration (grade {a.grade})"
            recommendation = (
                "Ask the vendor to disable TLS 1.0/1.1 and legacy cipher suites, and to enable "
                "forward secrecy. This is a standard hardening request most providers can action."
            )

        return CheckResult(
            check_type=CheckType.TLS_CONFIGURATION,
            status=status,
            severity=severity,
            summary=summary,
            title=title,
            recommendation=recommendation,
            source=source,
            details=details,
            evidence=evidence,
        )
