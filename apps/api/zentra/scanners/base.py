"""The scanner contract.

Every security signal Zentra collects is produced by a :class:`BaseScanner`
subclass and returned as one or more :class:`CheckResult` objects. The
normalized shape is what the scoring engine, the findings generator and the
report renderer all consume, so adding a provider never requires touching them.

The single most important invariant in this file:

    A provider failure produces ``CheckStatus.ERROR`` or
    ``CheckStatus.UNKNOWN`` — never ``CheckStatus.FAIL``.

An outage is missing information, not evidence of a security weakness.
"""

from __future__ import annotations

import abc
import asyncio
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from zentra.logging import get_logger

log = get_logger("zentra.scanner")


class CheckStatus(StrEnum):
    PASS = "pass"  # noqa: S105 - a check outcome, not a credential
    WARN = "warn"
    FAIL = "fail"
    #: The check ran but could not reach a conclusion (e.g. DKIM without a
    #: known selector). Explicitly *not* a failure.
    UNKNOWN = "unknown"
    #: The provider could not be reached, or returned an unusable response.
    ERROR = "error"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class CheckType(StrEnum):
    """Stable identifiers used in the database, the API and the UI."""

    TLS_CERTIFICATE = "tls_certificate"
    TLS_CONFIGURATION = "tls_configuration"
    DNS_SPF = "dns_spf"
    DNS_DMARC = "dns_dmarc"
    DNS_DKIM = "dns_dkim"
    DNS_CAA = "dns_caa"
    BREACH_HISTORY = "breach_history"
    INTERNET_EXPOSURE = "internet_exposure"
    TECHNOLOGY_STACK = "technology_stack"
    CVE_EXPOSURE = "cve_exposure"
    HTTP_SECURITY_HEADERS = "http_security_headers"


@dataclass(frozen=True)
class Evidence:
    """A single piece of supporting data with explicit provenance."""

    label: str
    value: str
    source: str
    observed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class CheckResult:
    """Normalized output of a single security check."""

    check_type: CheckType
    status: CheckStatus
    severity: Severity
    summary: str
    source: str
    details: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    #: 0.0–1.0. How much weight the scoring engine should place on this signal.
    confidence: float = 1.0
    #: Raw provider status string, e.g. "ok", "rate_limited", "no_api_key".
    provider_status: str = "ok"
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int | None = None
    #: Populated by the scanner when this check should raise a tracked finding.
    recommendation: str | None = None
    title: str | None = None

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        # Defensive: an inconclusive check can never carry a risk severity.
        if (
            self.status in (CheckStatus.ERROR, CheckStatus.UNKNOWN)
            and self.severity.rank > Severity.INFO.rank
        ):
            self.severity = Severity.INFO

    @property
    def is_conclusive(self) -> bool:
        return self.status in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL)

    @property
    def is_problem(self) -> bool:
        return self.status in (CheckStatus.WARN, CheckStatus.FAIL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_type": self.check_type.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "details": self.details,
            "evidence": [e.to_dict() for e in self.evidence],
            "source": self.source,
            "confidence": round(self.confidence, 3),
            "provider_status": self.provider_status,
            "checked_at": self.checked_at.isoformat(),
            "duration_ms": self.duration_ms,
            "recommendation": self.recommendation,
            "title": self.title,
        }


@dataclass(frozen=True)
class ScanContext:
    """Everything a scanner is allowed to know about the job."""

    domain: str
    vendor_id: str | None = None
    organization_id: str | None = None
    scan_id: str | None = None
    #: Public/free scans run a reduced, cheaper check set.
    limited: bool = False


class BaseScanner(abc.ABC):
    """Base class for all security signal collectors.

    Subclasses implement :meth:`run`. The orchestrator calls :meth:`execute`,
    which adds timing, a hard timeout and a guaranteed-normalized error result
    so a misbehaving provider can never take down a scan.
    """

    #: Stable machine name, used in logs and configuration.
    name: str = "base"
    #: Human label shown in the UI.
    display_name: str = "Base scanner"
    #: The check types this scanner may emit.
    check_types: tuple[CheckType, ...] = ()
    #: Per-scanner wall-clock budget in seconds.
    timeout_seconds: float = 30.0
    #: Whether this scanner participates in the reduced public/free scan.
    included_in_public_scan: bool = False
    #: Number of attempts for transient failures.
    max_attempts: int = 2
    retry_backoff_seconds: float = 1.0

    def __init__(self, **options: Any) -> None:
        self.options = options

    @abc.abstractmethod
    async def run(self, context: ScanContext) -> list[CheckResult]:
        """Perform the check. May raise; :meth:`execute` normalizes failures."""

    async def execute(self, context: ScanContext) -> list[CheckResult]:
        started = time.perf_counter()
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                results = await asyncio.wait_for(self.run(context), timeout=self.timeout_seconds)
                elapsed = int((time.perf_counter() - started) * 1000)
                for result in results:
                    if result.duration_ms is None:
                        result.duration_ms = elapsed
                log.info(
                    "scanner_completed",
                    scanner=self.name,
                    domain=context.domain,
                    checks=len(results),
                    duration_ms=elapsed,
                    attempt=attempt,
                )
                return results
            except TimeoutError as exc:
                last_error = exc
                log.warning(
                    "scanner_timeout", scanner=self.name, domain=context.domain, attempt=attempt
                )
            except Exception as exc:  # noqa: BLE001 - deliberate: normalize everything
                last_error = exc
                log.warning(
                    "scanner_failed",
                    scanner=self.name,
                    domain=context.domain,
                    attempt=attempt,
                    error_type=type(exc).__name__,
                )
                if not self._is_retryable(exc):
                    break
            if attempt < self.max_attempts:
                await asyncio.sleep(self.retry_backoff_seconds * (2 ** (attempt - 1)))

        elapsed = int((time.perf_counter() - started) * 1000)
        return [self.error_result(last_error, duration_ms=elapsed)]

    def _is_retryable(self, exc: Exception) -> bool:
        from zentra.errors import InvalidDomainError, UnsafeTargetError

        # Never retry a rejected target or a malformed domain.
        return not isinstance(exc, UnsafeTargetError | InvalidDomainError)

    # ------------------------------------------------------------------ helpers
    def error_result(
        self,
        error: Exception | None,
        *,
        duration_ms: int | None = None,
        provider_status: str = "unavailable",
    ) -> CheckResult:
        """A normalized "we could not assess this" result.

        Deliberately ``ERROR``/``INFO``: never a security failure.
        """
        primary = self.check_types[0] if self.check_types else CheckType.TECHNOLOGY_STACK
        reason = type(error).__name__ if error else "unknown"
        return CheckResult(
            check_type=primary,
            status=CheckStatus.ERROR,
            severity=Severity.INFO,
            summary=f"{self.display_name} could not be assessed (data source unavailable).",
            source=self.name,
            details={"error_type": reason, "assessed": False},
            confidence=0.0,
            provider_status=provider_status,
            duration_ms=duration_ms,
        )

    def not_assessed(
        self, check_type: CheckType, summary: str, *, reason: str = "not_assessed"
    ) -> CheckResult:
        """A check that ran but reached no conclusion. Not a failure."""
        return CheckResult(
            check_type=check_type,
            status=CheckStatus.UNKNOWN,
            severity=Severity.INFO,
            summary=summary,
            source=self.name,
            details={"reason": reason, "assessed": False},
            confidence=0.0,
            provider_status="not_assessed",
        )


__all__ = [
    "BaseScanner",
    "CheckResult",
    "CheckStatus",
    "CheckType",
    "Evidence",
    "ScanContext",
    "Severity",
]
