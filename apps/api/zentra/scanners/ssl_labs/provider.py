"""SSL/TLS assessment providers.

Real implementation talks to the public Qualys SSL Labs API v3. That API is an
asynchronous job API: you submit a host, then poll until it reports ``READY``.
It is also heavily rate limited, so we poll with exponential backoff, respect
its documented cool-off responses, and give up cleanly within a fixed budget.

If the assessment cannot be completed the result is ``UNAVAILABLE`` — never a
TLS failure.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from zentra.config import get_settings
from zentra.errors import UnsafeTargetError
from zentra.logging import get_logger
from zentra.scanners.provider import Provider, ProviderResult, ProviderStatus, deterministic_seed

log = get_logger("zentra.scanner.ssl")


@dataclass
class TlsAssessment:
    """Normalized TLS assessment, independent of the upstream provider."""

    grade: str | None = None
    host: str = ""
    certificate_valid: bool | None = None
    certificate_expires_at: str | None = None
    days_until_expiry: int | None = None
    certificate_issuer: str | None = None
    certificate_subject: str | None = None
    self_signed: bool | None = None
    hostname_mismatch: bool | None = None
    revoked: bool | None = None
    protocols: list[str] = field(default_factory=list)
    weak_protocols: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    forward_secrecy: bool | None = None
    weaknesses: list[str] = field(default_factory=list)
    endpoint_count: int = 0
    provider_metadata: dict[str, Any] = field(default_factory=dict)


class TlsProvider(Provider):
    name = "tls"

    async def assess(self, domain: str) -> ProviderResult[TlsAssessment]:  # pragma: no cover
        raise NotImplementedError


# --------------------------------------------------------------------------- real
#: Protocol versions we consider weak. TLS 1.0/1.1 are deprecated (RFC 8996).
WEAK_PROTOCOLS = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}

#: SSL Labs endpoint-detail flags that map to a named weakness.
_VULN_FLAGS: dict[str, str] = {
    "heartbleed": "Heartbleed (CVE-2014-0160)",
    "poodle": "POODLE (SSLv3)",
    "poodleTls": "POODLE over TLS",
    "freak": "FREAK",
    "logjam": "Logjam",
    "drownVulnerable": "DROWN",
    "ticketbleed": "Ticketbleed",
    "bleichenbacher": "ROBOT / Bleichenbacher oracle",
    "supportsRc4": "RC4 cipher support",
    "vulnBeast": "BEAST",
}

# SSL Labs certificate `issues` bit field (documented in the API guide).
_CERT_ISSUE_BITS: list[tuple[int, str]] = [
    (1, "No chain of trust"),
    (2, "Certificate not yet valid"),
    (4, "Certificate expired"),
    (8, "Hostname mismatch"),
    (16, "Certificate revoked"),
    (32, "Bad common name"),
    (64, "Self-signed certificate"),
    (128, "Blacklisted certificate"),
    (256, "Insecure signature"),
    (512, "Insecure key"),
]


class SslLabsProvider(TlsProvider):
    """Qualys SSL Labs API v3 client."""

    name = "ssllabs"

    def __init__(self, *, api_url: str | None = None, max_poll_seconds: int | None = None) -> None:
        settings = get_settings()
        self.api_url = (api_url or settings.ssllabs_api_url).rstrip("/")
        self.max_poll_seconds = max_poll_seconds or settings.ssllabs_max_poll_seconds
        self.timeout = settings.scanner_http_timeout_seconds

    async def assess(self, domain: str) -> ProviderResult[TlsAssessment]:
        from zentra.scanners.net.ssrf import resolve_target

        try:
            # Validate the target before we ask a third party to look at it.
            resolve_target(domain)
        except UnsafeTargetError as exc:
            return ProviderResult(status=ProviderStatus.INVALID_TARGET, error=str(exc))

        deadline = time.monotonic() + self.max_poll_seconds
        params: dict[str, str] = {
            "host": domain,
            "all": "done",
            "fromCache": "on",
            "maxAge": "24",
            "ignoreMismatch": "off",
        }
        delay = 5.0
        attempt = 0
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": "Zentra-Scanner/1.0"},
        ) as client:
            while time.monotonic() < deadline:
                attempt += 1
                try:
                    response = await client.get(f"{self.api_url}/analyze", params=params)
                except httpx.HTTPError as exc:
                    return ProviderResult.unavailable(f"transport: {type(exc).__name__}")

                if response.status_code == 429:
                    return ProviderResult(
                        status=ProviderStatus.RATE_LIMITED,
                        error="SSL Labs rate limit reached.",
                    )
                if response.status_code in (503, 529):
                    # Documented "service overloaded / cool-off" responses.
                    await asyncio.sleep(min(delay, max(deadline - time.monotonic(), 0)))
                    delay = min(delay * 2, 30.0)
                    continue
                if response.status_code >= 400:
                    return ProviderResult.unavailable(f"http_{response.status_code}")

                try:
                    payload = response.json()
                except ValueError:
                    return ProviderResult.unavailable("malformed_json")

                status = str(payload.get("status", "")).upper()
                if status == "READY":
                    return ProviderResult(
                        status=ProviderStatus.OK,
                        data=self._normalize(domain, payload),
                        provider_timestamp=str(payload.get("testTime") or ""),
                        meta={"attempts": attempt, "engine": payload.get("engineVersion")},
                    )
                if status == "ERROR":
                    message = str(payload.get("statusMessage", "assessment error"))
                    # SSL Labs reports unresolvable/unreachable hosts as ERROR.
                    return ProviderResult(status=ProviderStatus.INVALID_TARGET, error=message[:200])
                # DNS / IN_PROGRESS -> keep polling, and stop re-submitting.
                params.pop("startNew", None)
                await asyncio.sleep(min(delay, max(deadline - time.monotonic(), 0)))
                delay = min(delay * 1.6, 20.0)

        return ProviderResult(
            status=ProviderStatus.UNAVAILABLE,
            error="SSL Labs assessment did not complete within the allotted time.",
        )

    @staticmethod
    def _normalize(domain: str, payload: dict[str, Any]) -> TlsAssessment:
        endpoints = payload.get("endpoints") or []
        certs = payload.get("certs") or []
        assessment = TlsAssessment(host=domain, endpoint_count=len(endpoints))

        grades = [e.get("grade") for e in endpoints if e.get("grade")]
        if grades:
            # Report the worst grade across endpoints.
            assessment.grade = max(grades, key=_grade_rank)

        if certs:
            leaf = certs[0]
            not_after = leaf.get("notAfter")
            if isinstance(not_after, int | float):
                from datetime import UTC, datetime

                expiry = datetime.fromtimestamp(not_after / 1000, tz=UTC)
                assessment.certificate_expires_at = expiry.isoformat()
                assessment.days_until_expiry = (expiry - datetime.now(UTC)).days
            assessment.certificate_issuer = leaf.get("issuerSubject")
            assessment.certificate_subject = leaf.get("subject")
            issues = int(leaf.get("issues") or 0)
            named = [label for bit, label in _CERT_ISSUE_BITS if issues & bit]
            assessment.weaknesses.extend(named)
            assessment.self_signed = bool(issues & 64)
            assessment.hostname_mismatch = bool(issues & 8)
            assessment.revoked = bool(issues & 16)
            assessment.certificate_valid = issues == 0

        protocols: set[str] = set()
        weak_ciphers: set[str] = set()
        forward_secrecy: bool | None = None
        for endpoint in endpoints:
            details = endpoint.get("details") or {}
            for proto in details.get("protocols") or []:
                label = f"{proto.get('name', '')} {proto.get('version', '')}".strip()
                if label:
                    protocols.add(label)
            for flag, label in _VULN_FLAGS.items():
                value = details.get(flag)
                if value is True or (isinstance(value, int) and value > 0 and flag != "vulnBeast"):
                    assessment.weaknesses.append(label)
            fs = details.get("forwardSecrecy")
            if isinstance(fs, int):
                # bit 2 = "with modern browsers", bit 4 = "with most browsers"
                forward_secrecy = bool(fs & 4) or bool(fs & 2)
            for suite_group in details.get("suites") or []:
                for suite in suite_group.get("list") or []:
                    name = suite.get("name", "")
                    if any(bad in name for bad in ("RC4", "NULL", "EXPORT", "DES-", "MD5")):
                        weak_ciphers.add(name)

        assessment.protocols = sorted(protocols)
        assessment.weak_protocols = sorted(p for p in protocols if p in WEAK_PROTOCOLS)
        assessment.weak_ciphers = sorted(weak_ciphers)[:10]
        assessment.forward_secrecy = forward_secrecy
        assessment.weaknesses = sorted(set(assessment.weaknesses))
        assessment.provider_metadata = {
            "engine_version": payload.get("engineVersion"),
            "criteria_version": payload.get("criteriaVersion"),
            "test_time": payload.get("testTime"),
            "endpoint_count": len(endpoints),
        }
        return assessment


_GRADE_ORDER = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"]


def _grade_rank(grade: str) -> int:
    try:
        return _GRADE_ORDER.index(grade)
    except ValueError:
        return len(_GRADE_ORDER)


# --------------------------------------------------------------------------- mock
class MockTlsProvider(TlsProvider):
    """Deterministic offline TLS assessment for local development and tests.

    Results are synthetic and derived from a hash of the domain, so a given
    domain always produces the same outcome. They are clearly labelled as
    synthetic wherever they surface.
    """

    name = "ssllabs"
    is_mock = True

    #: Domains forced into a specific outcome, for fixtures and demos.
    SCRIPTED: dict[str, str] = {}

    async def assess(self, domain: str) -> ProviderResult[TlsAssessment]:
        outcome = self.SCRIPTED.get(domain)
        seed = deterministic_seed("tls", domain)
        rng = random.Random(seed)  # noqa: S311 - deterministic fixtures, not crypto
        if outcome is None:
            outcome = rng.choices(
                ["excellent", "good", "expiring", "weak_protocol", "expired", "unavailable"],
                weights=[35, 30, 12, 12, 6, 5],
            )[0]

        if outcome == "unavailable":
            return ProviderResult.unavailable("mock: provider temporarily unavailable")

        from datetime import UTC, datetime, timedelta

        base = TlsAssessment(host=domain, endpoint_count=1 + (seed % 2))
        now = datetime.now(UTC)

        if outcome == "excellent":
            expiry = now + timedelta(days=200 + (seed % 100))
            base.grade = "A+"
            base.certificate_valid = True
            base.protocols = ["TLS 1.2", "TLS 1.3"]
            base.forward_secrecy = True
        elif outcome == "good":
            expiry = now + timedelta(days=60 + (seed % 90))
            base.grade = "A"
            base.certificate_valid = True
            base.protocols = ["TLS 1.2", "TLS 1.3"]
            base.forward_secrecy = True
        elif outcome == "expiring":
            expiry = now + timedelta(days=7 + (seed % 14))
            base.grade = "A"
            base.certificate_valid = True
            base.protocols = ["TLS 1.2", "TLS 1.3"]
            base.forward_secrecy = True
        elif outcome == "weak_protocol":
            expiry = now + timedelta(days=120)
            base.grade = "C"
            base.certificate_valid = True
            base.protocols = ["TLS 1.0", "TLS 1.1", "TLS 1.2"]
            base.weak_protocols = ["TLS 1.0", "TLS 1.1"]
            base.weak_ciphers = ["TLS_RSA_WITH_RC4_128_SHA"]
            base.weaknesses = ["RC4 cipher support"]
            base.forward_secrecy = False
        else:  # expired
            expiry = now - timedelta(days=3 + (seed % 30))
            base.grade = "T"
            base.certificate_valid = False
            base.protocols = ["TLS 1.2"]
            base.weaknesses = ["Certificate expired"]
            base.forward_secrecy = True

        base.certificate_expires_at = expiry.isoformat()
        base.days_until_expiry = (expiry - now).days
        base.certificate_issuer = "CN=Zentra Demo CA, O=Zentra (synthetic), C=GB"
        base.certificate_subject = f"CN={domain}"
        base.self_signed = False
        base.hostname_mismatch = False
        base.revoked = False
        base.provider_metadata = {"mock": True, "scenario": outcome}
        return ProviderResult(
            status=ProviderStatus.OK,
            data=base,
            provider_timestamp=now.isoformat(),
            meta={"mock": True, "scenario": outcome},
        )


def get_tls_provider() -> TlsProvider:
    return MockTlsProvider() if get_settings().use_mock_scanners else SslLabsProvider()
