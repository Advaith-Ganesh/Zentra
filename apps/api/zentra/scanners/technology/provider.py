"""Passive technology fingerprinting from HTTP response headers.

This is a deliberately conservative implementation: it reads what the server
volunteers in its own response headers and nothing more. No content probing,
no path enumeration, no version guessing.

A version is only recorded when the server states it explicitly. "Unknown
version" is recorded as unknown — it is never inferred, and unknown is never
treated as vulnerable.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

from zentra.config import get_settings
from zentra.errors import UnsafeTargetError
from zentra.logging import get_logger
from zentra.scanners.provider import Provider, ProviderResult, ProviderStatus, deterministic_seed

log = get_logger("zentra.scanner.tech")


@dataclass
class Technology:
    name: str
    version: str | None = None
    category: str = "unknown"
    #: 0.0-1.0. Header-declared versions are high confidence; anything inferred
    #: from a fingerprint pattern is not.
    confidence: float = 0.5
    evidence: str = ""


@dataclass
class TechnologyProfile:
    domain: str
    url: str | None = None
    status_code: int | None = None
    technologies: list[Technology] = field(default_factory=list)
    security_headers: dict[str, str | None] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    server_header: str | None = None


#: Response headers that materially reduce common web attack classes.
SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS (forces HTTPS)",
    "content-security-policy": "Content Security Policy (limits script injection)",
    "x-content-type-options": "X-Content-Type-Options (blocks MIME sniffing)",
    "x-frame-options": "Clickjacking protection",
    "referrer-policy": "Referrer Policy",
}

_VERSION_RE = re.compile(
    r"^(?P<name>[A-Za-z][A-Za-z0-9 _.\-]{0,40}?)[/ ]v?(?P<version>\d+[\w.\-]*)$"
)


class TechnologyProvider(Provider):
    name = "technology"

    async def profile(self, domain: str) -> ProviderResult[TechnologyProfile]:  # pragma: no cover
        raise NotImplementedError


class HttpHeaderTechnologyProvider(TechnologyProvider):
    """Reads publicly served HTTP response headers through the SSRF-safe client."""

    name = "technology"

    async def profile(self, domain: str) -> ProviderResult[TechnologyProfile]:
        from zentra.scanners.net.ssrf import SafeAsyncClient

        url = f"https://{domain}/"
        try:
            async with SafeAsyncClient() as client:
                response = await client.get(url)
        except UnsafeTargetError as exc:
            return ProviderResult(status=ProviderStatus.INVALID_TARGET, error=str(exc))
        except Exception as exc:  # noqa: BLE001 - any transport problem is "unavailable"
            return ProviderResult.unavailable(f"transport: {type(exc).__name__}")

        headers = {k.lower(): v for k, v in response.headers.items()}
        profile = TechnologyProfile(
            domain=domain,
            url=str(response.url),
            status_code=response.status_code,
            server_header=headers.get("server"),
        )
        for header, _label in SECURITY_HEADERS.items():
            value = headers.get(header)
            profile.security_headers[header] = value
            if not value:
                profile.missing_security_headers.append(header)

        for header_name, category in (
            ("server", "web-server"),
            ("x-powered-by", "application"),
            ("x-generator", "application"),
            ("x-aspnet-version", "framework"),
        ):
            raw = headers.get(header_name)
            if not raw:
                continue
            for token in str(raw).split()[:3]:
                tech = _parse_token(token, category)
                if tech:
                    profile.technologies.append(tech)

        return ProviderResult(status=ProviderStatus.OK, data=profile)


def _parse_token(token: str, category: str) -> Technology | None:
    token = token.strip().strip(",")[:80]
    if not token:
        return None
    match = _VERSION_RE.match(token)
    if match:
        return Technology(
            name=match.group("name").strip(),
            version=match.group("version"),
            category=category,
            # The server declared this version itself.
            confidence=0.9,
            evidence=f"HTTP response header value: {token}",
        )
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.\-]{0,40}", token):
        return Technology(
            name=token,
            version=None,
            category=category,
            confidence=0.5,
            evidence=f"HTTP response header value: {token}",
        )
    return None


class MockTechnologyProvider(TechnologyProvider):
    """Deterministic synthetic technology profile."""

    name = "technology"
    is_mock = True

    SCRIPTED: dict[str, str] = {}

    async def profile(self, domain: str) -> ProviderResult[TechnologyProfile]:
        scenario = self.SCRIPTED.get(domain)
        seed = deterministic_seed("tech", domain)
        rng = random.Random(seed)  # noqa: S311 - deterministic fixtures, not crypto
        if scenario is None:
            scenario = rng.choices(
                ["hardened", "typical", "outdated", "unavailable"], weights=[30, 45, 20, 5]
            )[0]

        if scenario == "unavailable":
            return ProviderResult.unavailable("mock: site unreachable")

        profile = TechnologyProfile(domain=domain, url=f"https://{domain}/", status_code=200)
        if scenario == "hardened":
            profile.server_header = "cloudflare"
            profile.technologies = [
                Technology("cloudflare", None, "cdn", 0.5, "HTTP response header value: cloudflare")
            ]
            present = list(SECURITY_HEADERS)
        elif scenario == "typical":
            profile.server_header = "nginx"
            profile.technologies = [
                Technology("nginx", None, "web-server", 0.5, "HTTP response header value: nginx")
            ]
            present = ["strict-transport-security", "x-content-type-options", "x-frame-options"]
        else:  # outdated
            profile.server_header = "Apache/2.4.49"
            profile.technologies = [
                Technology(
                    "Apache",
                    "2.4.49",
                    "web-server",
                    0.9,
                    "HTTP response header value: Apache/2.4.49",
                ),
                Technology(
                    "PHP", "7.4.3", "application", 0.9, "HTTP response header value: PHP/7.4.3"
                ),
            ]
            present = ["x-content-type-options"]

        for header in SECURITY_HEADERS:
            if header in present:
                profile.security_headers[header] = "present (synthetic demo data)"
            else:
                profile.security_headers[header] = None
                profile.missing_security_headers.append(header)
        return ProviderResult(
            status=ProviderStatus.OK, data=profile, meta={"mock": True, "scenario": scenario}
        )


def get_technology_provider() -> TechnologyProvider:
    return (
        MockTechnologyProvider()
        if get_settings().use_mock_scanners
        else HttpHeaderTechnologyProvider()
    )
