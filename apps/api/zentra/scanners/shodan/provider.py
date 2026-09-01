"""Internet-exposure provider (Shodan).

Only Shodan's passive host API is used: we read what Shodan already published
about an address. Zentra never connects to, probes, or authenticates against
any discovered service.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import httpx

from zentra.config import get_settings
from zentra.errors import UnsafeTargetError
from zentra.logging import get_logger
from zentra.scanners.provider import Provider, ProviderResult, ProviderStatus, deterministic_seed

log = get_logger("zentra.scanner.shodan")


@dataclass
class ExposedService:
    port: int
    transport: str = "tcp"
    product: str | None = None
    version: str | None = None
    service: str | None = None
    cpe: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)


@dataclass
class ExposureReport:
    domain: str
    ip_address: str | None = None
    organization: str | None = None
    country: str | None = None
    hostnames: list[str] = field(default_factory=list)
    services: list[ExposedService] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    last_update: str | None = None

    @property
    def open_ports(self) -> list[int]:
        return sorted({s.port for s in self.services})

    @property
    def all_vulns(self) -> list[str]:
        seen: list[str] = []
        for service in self.services:
            for vuln in service.vulns:
                if vuln not in seen:
                    seen.append(vuln)
        return seen


#: Ports that should not normally be reachable from the public internet on a
#: SaaS vendor's production edge.
SENSITIVE_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    111: "RPC portmapper",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    2375: "Docker API (unencrypted)",
    2376: "Docker API",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    7001: "WebLogic",
    8020: "Hadoop",
    9200: "Elasticsearch",
    9300: "Elasticsearch transport",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
}

CRITICAL_PORTS = frozenset({23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017})


class ExposureProvider(Provider):
    name = "shodan"

    async def lookup(self, domain: str) -> ProviderResult[ExposureReport]:  # pragma: no cover
        raise NotImplementedError


class ShodanProvider(ExposureProvider):
    """Shodan REST API (`/shodan/host/{ip}`)."""

    name = "shodan"

    def __init__(self, *, api_key: str | None = None, api_url: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key if api_key is not None else settings.shodan_api_key
        self.api_url = (api_url or settings.shodan_api_url).rstrip("/")
        self.timeout = settings.scanner_http_timeout_seconds

    async def lookup(self, domain: str) -> ProviderResult[ExposureReport]:
        if not self.api_key:
            return ProviderResult.not_configured("Shodan")

        from zentra.scanners.net.ssrf import resolve_target

        try:
            target = resolve_target(domain)
        except UnsafeTargetError as exc:
            return ProviderResult(status=ProviderStatus.INVALID_TARGET, error=str(exc))

        ip = str(target.primary)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout), follow_redirects=False, trust_env=False
            ) as client:
                response = await client.get(
                    f"{self.api_url}/shodan/host/{ip}",
                    params={"key": self.api_key, "minify": "false"},
                    headers={"User-Agent": "Zentra-VendorRisk/1.0"},
                )
        except httpx.HTTPError as exc:
            return ProviderResult.unavailable(f"transport: {type(exc).__name__}")

        if response.status_code == 404:
            # Shodan has nothing recorded for this address: a definite negative.
            return ProviderResult(
                status=ProviderStatus.NOT_FOUND,
                data=ExposureReport(domain=domain, ip_address=ip),
            )
        if response.status_code in (401, 403):
            return ProviderResult(
                status=ProviderStatus.NOT_CONFIGURED,
                error="The configured Shodan API key was rejected or lacks access.",
            )
        if response.status_code == 429:
            return ProviderResult(
                status=ProviderStatus.RATE_LIMITED, error="Shodan rate limit reached."
            )
        if response.status_code >= 400:
            return ProviderResult.unavailable(f"http_{response.status_code}")

        try:
            payload = response.json()
        except ValueError:
            return ProviderResult.unavailable("malformed_json")
        if not isinstance(payload, dict):
            return ProviderResult.unavailable("unexpected_payload")

        report = ExposureReport(
            domain=domain,
            ip_address=ip,
            organization=_clean(payload.get("org")),
            country=_clean(payload.get("country_code")),
            hostnames=[str(h)[:253] for h in (payload.get("hostnames") or [])][:20],
            tags=[str(t)[:40] for t in (payload.get("tags") or [])][:20],
            last_update=_clean(payload.get("last_update")),
        )
        for item in payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            raw_port = item.get("port")
            try:
                port = int(raw_port)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            report.services.append(
                ExposedService(
                    port=port,
                    transport=str(item.get("transport", "tcp"))[:10],
                    product=_clean(item.get("product")),
                    version=_clean(item.get("version")),
                    service=_clean(item.get("_shodan", {}).get("module"))
                    if isinstance(item.get("_shodan"), dict)
                    else None,
                    cpe=[str(c)[:120] for c in (item.get("cpe23") or item.get("cpe") or [])][:10],
                    vulns=sorted(item.get("vulns") or {})[:25]
                    if isinstance(item.get("vulns"), dict)
                    else [str(v)[:30] for v in (item.get("vulns") or [])][:25],
                )
            )
        return ProviderResult(
            status=ProviderStatus.OK,
            data=report,
            provider_timestamp=report.last_update,
        )


def _clean(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:200] or None


class MockExposureProvider(ExposureProvider):
    """Deterministic synthetic exposure data."""

    name = "shodan"
    is_mock = True

    SCRIPTED: dict[str, str] = {}

    async def lookup(self, domain: str) -> ProviderResult[ExposureReport]:
        scenario = self.SCRIPTED.get(domain)
        seed = deterministic_seed("shodan", domain)
        rng = random.Random(seed)  # noqa: S311 - deterministic fixtures, not crypto
        if scenario is None:
            scenario = rng.choices(
                ["clean", "web_only", "ssh_exposed", "database_exposed", "unavailable"],
                weights=[30, 34, 18, 11, 7],
            )[0]

        if scenario == "unavailable":
            return ProviderResult.unavailable("mock: exposure provider unavailable")

        report = ExposureReport(
            domain=domain,
            ip_address=f"203.0.113.{seed % 254 + 1}",
            organization="Synthetic Cloud Ltd (demo data)",
            country="GB",
            hostnames=[domain],
            tags=["cloud"],
            last_update="2026-01-01T00:00:00.000000",
        )
        if scenario == "clean":
            return ProviderResult(status=ProviderStatus.NOT_FOUND, data=report)

        report.services.append(
            ExposedService(port=443, product="nginx", version="1.24.0", service="https")
        )
        report.services.append(
            ExposedService(port=80, product="nginx", version="1.24.0", service="http")
        )
        if scenario == "ssh_exposed":
            report.services.append(
                ExposedService(port=22, product="OpenSSH", version="8.9p1", service="ssh")
            )
        elif scenario == "database_exposed":
            report.services.append(
                ExposedService(port=22, product="OpenSSH", version="7.4", service="ssh")
            )
            report.services.append(
                ExposedService(
                    port=6379,
                    product="Redis",
                    version="6.0.9",
                    service="redis",
                    vulns=["CVE-2022-0543"],
                )
            )
        return ProviderResult(
            status=ProviderStatus.OK,
            data=report,
            provider_timestamp=report.last_update,
            meta={"mock": True, "scenario": scenario},
        )


def get_exposure_provider() -> ExposureProvider:
    return MockExposureProvider() if get_settings().use_mock_scanners else ShodanProvider()
