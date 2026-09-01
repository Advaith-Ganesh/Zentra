"""CVE intelligence provider.

Real implementation queries the NIST National Vulnerability Database (NVD)
REST API 2.0 by CPE name. Only technologies whose version was explicitly
declared by the vendor's own server are looked up: a technology with an unknown
version produces no CVE claim at all.

**Unknown is never vulnerable.** Zentra will not assert that a vendor is
affected by a CVE it cannot tie to a stated version.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import httpx

from zentra.config import get_settings
from zentra.logging import get_logger
from zentra.scanners.provider import Provider, ProviderResult, ProviderStatus, deterministic_seed

log = get_logger("zentra.scanner.cve")


@dataclass
class Vulnerability:
    cve_id: str
    severity: str  # critical | high | medium | low | unknown
    cvss_score: float | None
    description: str
    published_date: str | None
    source: str
    technology: str
    technology_version: str | None
    #: How confident we are that this vendor is actually affected.
    confidence: float = 0.5
    reference_url: str | None = None


@dataclass
class VulnerabilityReport:
    domain: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    technologies_queried: list[str] = field(default_factory=list)
    technologies_skipped_unknown_version: list[str] = field(default_factory=list)
    last_checked_at: str | None = None

    def by_severity(self, level: str) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if v.severity == level]


class CveProvider(Provider):
    name = "cve"

    async def lookup(
        self, domain: str, technologies: list[tuple[str, str | None]], known_cve_ids: list[str]
    ) -> ProviderResult[VulnerabilityReport]:  # pragma: no cover
        raise NotImplementedError


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class NvdProvider(CveProvider):
    """NIST NVD REST API 2.0."""

    name = "nvd"

    def __init__(self, *, api_key: str | None = None, api_url: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key if api_key is not None else settings.nvd_api_key
        self.api_url = (api_url or settings.nvd_api_url).rstrip("/")
        self.timeout = settings.scanner_http_timeout_seconds
        # NVD asks unauthenticated clients to stay under ~5 requests / 30s.
        self.max_queries = 3 if not self.api_key else 8

    async def lookup(
        self, domain: str, technologies: list[tuple[str, str | None]], known_cve_ids: list[str]
    ) -> ProviderResult[VulnerabilityReport]:
        from datetime import UTC, datetime

        report = VulnerabilityReport(domain=domain, last_checked_at=datetime.now(UTC).isoformat())
        headers = {"User-Agent": "Zentra-VendorRisk/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        queries: list[tuple[str, str | None, dict[str, str]]] = []
        # CVE IDs surfaced directly by the exposure provider are high confidence:
        # they were attributed to an observed service banner.
        for cve_id in known_cve_ids[: self.max_queries]:
            queries.append((cve_id, None, {"cveId": cve_id}))
        remaining = self.max_queries - len(queries)
        for name, version in technologies:
            if remaining <= 0:
                break
            if not version:
                report.technologies_skipped_unknown_version.append(name)
                continue
            cpe = f"cpe:2.3:a:*:{name.lower()}:{version}:*:*:*:*:*:*:*"
            queries.append((name, version, {"cpeName": cpe, "resultsPerPage": "20"}))
            report.technologies_queried.append(f"{name} {version}")
            remaining -= 1

        if not queries:
            return ProviderResult(status=ProviderStatus.NOT_FOUND, data=report)

        errors = 0
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout), follow_redirects=False, trust_env=False
            ) as client:
                for label, version, params in queries:
                    try:
                        response = await client.get(
                            f"{self.api_url}/cves/2.0", params=params, headers=headers
                        )
                    except httpx.HTTPError:
                        errors += 1
                        continue
                    if response.status_code == 429:
                        return ProviderResult(
                            status=ProviderStatus.RATE_LIMITED,
                            data=report,
                            error="NVD rate limit reached.",
                        )
                    if response.status_code >= 400:
                        errors += 1
                        continue
                    try:
                        payload = response.json()
                    except ValueError:
                        errors += 1
                        continue
                    self._collect(report, payload, label, version)
        except Exception as exc:  # noqa: BLE001
            return ProviderResult.unavailable(f"transport: {type(exc).__name__}")

        if errors and errors == len(queries):
            return ProviderResult.unavailable("all NVD queries failed")
        status = ProviderStatus.OK if report.vulnerabilities else ProviderStatus.NOT_FOUND
        return ProviderResult(status=status, data=report, meta={"query_errors": errors})

    @staticmethod
    def _collect(
        report: VulnerabilityReport, payload: object, technology: str, version: str | None
    ) -> None:
        if not isinstance(payload, dict):
            return
        for item in payload.get("vulnerabilities") or []:
            cve = (item or {}).get("cve") or {}
            cve_id = str(cve.get("id", ""))[:30]
            if not cve_id or any(v.cve_id == cve_id for v in report.vulnerabilities):
                continue
            descriptions = cve.get("descriptions") or []
            description = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
            )
            metrics = cve.get("metrics") or {}
            score: float | None = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key) or []
                if entries:
                    data = (entries[0] or {}).get("cvssData") or {}
                    raw = data.get("baseScore")
                    if isinstance(raw, int | float):
                        score = float(raw)
                        break
            report.vulnerabilities.append(
                Vulnerability(
                    cve_id=cve_id,
                    severity=_severity_from_cvss(score),
                    cvss_score=score,
                    description=description[:600],
                    published_date=cve.get("published"),
                    source="NIST NVD",
                    technology=technology,
                    technology_version=version,
                    # Version-matched CPE results are still only an indication
                    # that the declared version is affected, not proof of
                    # exploitability in the vendor's deployment.
                    confidence=0.7 if version else 0.85,
                    reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                )
            )


class MockCveProvider(CveProvider):
    """Deterministic synthetic CVE data."""

    name = "nvd"
    is_mock = True

    SCRIPTED: dict[str, str] = {}

    async def lookup(
        self, domain: str, technologies: list[tuple[str, str | None]], known_cve_ids: list[str]
    ) -> ProviderResult[VulnerabilityReport]:
        from datetime import UTC, datetime, timedelta

        report = VulnerabilityReport(domain=domain, last_checked_at=datetime.now(UTC).isoformat())
        versioned = [(n, v) for n, v in technologies if v]
        report.technologies_skipped_unknown_version = [n for n, v in technologies if not v]
        report.technologies_queried = [f"{n} {v}" for n, v in versioned]

        scenario = self.SCRIPTED.get(domain)
        if scenario is None:
            if not versioned and not known_cve_ids:
                # Nothing to look up: honestly, no claim.
                return ProviderResult(status=ProviderStatus.NOT_FOUND, data=report)
            seed = deterministic_seed("cve", domain)
            rng = random.Random(seed)  # noqa: S311 - deterministic fixtures, not crypto
            scenario = rng.choices(
                ["none", "medium", "high", "critical", "unavailable"],
                weights=[38, 24, 20, 12, 6],
            )[0]

        if scenario == "unavailable":
            return ProviderResult.unavailable("mock: CVE provider unavailable")
        if scenario == "none":
            return ProviderResult(status=ProviderStatus.NOT_FOUND, data=report)

        tech, version = versioned[0] if versioned else ("observed service", None)
        now = datetime.now(UTC)
        spec = {
            "medium": (5.3, "medium", 1),
            "high": (7.5, "high", 1),
            "critical": (9.8, "critical", 2),
        }[scenario]
        score, severity, count = spec
        for index in range(count):
            report.vulnerabilities.append(
                Vulnerability(
                    cve_id=f"CVE-2024-{10000 + (deterministic_seed('cve', domain) + index) % 8999}",
                    severity=severity,
                    cvss_score=score,
                    description=(
                        "Synthetic demo vulnerability record generated by Zentra's mock CVE "
                        "provider. It does not describe a real vulnerability in any real product."
                    ),
                    published_date=(now - timedelta(days=90 + index * 45)).date().isoformat(),
                    source="Zentra mock CVE provider (synthetic demo data)",
                    technology=tech,
                    technology_version=version,
                    confidence=0.7,
                    reference_url=None,
                )
            )
        return ProviderResult(
            status=ProviderStatus.OK, data=report, meta={"mock": True, "scenario": scenario}
        )


def get_cve_provider() -> CveProvider:
    return MockCveProvider() if get_settings().use_mock_scanners else NvdProvider()
