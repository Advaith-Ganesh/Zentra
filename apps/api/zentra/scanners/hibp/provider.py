"""Have I Been Pwned breach-history provider.

Uses the official HIBP API v3 ``/breaches?domain=`` endpoint, which returns the
publicly catalogued breaches affecting a domain. That endpoint returns breach
*metadata* only — never individual accounts or credentials — which is all
Zentra needs and all it stores.

Requesting the paid ``/breacheddomain/{domain}`` endpoint (which exposes
affected local-parts) is deliberately **not** implemented: it is far more
personal data than a vendor risk score requires.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx

from zentra.config import get_settings
from zentra.logging import get_logger
from zentra.scanners.provider import Provider, ProviderResult, ProviderStatus, deterministic_seed

log = get_logger("zentra.scanner.hibp")


@dataclass
class BreachRecord:
    name: str
    title: str
    breach_date: str | None
    added_date: str | None
    pwn_count: int
    data_classes: list[str] = field(default_factory=list)
    is_verified: bool = True
    is_sensitive: bool = False


@dataclass
class BreachHistory:
    domain: str
    breaches: list[BreachRecord] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.breaches)

    def recent(self, within_days: int = 730) -> list[BreachRecord]:
        cutoff = datetime.now(UTC) - timedelta(days=within_days)
        out = []
        for breach in self.breaches:
            if not breach.breach_date:
                continue
            try:
                when = datetime.fromisoformat(breach.breach_date).replace(tzinfo=UTC)
            except ValueError:
                continue
            if when >= cutoff:
                out.append(breach)
        return out

    @property
    def exposes_credentials(self) -> bool:
        sensitive = {"passwords", "password hints", "security questions and answers", "auth tokens"}
        return any(
            any(dc.lower() in sensitive for dc in breach.data_classes) for breach in self.breaches
        )


class BreachProvider(Provider):
    name = "hibp"

    async def lookup(self, domain: str) -> ProviderResult[BreachHistory]:  # pragma: no cover
        raise NotImplementedError


class HibpProvider(BreachProvider):
    """Have I Been Pwned API v3."""

    name = "hibp"

    def __init__(self, *, api_key: str | None = None, api_url: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key if api_key is not None else settings.hibp_api_key
        self.api_url = (api_url or settings.hibp_api_url).rstrip("/")
        self.timeout = settings.scanner_http_timeout_seconds

    async def lookup(self, domain: str) -> ProviderResult[BreachHistory]:
        if not self.api_key:
            # HIBP requires a key on authenticated endpoints. Without one we
            # report "not configured" — categorically different from "clean".
            return ProviderResult.not_configured("Have I Been Pwned")

        headers = {
            "hibp-api-key": self.api_key,
            # HIBP requires a descriptive user agent and rejects requests without one.
            "User-Agent": "Zentra-VendorRisk/1.0",
            "Accept": "application/json",
        }
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout), follow_redirects=False, trust_env=False
            ) as client:
                response = await client.get(
                    f"{self.api_url}/breaches", params={"domain": domain}, headers=headers
                )
        except httpx.HTTPError as exc:
            return ProviderResult.unavailable(f"transport: {type(exc).__name__}")

        if response.status_code == 404:
            # HIBP returns 404 when the domain has no catalogued breaches.
            return ProviderResult(
                status=ProviderStatus.NOT_FOUND, data=BreachHistory(domain=domain)
            )
        if response.status_code == 401:
            return ProviderResult(
                status=ProviderStatus.NOT_CONFIGURED,
                error="The configured Have I Been Pwned API key was rejected.",
            )
        if response.status_code == 429:
            return ProviderResult(
                status=ProviderStatus.RATE_LIMITED,
                error="Have I Been Pwned rate limit reached.",
                meta={"retry_after": response.headers.get("retry-after")},
            )
        if response.status_code >= 400:
            return ProviderResult.unavailable(f"http_{response.status_code}")

        try:
            payload = response.json()
        except ValueError:
            return ProviderResult.unavailable("malformed_json")
        if not isinstance(payload, list):
            return ProviderResult.unavailable("unexpected_payload")

        history = BreachHistory(domain=domain)
        for item in payload:
            if not isinstance(item, dict):
                continue
            history.breaches.append(
                BreachRecord(
                    name=str(item.get("Name", ""))[:200],
                    title=str(item.get("Title", item.get("Name", "")))[:200],
                    breach_date=item.get("BreachDate"),
                    added_date=item.get("AddedDate"),
                    pwn_count=int(item.get("PwnCount") or 0),
                    data_classes=[str(d)[:80] for d in (item.get("DataClasses") or [])][:20],
                    is_verified=bool(item.get("IsVerified", True)),
                    is_sensitive=bool(item.get("IsSensitive", False)),
                )
            )
        status = ProviderStatus.OK if history.breaches else ProviderStatus.NOT_FOUND
        return ProviderResult(status=status, data=history)


class MockBreachProvider(BreachProvider):
    """Deterministic synthetic breach history."""

    name = "hibp"
    is_mock = True

    SCRIPTED: dict[str, str] = {}

    async def lookup(self, domain: str) -> ProviderResult[BreachHistory]:
        scenario = self.SCRIPTED.get(domain)
        seed = deterministic_seed("hibp", domain)
        rng = random.Random(seed)  # noqa: S311 - deterministic fixtures, not crypto
        if scenario is None:
            scenario = rng.choices(
                ["clean", "old_breach", "recent_breach", "credential_breach", "unavailable"],
                weights=[52, 18, 13, 10, 7],
            )[0]

        if scenario == "unavailable":
            return ProviderResult.unavailable("mock: breach provider unavailable")
        history = BreachHistory(domain=domain)
        if scenario == "clean":
            return ProviderResult(status=ProviderStatus.NOT_FOUND, data=history)

        now = datetime.now(UTC)
        if scenario == "old_breach":
            history.breaches.append(
                BreachRecord(
                    name="SyntheticLegacyIncident",
                    title="Synthetic legacy incident (demo data)",
                    breach_date=(now - timedelta(days=1800 + seed % 400)).date().isoformat(),
                    added_date=(now - timedelta(days=1700)).date().isoformat(),
                    pwn_count=120_000 + seed % 400_000,
                    data_classes=["Email addresses", "Names"],
                )
            )
        elif scenario == "recent_breach":
            history.breaches.append(
                BreachRecord(
                    name="SyntheticRecentIncident",
                    title="Synthetic recent incident (demo data)",
                    breach_date=(now - timedelta(days=120 + seed % 300)).date().isoformat(),
                    added_date=(now - timedelta(days=90)).date().isoformat(),
                    pwn_count=45_000 + seed % 200_000,
                    data_classes=["Email addresses", "IP addresses", "Names"],
                )
            )
        else:  # credential_breach
            history.breaches.append(
                BreachRecord(
                    name="SyntheticCredentialIncident",
                    title="Synthetic credential incident (demo data)",
                    breach_date=(now - timedelta(days=200 + seed % 300)).date().isoformat(),
                    added_date=(now - timedelta(days=150)).date().isoformat(),
                    pwn_count=900_000 + seed % 2_000_000,
                    data_classes=["Email addresses", "Passwords", "Usernames"],
                )
            )
            history.breaches.append(
                BreachRecord(
                    name="SyntheticLegacyIncident",
                    title="Synthetic legacy incident (demo data)",
                    breach_date=(now - timedelta(days=2200)).date().isoformat(),
                    added_date=(now - timedelta(days=2000)).date().isoformat(),
                    pwn_count=80_000,
                    data_classes=["Email addresses"],
                )
            )
        return ProviderResult(
            status=ProviderStatus.OK, data=history, meta={"mock": True, "scenario": scenario}
        )


def get_breach_provider() -> BreachProvider:
    return MockBreachProvider() if get_settings().use_mock_scanners else HibpProvider()
