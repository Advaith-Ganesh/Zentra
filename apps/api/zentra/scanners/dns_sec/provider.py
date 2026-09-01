"""DNS record retrieval.

The real provider uses dnspython against the host's configured resolvers. The
mock provider returns deterministic synthetic records so the whole product runs
offline.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import dns.exception
import dns.rdatatype
import dns.resolver

from zentra.config import get_settings
from zentra.scanners.provider import Provider, ProviderResult, ProviderStatus, deterministic_seed


@dataclass
class DnsRecords:
    txt: list[str] = field(default_factory=list)
    dmarc_txt: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    #: selector -> record, only for selectors we actually probed
    dkim: dict[str, str] = field(default_factory=dict)
    #: selectors probed that returned nothing
    dkim_selectors_checked: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


#: DKIM selectors are not discoverable from DNS in general — there is no record
#: that enumerates them. We probe a short list of selectors used by common mail
#: platforms. A miss means "not assessed", never "missing".
COMMON_DKIM_SELECTORS = (
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mandrill",
    "dkim",
    "default",
    "zoho",
    "fm1",
    "mail",
)


class DnsProvider(Provider):
    name = "dns"

    async def lookup(self, domain: str) -> ProviderResult[DnsRecords]:  # pragma: no cover
        raise NotImplementedError


class SystemDnsProvider(DnsProvider):
    """Live DNS lookups via dnspython."""

    name = "dns"

    def __init__(self, *, timeout: float | None = None, selectors: tuple[str, ...] | None = None):
        settings = get_settings()
        self.timeout = timeout or min(settings.scanner_http_timeout_seconds, 8.0)
        self.selectors = selectors or COMMON_DKIM_SELECTORS

    def _resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        return resolver

    def _query(self, resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str] | None:
        """Return records, or None when the lookup itself failed."""
        try:
            answer = resolver.resolve(name, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
            return None
        values: list[str] = []
        for record in answer:
            if rdtype == "TXT":
                # TXT strings may be split into multiple chunks; join them.
                chunks = getattr(record, "strings", None)
                if chunks:
                    values.append(b"".join(chunks).decode("utf-8", errors="replace"))
                else:
                    values.append(str(record).strip('"'))
            else:
                values.append(str(record))
        return values

    async def lookup(self, domain: str) -> ProviderResult[DnsRecords]:
        import asyncio

        return await asyncio.to_thread(self._lookup_sync, domain)

    def _lookup_sync(self, domain: str) -> ProviderResult[DnsRecords]:
        resolver = self._resolver()
        records = DnsRecords()
        hard_failures = 0

        txt = self._query(resolver, domain, "TXT")
        if txt is None:
            hard_failures += 1
            records.errors.append("TXT lookup failed")
        else:
            records.txt = txt

        dmarc = self._query(resolver, f"_dmarc.{domain}", "TXT")
        if dmarc is None:
            hard_failures += 1
            records.errors.append("DMARC lookup failed")
        else:
            records.dmarc_txt = dmarc

        caa = self._query(resolver, domain, "CAA")
        if caa is not None:
            records.caa = caa

        mx = self._query(resolver, domain, "MX")
        if mx is not None:
            records.mx = mx

        for selector in self.selectors:
            found = self._query(resolver, f"{selector}._domainkey.{domain}", "TXT")
            records.dkim_selectors_checked.append(selector)
            if found:
                records.dkim[selector] = found[0]
                break

        if hard_failures >= 2:
            return ProviderResult(
                status=ProviderStatus.UNAVAILABLE,
                data=records,
                error="DNS resolution failed for this domain.",
            )
        return ProviderResult(status=ProviderStatus.OK, data=records)


class MockDnsProvider(DnsProvider):
    """Deterministic synthetic DNS records."""

    name = "dns"
    is_mock = True

    SCRIPTED: dict[str, str] = {}

    async def lookup(self, domain: str) -> ProviderResult[DnsRecords]:
        scenario = self.SCRIPTED.get(domain)
        seed = deterministic_seed("dns", domain)
        rng = random.Random(seed)  # noqa: S311 - deterministic fixtures, not crypto
        if scenario is None:
            scenario = rng.choices(
                ["strong", "monitor_only", "no_dmarc", "no_spf", "unavailable"],
                weights=[35, 25, 22, 13, 5],
            )[0]

        records = DnsRecords(mx=[f"10 mx.{domain}."])
        if scenario == "unavailable":
            return ProviderResult(
                status=ProviderStatus.UNAVAILABLE,
                data=records,
                error="mock: DNS resolver unavailable",
            )

        if scenario != "no_spf":
            records.txt = [f"v=spf1 include:_spf.{domain} -all"]
        else:
            records.txt = ["zentra-demo-verification=synthetic"]

        if scenario == "strong":
            records.dmarc_txt = [f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}; pct=100"]
            records.dkim = {"selector1": "v=DKIM1; k=rsa; p=MIIBIjAN...synthetic"}
            records.caa = ['0 issue "letsencrypt.org"']
        elif scenario == "monitor_only":
            records.dmarc_txt = [f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}"]
            records.dkim = {"google": "v=DKIM1; k=rsa; p=MIIBIjAN...synthetic"}
        elif scenario == "no_dmarc":
            records.dmarc_txt = []
        else:  # no_spf
            records.dmarc_txt = [f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"]

        records.dkim_selectors_checked = list(COMMON_DKIM_SELECTORS)
        return ProviderResult(
            status=ProviderStatus.OK, data=records, meta={"mock": True, "scenario": scenario}
        )


def get_dns_provider() -> DnsProvider:
    return MockDnsProvider() if get_settings().use_mock_scanners else SystemDnsProvider()
