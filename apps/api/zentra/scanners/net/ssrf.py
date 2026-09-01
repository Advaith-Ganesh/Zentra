"""SSRF protection for outbound scanning.

Zentra accepts arbitrary domains from users and then makes outbound requests
about them. Everything in this module exists to guarantee that a user-supplied
name can never cause Zentra to talk to a host we do not intend to reach.

Controls implemented here:

* Domain syntax/validation happens first (:mod:`zentra.core.domains`).
* DNS resolution is performed **once**, and every returned A/AAAA record is
  checked. If *any* record points at non-public address space the target is
  rejected outright — this is the fail-closed behaviour that defeats a
  round-robin "one public, one private" rebinding record set.
* The validated IP is then **pinned** for the actual connection: we connect to
  the literal address and pass the original hostname for SNI and the Host
  header. The resolver is therefore never consulted a second time, which closes
  the TOCTOU window a classic DNS-rebinding attack relies on.
* Redirects are never followed automatically. Each hop is re-validated through
  the same path before it is followed, and the hop count is bounded.
* Only http/https on ports 80/443 are permitted.
* Response bodies are size-capped and all requests are time-bounded.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any, Literal

import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

from zentra.config import get_settings
from zentra.core.domains import normalize_domain
from zentra.errors import UnsafeTargetError
from zentra.logging import get_logger

log = get_logger("zentra.ssrf")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})
MAX_REDIRECTS = 3

# Explicit deny list on top of the stdlib `is_global` checks. Some of these are
# already covered by `is_global`; they are repeated so that a future stdlib
# behaviour change cannot silently open a hole.
_DENIED_V4_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",  # RFC1918
        "100.64.0.0/10",  # CGNAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, incl. 169.254.169.254 cloud metadata
        "172.16.0.0/12",  # RFC1918
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # TEST-NET-1
        "192.88.99.0/24",  # 6to4 relay anycast
        "192.168.0.0/16",  # RFC1918
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved
        "255.255.255.255/32",  # broadcast
    )
)

_DENIED_V6_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "::/128",  # unspecified
        "::1/128",  # loopback
        "::ffff:0:0/96",  # IPv4-mapped
        "::ffff:0:0:0/96",  # IPv4-mapped (alt)
        "64:ff9b::/96",  # NAT64
        "100::/64",  # discard-only
        "2001::/23",  # IETF protocol assignments
        "2001:2::/48",  # benchmarking
        "2001:db8::/32",  # documentation
        "fc00::/7",  # unique local (private)
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
        "fec0::/10",  # deprecated site-local
    )
)

# Well-known cloud instance-metadata endpoints, denied by address as well as by
# the network rules above.
METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)


class SsrfBlocked(UnsafeTargetError):
    """A target was rejected by the SSRF guard."""


def _reason_for(ip: IPAddress) -> str | None:
    """Return a denial reason, or None when the address may be contacted."""
    if str(ip) in METADATA_ADDRESSES:
        return "cloud instance metadata endpoint"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            inner = _reason_for(ip.ipv4_mapped)
            return inner or "IPv4-mapped IPv6 address"
        if ip.sixtofour is not None:
            inner = _reason_for(ip.sixtofour)
            if inner:
                return f"6to4 tunnel to {inner}"
        for net in _DENIED_V6_NETWORKS:
            if ip in net:
                return f"reserved IPv6 range {net}"
    else:
        for net in _DENIED_V4_NETWORKS:
            if ip in net:
                return f"reserved IPv4 range {net}"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_private:
        return "private address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_unspecified:
        return "unspecified address"
    if not ip.is_global:
        return "non-globally-routable address"
    return None


def is_public_ip(value: str | IPAddress) -> bool:
    """True when the address is safe to contact from the scanner."""
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    if get_settings().allow_private_scan_targets:
        return True
    return _reason_for(ip) is None


def assert_public_ip(value: str | IPAddress) -> IPAddress:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise SsrfBlocked("The supplied address is not a valid IP address.") from exc
    if get_settings().allow_private_scan_targets:
        return ip
    reason = _reason_for(ip)
    if reason:
        # The user-facing message deliberately omits the resolved address so we
        # do not turn the scanner into an internal-network oracle.
        log.warning("ssrf_blocked", reason=reason)
        raise SsrfBlocked("This domain resolves to a network that Zentra will not contact.")
    return ip


@dataclass(frozen=True)
class ResolvedTarget:
    """A domain that has passed validation, with its pinned addresses."""

    domain: str
    addresses: tuple[IPAddress, ...]
    families: tuple[str, ...] = field(default=())

    @property
    def primary(self) -> IPAddress:
        return self.addresses[0]


def _resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def resolve_target(domain: str, *, timeout: float | None = None) -> ResolvedTarget:
    """Validate ``domain`` and resolve it to a set of vetted public addresses.

    Raises :class:`SsrfBlocked` if the name does not resolve, or if *any*
    resolved address is outside public address space.
    """
    settings = get_settings()
    timeout = timeout or min(settings.scanner_http_timeout_seconds, 10.0)
    host = normalize_domain(domain)
    resolver = _resolver(timeout)

    addresses: list[IPAddress] = []
    families: list[str] = []
    errors: list[str] = []
    for rdtype, family in (("A", "ipv4"), ("AAAA", "ipv6")):
        try:
            answer = resolver.resolve(host, rdtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            errors.append(f"{rdtype}: {type(exc).__name__}")
            continue
        for record in answer:
            ip = assert_public_ip(str(record))
            addresses.append(ip)
            families.append(family)

    if not addresses:
        detail = f" ({'; '.join(errors)})" if errors else ""
        raise SsrfBlocked(f"The domain does not resolve to any address{detail}.")

    return ResolvedTarget(
        domain=host, addresses=tuple(addresses), families=tuple(dict.fromkeys(families))
    )


class SafeAsyncClient:
    """An httpx client that only ever connects to pre-validated public IPs.

    Usage::

        async with SafeAsyncClient() as client:
            response = await client.get("https://example.com/.well-known/x")
    """

    def __init__(
        self,
        *,
        timeout: float | None = None,
        max_bytes: int | None = None,
        headers: dict[str, str] | None = None,
        verify: bool = True,
    ) -> None:
        settings = get_settings()
        self._timeout = timeout or settings.scanner_http_timeout_seconds
        self._max_bytes = max_bytes or settings.scanner_max_response_bytes
        self._headers = {
            "User-Agent": "Zentra-Scanner/1.0 (+https://zentra.example/security)",
            "Accept": "*/*",
            **(headers or {}),
        }
        self._verify = verify
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> SafeAsyncClient:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout, connect=min(self._timeout, 8.0)),
            follow_redirects=False,
            verify=self._verify,
            headers=self._headers,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            trust_env=False,
        )
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method: Literal["GET", "HEAD", "POST"],
        url: str,
        *,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        if self._client is None:  # pragma: no cover - programming error
            raise RuntimeError("SafeAsyncClient must be used as an async context manager")

        current = url
        for hop in range(MAX_REDIRECTS + 1):
            response = await self._request_once(method, current, **kwargs)
            if not (allow_redirects and 300 <= response.status_code < 400):
                return response
            location = response.headers.get("location")
            if not location:
                return response
            current = str(httpx.URL(current).join(location))
            log.debug("ssrf_redirect", hop=hop, status=response.status_code)
        raise SsrfBlocked("Too many redirects while contacting the target.")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def _request_once(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        assert self._client is not None
        parsed = httpx.URL(url)
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise SsrfBlocked(f"Scheme {scheme!r} is not permitted.")
        host = parsed.host
        if not host:
            raise SsrfBlocked("The target URL has no host.")
        port = parsed.port or (443 if scheme == "https" else 80)
        if port not in ALLOWED_PORTS:
            raise SsrfBlocked(f"Port {port} is not permitted.")

        # If the URL already carries an IP literal, validate it directly.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            target = resolve_target(host)
            pinned = target.primary
            pinned_host = target.domain
        else:
            pinned = assert_public_ip(host)
            pinned_host = host

        literal = f"[{pinned}]" if isinstance(pinned, ipaddress.IPv6Address) else str(pinned)
        pinned_url = parsed.copy_with(host=literal, port=port)
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Host"] = pinned_host if port in (80, 443) else f"{pinned_host}:{port}"

        response = await self._client.request(
            method,
            pinned_url,
            headers=headers,
            # SNI and certificate verification still use the real hostname.
            extensions={"sni_hostname": pinned_host},
            **kwargs,
        )
        if len(response.content) > self._max_bytes:
            raise SsrfBlocked("The target returned an oversized response.")
        return response


def safe_getaddrinfo(host: str, port: int) -> list[tuple[Any, ...]]:
    """`socket.getaddrinfo` restricted to vetted public addresses.

    Used by the TLS scanner, which needs a raw socket rather than HTTP.
    """
    target = resolve_target(host)
    infos: list[tuple[Any, ...]] = []
    for ip in target.addresses:
        family = socket.AF_INET6 if isinstance(ip, ipaddress.IPv6Address) else socket.AF_INET
        sockaddr: tuple[Any, ...] = (
            (str(ip), port, 0, 0) if family == socket.AF_INET6 else (str(ip), port)
        )
        infos.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
    return infos


__all__ = [
    "METADATA_ADDRESSES",
    "ResolvedTarget",
    "SafeAsyncClient",
    "SsrfBlocked",
    "assert_public_ip",
    "is_public_ip",
    "resolve_target",
    "safe_getaddrinfo",
]
