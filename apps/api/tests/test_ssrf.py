"""SSRF protection.

These tests are the security backbone of the scanner: Zentra accepts arbitrary
domains from unauthenticated users, so every one of these must hold.
"""

from __future__ import annotations

import ipaddress
from unittest.mock import patch

import pytest

from zentra.errors import InvalidDomainError, UnsafeTargetError
from zentra.scanners.net.ssrf import (
    METADATA_ADDRESSES,
    SsrfBlocked,
    assert_public_ip,
    is_public_ip,
    resolve_target,
    safe_getaddrinfo,
)


@pytest.mark.parametrize(
    "address",
    [
        # IPv4 loopback and private space
        "127.0.0.1",
        "127.1.2.3",
        "127.255.255.254",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.20.10.5",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        # Link-local and cloud metadata
        "169.254.0.1",
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        # Carrier-grade NAT, reserved, multicast, broadcast
        "100.64.0.1",
        "0.0.0.0",
        "0.1.2.3",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "192.0.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        # IPv6 loopback, unspecified, private, link-local, multicast
        "::1",
        "::",
        "fc00::1",
        "fd12:3456:789a::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "2001:db8::1",
        "fd00:ec2::254",
        # IPv4-mapped and 6to4 encapsulation of private space
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "2002:7f00:0001::",
        "2002:a00:1::",
    ],
)
def test_blocks_non_public_addresses(address: str) -> None:
    assert is_public_ip(address) is False
    with pytest.raises(UnsafeTargetError):
        assert_public_ip(address)


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "2a00:1450:4009:80f::200e"],
)
def test_allows_public_addresses(address: str) -> None:
    assert is_public_ip(address) is True
    assert assert_public_ip(address) == ipaddress.ip_address(address)


def test_every_known_metadata_address_is_blocked() -> None:
    for address in METADATA_ADDRESSES:
        assert is_public_ip(address) is False


def test_rejects_garbage_addresses() -> None:
    for value in ["not-an-ip", "", "999.999.999.999", "1.2.3", "::gg"]:
        assert is_public_ip(value) is False
        with pytest.raises(SsrfBlocked):
            assert_public_ip(value)


class _FakeRecord:
    def __init__(self, value: str) -> None:
        self._value = value

    def __str__(self) -> str:
        return self._value


def _fake_resolver(mapping: dict[str, list[str]]):
    class _Resolver:
        timeout = 5.0
        lifetime = 5.0

        def resolve(self, name: str, rdtype: str):
            key = f"{name}:{rdtype}"
            if key not in mapping:
                import dns.resolver

                raise dns.resolver.NoAnswer()
            return [_FakeRecord(v) for v in mapping[key]]

    return _Resolver()


def test_resolve_target_accepts_public_records() -> None:
    with patch(
        "zentra.scanners.net.ssrf._resolver",
        return_value=_fake_resolver({"example.com:A": ["93.184.216.34"]}),
    ):
        target = resolve_target("example.com")
    assert target.domain == "example.com"
    assert str(target.primary) == "93.184.216.34"


def test_resolve_target_rejects_private_record() -> None:
    with (
        patch(
            "zentra.scanners.net.ssrf._resolver",
            return_value=_fake_resolver({"evil.test-domain.com:A": ["10.0.0.5"]}),
        ),
        pytest.raises(UnsafeTargetError),
    ):
        resolve_target("evil.test-domain.com")


def test_resolve_target_fails_closed_on_mixed_records() -> None:
    """A rebinding record set that mixes public and private must be rejected.

    Accepting the public record and discarding the private one would let an
    attacker win the race on a later lookup.
    """
    with (
        patch(
            "zentra.scanners.net.ssrf._resolver",
            return_value=_fake_resolver({"rebind.example.com:A": ["93.184.216.34", "127.0.0.1"]}),
        ),
        pytest.raises(UnsafeTargetError),
    ):
        resolve_target("rebind.example.com")


def test_resolve_target_rejects_private_ipv6_alongside_public_ipv4() -> None:
    with (
        patch(
            "zentra.scanners.net.ssrf._resolver",
            return_value=_fake_resolver(
                {"dual.example.com:A": ["93.184.216.34"], "dual.example.com:AAAA": ["::1"]}
            ),
        ),
        pytest.raises(UnsafeTargetError),
    ):
        resolve_target("dual.example.com")


def test_resolve_target_rejects_nxdomain() -> None:
    with (
        patch("zentra.scanners.net.ssrf._resolver", return_value=_fake_resolver({})),
        pytest.raises(UnsafeTargetError),
    ):
        resolve_target("nothing-here.example.com")


@pytest.mark.parametrize(
    "domain",
    ["localhost", "127.0.0.1", "metadata.google.internal", "foo.internal", "10.0.0.1"],
)
def test_resolve_target_rejects_before_dns(domain: str) -> None:
    """Blocked names must never even reach the resolver."""
    with patch("zentra.scanners.net.ssrf._resolver") as resolver:
        with pytest.raises((UnsafeTargetError, InvalidDomainError)):
            resolve_target(domain)
        resolver.assert_not_called()


def test_safe_getaddrinfo_returns_only_validated_addresses() -> None:
    with patch(
        "zentra.scanners.net.ssrf._resolver",
        return_value=_fake_resolver({"example.com:A": ["93.184.216.34"]}),
    ):
        infos = safe_getaddrinfo("example.com", 443)
    assert len(infos) == 1
    assert infos[0][4][0] == "93.184.216.34"


def test_safe_getaddrinfo_rejects_private() -> None:
    with (
        patch(
            "zentra.scanners.net.ssrf._resolver",
            return_value=_fake_resolver({"internal.example.com:A": ["192.168.1.1"]}),
        ),
        pytest.raises(UnsafeTargetError),
    ):
        safe_getaddrinfo("internal.example.com", 443)


@pytest.mark.anyio
async def test_safe_client_rejects_disallowed_scheme() -> None:
    from zentra.scanners.net.ssrf import SafeAsyncClient

    async with SafeAsyncClient() as client:
        for url in ["file:///etc/passwd", "gopher://example.com/", "ftp://example.com/"]:
            with pytest.raises(SsrfBlocked):
                await client.get(url)


@pytest.mark.anyio
async def test_safe_client_rejects_disallowed_port() -> None:
    from zentra.scanners.net.ssrf import SafeAsyncClient

    async with SafeAsyncClient() as client:
        with pytest.raises(SsrfBlocked):
            await client.get("http://example.com:6379/")


@pytest.mark.anyio
async def test_safe_client_rejects_private_ip_literal() -> None:
    from zentra.scanners.net.ssrf import SafeAsyncClient

    async with SafeAsyncClient() as client:
        for url in ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"]:
            with pytest.raises(SsrfBlocked):
                await client.get(url)
