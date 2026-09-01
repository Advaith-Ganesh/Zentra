"""Domain normalization and validation."""

from __future__ import annotations

import pytest

from zentra.core.domains import is_valid_domain, normalize_domain, registrable_root
from zentra.errors import InvalidDomainError


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.com", "example.com"),
        ("  EXAMPLE.COM  ", "example.com"),
        ("example.com.", "example.com"),
        ("https://example.com/path?q=1", "example.com"),
        ("http://sub.example.co.uk", "sub.example.co.uk"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("a-b-c.example.org", "a-b-c.example.org"),
    ],
)
def test_normalizes_valid_domains(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "localhost",
        "LOCALHOST",
        "localhost.localdomain",
        "ip6-localhost",
        "metadata.google.internal",
        "instance-data",
        "host.docker.internal",
        "kubernetes.default",
        "app.local",
        "server.internal",
        "db.lan",
        "site.test",
        "thing.example",
        "x.invalid",
        "abc.onion",
        "svc.cluster.local",
        "1.0.0.127.in-addr.arpa",
    ],
)
def test_rejects_internal_hostnames(raw: str) -> None:
    with pytest.raises(InvalidDomainError):
        normalize_domain(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "[::1]",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
        "8.8.8.8",
    ],
)
def test_rejects_ip_literals(raw: str) -> None:
    with pytest.raises(InvalidDomainError):
        normalize_domain(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "example",
        "exa mple.com",
        ".com",
        "example..com",
        "-example.com",
        "example-.com",
        "example.c",
        "example.123",
        "example.com:8080",
        "user:pass@example.com",
        "example.com/../etc/passwd",
        "example.com\\admin",
        "exam\x00ple.com",
        "example.com\nHost: evil.com",
        "a" * 64 + ".com",
        "a" * 400 + ".com",
        "'; DROP TABLE vendors; --",
        "<script>alert(1)</script>",
        "example.com?x=<img src=x onerror=alert(1)>",
    ],
)
def test_rejects_malformed_input(raw: str) -> None:
    assert is_valid_domain(raw) is False


def test_rejects_non_string() -> None:
    with pytest.raises(InvalidDomainError):
        normalize_domain(None)  # type: ignore[arg-type]


def test_url_form_drops_credentials() -> None:
    # A URL with userinfo resolves to its host; credentials are discarded.
    assert normalize_domain("https://user:secret@example.com/admin") == "example.com"


@pytest.mark.parametrize(
    ("domain", "root"),
    [
        ("example.com", "example.com"),
        ("api.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("example.co.uk", "example.co.uk"),
    ],
)
def test_registrable_root(domain: str, root: str) -> None:
    assert registrable_root(domain) == root
