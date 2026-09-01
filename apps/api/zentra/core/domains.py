"""Domain name normalization and validation.

Every user-supplied domain passes through :func:`normalize_domain` before it is
stored or handed to a scanner. This rejects IP literals, credentials, ports,
paths and non-public suffixes early, well before any network activity.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import idna

from zentra.errors import InvalidDomainError

MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
MAX_INPUT_LENGTH = 400

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Hostnames that must never be treated as a scannable public vendor domain.
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "broadcasthost",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "kubernetes",
        "kubernetes.default",
        "host.docker.internal",
        "gateway.docker.internal",
    }
)

# Suffixes reserved for private/internal use (RFC 6762, RFC 8375, RFC 2606).
BLOCKED_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".home.arpa",
    ".lan",
    ".private",
    ".test",
    ".example",
    ".invalid",
    ".onion",
    ".alt",
    ".localdomain",
    ".in-addr.arpa",
    ".ip6.arpa",
    ".cluster.local",
    ".svc.cluster.local",
)


def _strip_scheme_and_path(value: str) -> str:
    candidate = value.strip()
    if "://" in candidate:
        parts = urlsplit(candidate)
        if parts.hostname is None:
            raise InvalidDomainError("The supplied value is not a valid domain name.")
        # `hostname` already drops userinfo and the port.
        return parts.hostname
    # Reject embedded credentials, paths, queries and ports explicitly rather
    # than silently truncating them.
    for marker in ("@", "/", "?", "#", "\\"):
        if marker in candidate:
            raise InvalidDomainError(
                "Enter a bare domain such as example.com (no scheme, path or credentials)."
            )
    if ":" in candidate:
        raise InvalidDomainError(
            "Ports are not permitted; enter a bare domain such as example.com."
        )
    return candidate


def normalize_domain(value: str) -> str:
    """Return the canonical lowercase ASCII (punycode) form of ``value``.

    Raises :class:`InvalidDomainError` for anything that is not a syntactically
    valid, public, non-IP domain name.
    """
    if not isinstance(value, str):
        raise InvalidDomainError("A domain name is required.")
    if len(value) > MAX_INPUT_LENGTH:
        raise InvalidDomainError("The supplied domain is too long.")
    if "\x00" in value or any(ord(c) < 0x20 for c in value):
        raise InvalidDomainError("The supplied domain contains control characters.")

    host = _strip_scheme_and_path(value).strip().strip(".").lower()
    if not host:
        raise InvalidDomainError("A domain name is required.")

    # Bracketed IPv6 literal, e.g. "[::1]".
    if host.startswith("[") and host.endswith("]"):
        raise InvalidDomainError("IP addresses cannot be monitored; supply a domain name.")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise InvalidDomainError("IP addresses cannot be monitored; supply a domain name.")

    # Unicode / IDN -> punycode. `uts46` folds case and normalizes homoglyph
    # sequences consistently.
    try:
        host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise InvalidDomainError("The supplied domain is not a valid domain name.") from exc

    if len(host) > MAX_DOMAIN_LENGTH:
        raise InvalidDomainError("The supplied domain is too long.")

    labels = host.split(".")
    if len(labels) < 2:
        raise InvalidDomainError("Enter a fully qualified domain such as example.com.")
    for label in labels:
        if not label or len(label) > MAX_LABEL_LENGTH or not _LABEL_RE.match(label):
            raise InvalidDomainError("The supplied domain is not a valid domain name.")

    tld = labels[-1]
    if tld.isdigit():
        raise InvalidDomainError("The supplied domain is not a valid domain name.")
    if len(tld) < 2:
        raise InvalidDomainError("The supplied domain is not a valid domain name.")

    if host in BLOCKED_HOSTNAMES:
        raise InvalidDomainError("Internal hostnames cannot be scanned.")
    for suffix in BLOCKED_SUFFIXES:
        if host.endswith(suffix):
            raise InvalidDomainError("Internal or reserved domains cannot be scanned.")

    return host


def is_valid_domain(value: str) -> bool:
    try:
        normalize_domain(value)
    except InvalidDomainError:
        return False
    return True


def registrable_root(domain: str) -> str:
    """Best-effort eTLD+1 for grouping. Not a public-suffix-list lookup.

    Used only for display grouping, never for an authorization decision.
    """
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    two_part_tlds = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz", "co.za", "com.br"}
    if ".".join(labels[-2:]) in two_part_tlds and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
