"""Scanner registry.

Adding a provider means adding it here; nothing else in the system needs to
know it exists.
"""

from __future__ import annotations

from collections.abc import Callable

from zentra.core.feature_flags import Flag, is_enabled
from zentra.scanners.base import BaseScanner
from zentra.scanners.cve.scanner import CVEScanner
from zentra.scanners.dns_sec.scanner import DNSScanner
from zentra.scanners.hibp.scanner import HIBPScanner
from zentra.scanners.shodan.scanner import ShodanScanner
from zentra.scanners.ssl_labs.scanner import SSLScanner
from zentra.scanners.technology.scanner import TechnologyScanner

#: Scanners that run in the first pass. They are independent of one another.
PRIMARY_SCANNERS: dict[str, Callable[..., BaseScanner]] = {
    "ssl": SSLScanner,
    "dns": DNSScanner,
    "hibp": HIBPScanner,
    "exposure": ShodanScanner,
    "technology": TechnologyScanner,
}

#: Scanners that consume the output of the first pass.
DEPENDENT_SCANNERS: dict[str, Callable[..., BaseScanner]] = {
    "cve": CVEScanner,
}

#: Scanners only enabled by the advanced-scanners feature flag.
ADVANCED = frozenset({"exposure", "cve"})


def build_primary_scanners(*, limited: bool = False) -> list[BaseScanner]:
    scanners: list[BaseScanner] = []
    for name, factory in PRIMARY_SCANNERS.items():
        if name in ADVANCED and not is_enabled(Flag.ADVANCED_SCANNERS):
            continue
        scanner = factory()
        if limited and not scanner.included_in_public_scan:
            continue
        scanners.append(scanner)
    return scanners


def build_dependent_scanners(*, limited: bool = False, **options: object) -> list[BaseScanner]:
    if limited:
        return []
    scanners: list[BaseScanner] = []
    for name, factory in DEPENDENT_SCANNERS.items():
        if name in ADVANCED and not is_enabled(Flag.ADVANCED_SCANNERS):
            continue
        scanners.append(factory(**options))
    return scanners


def all_scanner_names() -> list[str]:
    return list(PRIMARY_SCANNERS) + list(DEPENDENT_SCANNERS)
