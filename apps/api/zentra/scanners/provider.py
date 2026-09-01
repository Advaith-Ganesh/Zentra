"""Shared contract for external security-data providers.

Every provider returns a :class:`ProviderResult` rather than raising for the
normal "we could not get an answer" cases. This makes the distinction between
"assessed and clean", "assessed and problematic", and "not assessed" a
structural property rather than something each scanner has to remember.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Generic, TypeVar


class ProviderStatus(StrEnum):
    OK = "ok"
    #: The provider has no record for this target. A definite negative answer.
    NOT_FOUND = "not_found"
    #: The provider is reachable but declined; treat as "not assessed".
    RATE_LIMITED = "rate_limited"
    #: No credential configured for this provider in this environment.
    NOT_CONFIGURED = "not_configured"
    #: Network error, timeout, 5xx, malformed response.
    UNAVAILABLE = "unavailable"
    #: The provider explicitly rejected the target (e.g. invalid host).
    INVALID_TARGET = "invalid_target"

    @property
    def is_conclusive(self) -> bool:
        return self in (ProviderStatus.OK, ProviderStatus.NOT_FOUND)


T = TypeVar("T")


@dataclass
class ProviderResult(Generic[T]):
    status: ProviderStatus
    data: T | None = None
    error: str | None = None
    #: Provider-side timestamp of the underlying data, when exposed.
    provider_timestamp: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status is ProviderStatus.OK

    @property
    def conclusive(self) -> bool:
        return self.status.is_conclusive

    @classmethod
    def unavailable(cls, error: str) -> ProviderResult[T]:
        return cls(status=ProviderStatus.UNAVAILABLE, error=error)

    @classmethod
    def not_configured(cls, provider: str) -> ProviderResult[T]:
        return cls(
            status=ProviderStatus.NOT_CONFIGURED,
            error=f"No API credential configured for {provider}.",
        )


class Provider(abc.ABC):  # noqa: B024 - a marker base; each subclass defines its own contract
    """Marker base class for provider implementations."""

    name: str = "provider"
    #: True for deterministic offline implementations used in dev/CI.
    is_mock: bool = False

    @property
    def source_label(self) -> str:
        return f"{self.name} (synthetic demo data)" if self.is_mock else self.name


def deterministic_seed(*parts: str) -> int:
    """Stable integer seed derived from the inputs.

    Mock providers use this so that a given domain always yields the same
    synthetic result — required for repeatable tests and a coherent demo.
    """
    import hashlib

    digest = hashlib.sha256("|".join(parts).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")
