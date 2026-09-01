"""Redis-backed fixed-window rate limiting with an in-process fallback.

The limiter fails **open** with a logged warning if Redis is unreachable: an
outage of the rate-limit store must not take the whole product offline. Public,
unauthenticated endpoints additionally keep a small in-process limiter so that
a Redis outage cannot remove all protection from them.
"""

from __future__ import annotations

import contextlib
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import redis

from zentra.config import get_settings
from zentra.logging import get_logger

log = get_logger("zentra.ratelimit")


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_after: int

    @property
    def retry_after(self) -> int:
        return max(self.reset_after, 1)


class _LocalWindow:
    """Tiny in-process fixed-window counter used as a fallback."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[int, int]] = {}

    def hit(self, key: str, limit: int, window: int) -> RateLimitResult:
        now = int(time.time())
        slot = now // window
        with self._lock:
            stored_slot, count = self._buckets.get(key, (slot, 0))
            if stored_slot != slot:
                stored_slot, count = slot, 0
            count += 1
            self._buckets[key] = (stored_slot, count)
            if len(self._buckets) > 10_000:  # bound memory
                cutoff = slot - 1
                self._buckets = {k: v for k, v in self._buckets.items() if v[0] >= cutoff}
        reset_after = ((slot + 1) * window) - now
        return RateLimitResult(count <= limit, limit, max(limit - count, 0), reset_after)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


_local = _LocalWindow()


@lru_cache(maxsize=4)
def _redis_client(url: str) -> redis.Redis:
    return redis.Redis.from_url(
        url,
        socket_timeout=1.5,
        socket_connect_timeout=1.5,
        retry_on_timeout=False,
        decode_responses=True,
        health_check_interval=30,
    )


def get_redis() -> redis.Redis:
    return _redis_client(get_settings().redis_url)


def redis_available() -> bool:
    try:
        return bool(get_redis().ping())
    except Exception:  # noqa: BLE001 - readiness probe must not raise
        return False


def check_rate_limit(
    bucket: str,
    identifier: str,
    limit: int,
    window_seconds: int,
    *,
    cost: int = 1,
) -> RateLimitResult:
    """Consume ``cost`` from ``bucket:identifier``.

    Returns a result rather than raising so callers can add headers on both the
    allowed and denied paths.
    """
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return RateLimitResult(True, limit, limit, window_seconds)

    key = f"zentra:rl:{bucket}:{identifier}:{int(time.time()) // window_seconds}"
    try:
        client = get_redis()
        pipe = client.pipeline()
        pipe.incrby(key, cost)
        pipe.expire(key, window_seconds + 1)
        count = int(pipe.execute()[0])
        reset_after = window_seconds - (int(time.time()) % window_seconds)
        return RateLimitResult(count <= limit, limit, max(limit - count, 0), reset_after)
    except Exception as exc:  # noqa: BLE001 - degrade, do not fail the request
        log.warning("ratelimit_backend_unavailable", bucket=bucket, error=type(exc).__name__)
        return _local.hit(f"{bucket}:{identifier}", limit, window_seconds)


def reset_local_state() -> None:
    """Test helper."""
    _local.reset()


def clear_redis_bucket(bucket: str) -> None:
    """Test/ops helper: drop every counter for a bucket."""
    try:
        client = get_redis()
        for key in client.scan_iter(f"zentra:rl:{bucket}:*", count=500):
            client.delete(key)
    except Exception as exc:  # noqa: BLE001
        log.warning("ratelimit_clear_failed", bucket=bucket, error=type(exc).__name__)


# ---------------------------------------------------------------- idempotency
def claim_idempotency_key(namespace: str, key: str, ttl_seconds: int = 86_400) -> bool:
    """Atomically claim ``key``. Returns False when it was already claimed.

    Falls back to allowing the operation when Redis is unavailable; every
    caller that relies on this also has a database-level unique constraint.
    """
    try:
        client = get_redis()
        return bool(client.set(f"zentra:idem:{namespace}:{key}", "1", nx=True, ex=ttl_seconds))
    except Exception as exc:  # noqa: BLE001
        log.warning("idempotency_backend_unavailable", error=type(exc).__name__)
        return True


def release_idempotency_key(namespace: str, key: str) -> None:
    # Best effort. A key that outlives its operation only costs one duplicate
    # suppression, so a Redis blip is not worth surfacing.
    with contextlib.suppress(Exception):
        get_redis().delete(f"zentra:idem:{namespace}:{key}")


def cache_get(key: str) -> str | None:
    try:
        value: Any = get_redis().get(f"zentra:cache:{key}")
        return value if isinstance(value, str) else None
    except Exception:  # noqa: BLE001 - a cache miss is the safe fallback
        return None


def cache_set(key: str, value: str, ttl_seconds: int = 300) -> None:
    # A failed cache write simply means the next read recomputes.
    with contextlib.suppress(Exception):
        get_redis().setex(f"zentra:cache:{key}", ttl_seconds, value)
