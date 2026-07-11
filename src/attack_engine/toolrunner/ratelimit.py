"""RoE-driven rate limiting at the Tool Runner boundary.

A token bucket per ``(tool, target)`` pair. The bucket refills continuously at
``requests_per_sec`` and holds up to ``burst`` tokens. This bounds how hard the
engine hits any single target — a Rules-of-Engagement requirement, not a
nicety. The clock is injectable so tests are deterministic (no ``sleep``).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from ..errors import RateLimitExceededError
from ..schemas.scope import RateLimit, Scope


class _TokenBucket:
    __slots__ = ("_last", "_tokens", "capacity", "rate")

    def __init__(self, rate: float, capacity: int, now: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self._tokens = float(capacity)
        self._last = now

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._last)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    def try_acquire(self, now: float) -> bool:
        self._refill(now)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    @property
    def tokens(self) -> float:
        return self._tokens


class RateLimiter:
    """Thread-safe token-bucket limiter keyed on ``(tool, target)``.

    Per-target overrides layer on top of the scope's default rate limit.
    """

    def __init__(
        self,
        scope: Scope,
        *,
        clock: Callable[[], float] = time.monotonic,
        overrides: dict[str, RateLimit] | None = None,
    ) -> None:
        self._default = scope.roe.default_rate_limit
        self._overrides = overrides or {}
        self._clock = clock
        self._buckets: dict[tuple[str, str], _TokenBucket] = {}
        self._lock = threading.Lock()

    def _limit_for(self, target: str) -> RateLimit:
        return self._overrides.get(target, self._default)

    def _bucket(self, tool: str, target: str) -> _TokenBucket:
        key = (tool, target)
        bucket = self._buckets.get(key)
        if bucket is None:
            limit = self._limit_for(target)
            bucket = _TokenBucket(
                rate=limit.requests_per_sec,
                capacity=limit.burst,
                now=self._clock(),
            )
            self._buckets[key] = bucket
        return bucket

    def try_acquire(self, tool: str, target: str) -> bool:
        with self._lock:
            return self._bucket(tool, target).try_acquire(self._clock())

    def check(self, tool: str, target: str) -> None:
        """Consume one token or raise :class:`RateLimitExceededError`."""

        if not self.try_acquire(tool, target):
            raise RateLimitExceededError(
                tool, target, self._limit_for(target).requests_per_sec
            )
