"""Resource-consumption guards (LLM10 — Unbounded Consumption).

A sliding-window rate limiter, kept deliberately small and dependency-free. The
size cap itself is just a length comparison enforced in the endpoint; this module
provides the throttling primitive and is unit-tested with an injectable clock so
the test is deterministic and needs no API key.
"""

import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    """Allow at most `max_calls` per `per_seconds` window, per key."""

    def __init__(self, max_calls: int, per_seconds: float) -> None:
        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str = "global", *, now: float | None = None) -> bool:
        """Record a call and return whether it is within the limit.

        `now` is injectable so callers/tests can supply a deterministic clock.
        """
        now = time.monotonic() if now is None else now
        hits = self._hits[key]
        cutoff = now - self.per_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= self.max_calls:
            return False
        hits.append(now)
        return True
