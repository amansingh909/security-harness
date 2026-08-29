"""Async token-bucket rate limiter, tuned to the target's published limit.

The refill/consume arithmetic is a pure method (``_take``) so it can be tested
deterministically with an injected clock, while ``acquire`` layers async sleep
on top. This is politeness, not evasion — one steady, bounded request rate."""
from __future__ import annotations

import asyncio
import time


class TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: float | None = None) -> None:
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        self.rate = rate_per_sec
        self.capacity = capacity if capacity is not None else max(1.0, rate_per_sec)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    def _take(self, now: float) -> float:
        """Refill by elapsed time, then consume one token. Returns the number of
        seconds the caller must wait before the consumed token is 'earned'
        (0.0 if a token was available immediately)."""
        elapsed = max(0.0, now - self._updated)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._updated = now
        self._tokens -= 1.0
        if self._tokens >= 0:
            return 0.0
        return -self._tokens / self.rate

    async def acquire(self) -> None:
        async with self._lock:
            wait = self._take(time.monotonic())
        if wait > 0:
            await asyncio.sleep(wait)
