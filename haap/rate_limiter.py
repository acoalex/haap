# -*- coding: utf-8 -*-
"""Per-(friend, action) token-bucket rate limiter + per-friend global limit.

Anti-flooding and anti-abuse: each inbound message consumes one token
from the action bucket and one from the friend's global bucket. When no
tokens remain -> ``RateLimitedError`` (the sender receives an ``error``
message with ``RATE_LIMITED`` and may retry after ``retry_after``).

Per-friend configuration lives in ``FriendRecord.rate_limits``; if a
friend does not define a limit for an action, the default catalog from
``directory.DEFAULT_RATE_LIMITS`` applies.
"""

from __future__ import annotations

import threading
import time

from .errors import RateLimitedError

# Default per-action limits (used when the friend specifies none).
DEFAULT_CATALOG = {
    "*": {"capacity": 60, "refill_per_sec": 0.5},       # per-friend global
    "task_request": {"capacity": 5, "refill_per_sec": 0.05},
    "task_result": {"capacity": 10, "refill_per_sec": 0.1},
    "task_progress": {"capacity": 20, "refill_per_sec": 0.2},
    "chat:converse": {"capacity": 20, "refill_per_sec": 0.2},
    "hello": {"capacity": 10, "refill_per_sec": 0.1},
    "friend_request": {"capacity": 3, "refill_per_sec": 0.02},
    "verify": {"capacity": 10, "refill_per_sec": 0.1},
    "error": {"capacity": 10, "refill_per_sec": 0.1},
}


class _Bucket:
    __slots__ = ("capacity", "tokens", "last_refill", "refill_per_sec")

    def __init__(self, capacity: float, refill_per_sec: float):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self.last_refill = time.monotonic()

    def _refill(self, now: float) -> None:
        if self.refill_per_sec > 0:
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now

    def take(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with RateLimiter._GLOBAL_LOCK:
            self._refill(now)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    def wait_seconds(self, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        self._refill(now)
        if self.refill_per_sec <= 0:
            return float("inf")
        missing = 1.0 - self.tokens
        return max(0.0, missing / self.refill_per_sec)


class RateLimiter:
    """Per-(friend, action) token buckets with a shared lock and pruning
    of inactive buckets."""

    _GLOBAL_LOCK = threading.Lock()  # process-wide lock for _Bucket.take

    def __init__(self, default_catalog: dict | None = None,
                 clock=None):
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()
        self._catalog = default_catalog or DEFAULT_CATALOG
        self._clock = clock  # optional: callable() -> float (tests)

    # -- configuration -----------------------------------------------------
    def configure(self, key: str, action: str,
                  capacity: float, refill_per_sec: float) -> None:
        """key = friend fingerprint; action = '*' for the global bucket."""
        with self._lock:
            self._buckets[(key, action)] = _Bucket(capacity, refill_per_sec)

    def config_for(self, friend_limits: dict, action: str) -> tuple[float, float]:
        """Resolve (capacity, refill) for a friend's action:
        friend-specific limit -> default catalog."""
        entry = (friend_limits or {}).get(action) or {}
        if not entry:
            entry = self._catalog.get(action) or self._catalog["*"]
        cap = float(entry.get("capacity", self._catalog["*"]["capacity"]))
        refill = float(entry.get("refill_per_sec",
                                 self._catalog["*"]["refill_per_sec"]))
        return cap, refill

    # -- evaluation --------------------------------------------------------
    def _bucket(self, key: str, action: str, capacity: float,
                refill: float) -> _Bucket:
        with self._lock:
            b = self._buckets.get((key, action))
            if b is None:
                b = _Bucket(capacity, refill)
                self._buckets[(key, action)] = b
            return b

    def check(self, fingerprint: str, action: str,
              friend_limits: dict | None = None,
              raise_on_limit: bool = True) -> bool:
        """Consume 1 token from (friend, action) and 1 from the global
        (friend, '*') bucket. Returns True if both pass; with
        ``raise_on_limit`` raises RateLimitedError with retry_after."""
        now = self._clock() if self._clock else None
        now_mono = time.monotonic() if now is None else now
        cap_a, refill_a = self.config_for(friend_limits, action)
        cap_g, refill_g = self.config_for(friend_limits, "*")
        ok_action = self._bucket(fingerprint, action, cap_a, refill_a).take(now)
        ok_global = self._bucket(fingerprint, "*", cap_g, refill_g).take(now)
        if ok_action and ok_global:
            return True
        if not raise_on_limit:
            return False
        wait = max(
            self._bucket(fingerprint, action, cap_a, refill_a).wait_seconds(now),
            self._bucket(fingerprint, "*", cap_g, refill_g).wait_seconds(now))
        retry_after = max(1, int(wait) + 1)
        raise RateLimitedError(
            f"{action} rate limit exceeded for {fingerprint}; retry in "
            f"~{retry_after}s", retry_after=retry_after)

    def reset(self, fingerprint: str | None = None) -> None:
        with self._lock:
            if fingerprint is None:
                self._buckets.clear()
            else:
                for k in [k for k in self._buckets if k[0] == fingerprint]:
                    del self._buckets[k]

    def __len__(self) -> int:
        return len(self._buckets)
