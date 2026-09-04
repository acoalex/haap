# -*- coding: utf-8 -*-
"""Rate limiter token-bucket por (amigo, acción) + límite global por amigo.

Anti-flooding y anti-abuso: cada mensaje entrante consume un token de la
acción y otro del límite global del amigo. Si no quedan tokens ->
``RateLimitedError`` (el emisor recibe un mensaje ``error`` con
``RATE_LIMITED`` y puede reintentar tras ``retry_after``).

Configuración por amigo vía ``FriendRecord.rate_limits``; si un amigo no
define límite para una acción, se aplica el catálogo por defecto de
``directory.DEFAULT_RATE_LIMITS``.
"""

from __future__ import annotations

import threading
import time

from .errors import RateLimitedError

# Catálogo de límites por defecto (por acción, si el amigo no especifica).
DEFAULT_CATALOG = {
    "*": {"capacity": 60, "refill_per_sec": 0.5},       # global por amigo
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
    """Token bucket por (amigo, acción) con lock compartido y poda de
    buckets inactivos."""

    _GLOBAL_LOCK = threading.Lock()  # lock de proceso para _Bucket.take

    def __init__(self, default_catalog: dict | None = None,
                 clock=None):
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()
        self._catalog = default_catalog or DEFAULT_CATALOG
        self._clock = clock  # opcional: callable() -> float (tests)

    # -- configuración -----------------------------------------------------
    def configure(self, key: str, action: str,
                  capacity: float, refill_per_sec: float) -> None:
        """key = fingerprint del amigo; action = '*' para global."""
        with self._lock:
            self._buckets[(key, action)] = _Bucket(capacity, refill_per_sec)

    def config_for(self, friend_limits: dict, action: str) -> tuple[float, float]:
        """Resuelve (capacity, refill) para la acción de un amigo:
        límite específico del amigo -> catálogo por defecto."""
        entry = (friend_limits or {}).get(action) or {}
        if not entry:
            entry = self._catalog.get(action) or self._catalog["*"]
        cap = float(entry.get("capacity", self._catalog["*"]["capacity"]))
        refill = float(entry.get("refill_per_sec",
                                 self._catalog["*"]["refill_per_sec"]))
        return cap, refill

    # -- evaluación --------------------------------------------------------
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
        """Consume 1 token de (amigo, acción) y 1 del global (amigo, '*').
        Devuelve True si ambos pasan; con ``raise_on_limit`` lanza
        RateLimitedError con retry_after."""
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
            f"límite de {action} superado para {fingerprint}; reintenta en "
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
