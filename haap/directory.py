# -*- coding: utf-8 -*-
"""Local, persistent friends directory.

File: ``<HAAP_DIR>/friends.json``. Each entry stores the friend's
fingerprint, the friend's PUBLIC KEY (needed to verify signatures),
messaging endpoints, declared capabilities, granted permissions, rate
limits and the relationship status:

    pending_out    -> I sent friend_request; awaiting friend_accept
    pending_in     -> I received friend_request; awaiting HUMAN approval
    accepted       -> friendship established (both sides)
    blocked        -> blocked (absolute deny-by-default)
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field

from .errors import (
    DuplicateRequestError,
    FriendBlockedError,
    FriendNotFoundError,
    HAAPError,
)
from .identity import haap_dir

FRIENDS_FILENAME = "friends.json"
STATUSES = ("pending_out", "pending_in", "accepted", "blocked")

DEFAULT_PERMISSIONS = {
    # Actions the FRIEND may perform AGAINST this agent.
    # deny-by-default: the local matrix only lists what is granted.
}
# Typical grants on approval (conservative template: no file/exec).
DEFAULT_GRANT_TEMPLATE = {
    "chat:converse": {"allow": True, "scopes": []},
    "task:delegate": {"allow": True, "scopes": []},
    "task:submit": {"allow": True, "scopes": []},
}
DEFAULT_RATE_LIMITS = {
    # per (friend, action): burst capacity and token refill per second.
    "*": {"capacity": 60, "refill_per_sec": 0.5},   # per-friend global
    "task_request": {"capacity": 5, "refill_per_sec": 0.05},
    "task_result": {"capacity": 10, "refill_per_sec": 0.1},
    "chat:converse": {"capacity": 20, "refill_per_sec": 0.2},
    "error": {"capacity": 10, "refill_per_sec": 0.1},
}


def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class FriendRecord:
    fingerprint: str
    name: str
    status: str = "pending_in"
    public_key_b64: str = ""      # friend's public key (verify signatures)
    endpoints: list = field(default_factory=list)   # ["https://host:8443"]
    declared_capabilities: dict = field(default_factory=dict)
    permissions: dict = field(default_factory=dict)  # action -> {allow,scopes}
    rate_limits: dict = field(default_factory=dict)  # action -> {capacity,refill}
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    last_seen: str = ""
    notes: str = ""

    # -- convenience API ---------------------------------------------------
    def has_permission(self, action: str) -> bool:
        perm = self.permissions.get(action)
        return bool(perm and perm.get("allow"))

    def permission_scopes(self, action: str) -> list:
        perm = self.permissions.get(action) or {}
        return list(perm.get("scopes") or [])

    def rate_limit_for(self, action: str) -> tuple[int, float]:
        rl = self.rate_limits.get(action) or {}
        cap = int(rl.get("capacity", 0))
        refill = float(rl.get("refill_per_sec", 0.0))
        return cap, refill

    def touch(self):
        self.updated_at = utc_now_iso()
        self.last_seen = utc_now_iso()

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "name": self.name,
            "status": self.status,
            "public_key_b64": self.public_key_b64,
            "endpoints": list(self.endpoints),
            "declared_capabilities": self.declared_capabilities,
            "permissions": self.permissions,
            "rate_limits": self.rate_limits,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_seen": self.last_seen,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FriendRecord":
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in data.items() if k in known}
        rec = cls(**clean)
        if rec.status not in STATUSES:
            raise HAAPError(f"invalid friendship status: {rec.status}")
        return rec


class Directory:
    """Local friends registry, persisted as JSON with locking."""

    def __init__(self, directory: str | None = None):
        self.directory = directory or haap_dir()
        self.path = os.path.join(self.directory, FRIENDS_FILENAME)
        self._lock = threading.RLock()
        self._friends: dict[str, FriendRecord] = {}
        self._load()

    # -- persistence -------------------------------------------------------
    def _load(self) -> None:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for fp, rec in data.items():
                self._friends[fp] = FriendRecord.from_dict(rec)

    def save(self) -> None:
        os.makedirs(self.directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(
                {fp: rec.to_dict() for fp, rec in self._friends.items()},
                fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, self.path)

    # -- queries -----------------------------------------------------------
    def get(self, fingerprint: str) -> FriendRecord | None:
        with self._lock:
            return self._friends.get(fingerprint)

    def require(self, fingerprint: str, statuses=None) -> FriendRecord:
        rec = self.get(fingerprint)
        if rec is None:
            raise FriendNotFoundError(f"no relationship with {fingerprint}")
        if statuses and rec.status not in statuses:
            raise FriendNotFoundError(
                f"relationship with {fingerprint} in status {rec.status} "
                f"(expected {'/'.join(statuses)})")
        return rec

    def all(self) -> list[FriendRecord]:
        with self._lock:
            return list(self._friends.values())

    def by_status(self, status: str) -> list[FriendRecord]:
        return [r for r in self.all() if r.status == status]

    def public_keys(self) -> dict[str, bytes]:
        """Map fingerprint -> RAW public key for signature verification.
        Includes pending and blocked entries: a known sender can always
        be verified (and rejected with the proper error)."""
        from .crypto import b64d
        return {
            fp: b64d(rec.public_key_b64)
            for fp, rec in self._friends.items() if rec.public_key_b64
        }

    # -- mutations ---------------------------------------------------------
    def upsert(self, rec: FriendRecord) -> FriendRecord:
        with self._lock:
            rec.touch()
            self._friends[rec.fingerprint] = rec
            self.save()
            return rec

    def remove(self, fingerprint: str) -> None:
        with self._lock:
            if fingerprint not in self._friends:
                raise FriendNotFoundError(f"no relationship with {fingerprint}")
            del self._friends[fingerprint]
            self.save()

    # -- friendship state machine ------------------------------------------
    def register_known(self, fingerprint: str, public_key_b64: str,
                       name: str = "", endpoints=None,
                       notes: str = "") -> FriendRecord:
        """Register/update a verified sender (public key already validated
        against the signature). Does not change an existing relationship's
        status; creates an implicit ``pending_in`` if none existed (the
        formal friend_request will consolidate it)."""
        with self._lock:
            existing = self._friends.get(fingerprint)
            if existing:
                if not existing.public_key_b64:
                    existing.public_key_b64 = public_key_b64
                if endpoints:
                    existing.endpoints = list(
                        dict.fromkeys(existing.endpoints + endpoints))
                if name and not existing.name:
                    existing.name = name
                existing.touch()
                rec = existing
            else:
                rec = FriendRecord(
                    fingerprint=fingerprint, name=name or fingerprint,
                    status="pending_in", public_key_b64=public_key_b64,
                    endpoints=list(endpoints or []), notes=notes)
                self._friends[fingerprint] = rec
            self.save()
            return rec

    def add_pending_out(self, fingerprint: str, public_key_b64: str,
                        name: str, endpoints=None,
                        permissions: dict | None = None,
                        rate_limits: dict | None = None) -> FriendRecord:
        """Manual friendship start from this side (``haap friends add``)."""
        with self._lock:
            existing = self._friends.get(fingerprint)
            if existing and existing.status == "blocked":
                raise FriendBlockedError(f"{fingerprint} is blocked")
            if existing and existing.status == "accepted":
                raise DuplicateRequestError(
                    f"already friends with {fingerprint}")
            rec = FriendRecord(
                fingerprint=fingerprint, name=name or fingerprint,
                status="pending_out", public_key_b64=public_key_b64,
                endpoints=list(endpoints or []),
                # NOTE: permissions={} means deny-everything (explicit empty
                # matrix); permissions=None means "use the conservative
                # default template".
                permissions=dict(permissions) if permissions is not None
                else dict(DEFAULT_GRANT_TEMPLATE),
                rate_limits=dict(rate_limits or {}),
                notes="request sent by this agent")
            self._friends[fingerprint] = rec
            self.save()
            return rec

    def mark_outbound_accepted(self, fingerprint: str,
                               their_endpoints=None) -> FriendRecord:
        """Received friend_accept: pending_out -> accepted. If the local
        relationship was pending_in (both sides initiated at once) or
        already known, also consolidates to accepted (idempotent)."""
        with self._lock:
            rec = self.get(fingerprint)
            if rec is None:
                raise FriendNotFoundError(f"no relationship with {fingerprint}")
            if rec.status == "blocked":
                raise FriendBlockedError(f"{fingerprint} is blocked")
            if rec.status not in ("pending_out", "pending_in", "accepted"):
                raise FriendNotFoundError(
                    f"unexpected relationship status with {fingerprint}: "
                    f"{rec.status}")
            rec.status = "accepted"
            if their_endpoints:
                rec.endpoints = list(
                    dict.fromkeys(rec.endpoints + their_endpoints))
            rec.notes = "friendship confirmed by the other agent"
            rec.touch()
            self.save()
            return rec

    def approve(self, fingerprint: str, grant: dict | None = None,
                rate_limits: dict | None = None) -> FriendRecord:
        """HUMAN approval of an inbound request: pending_in -> accepted,
        with the permission matrix the owner grants."""
        with self._lock:
            rec = self.require(fingerprint, statuses=("pending_in",))
            rec.status = "accepted"
            rec.permissions = dict(grant or DEFAULT_GRANT_TEMPLATE)
            if rate_limits:
                rec.rate_limits = dict(rate_limits)
            rec.notes = "approved by the human owner"
            rec.touch()
            self.save()
            return rec

    def deny(self, fingerprint: str) -> None:
        """Human rejection of an inbound request: removes the entry."""
        with self._lock:
            rec = self.require(fingerprint, statuses=("pending_in",))
            del self._friends[fingerprint]
            self.save()

    def block(self, fingerprint: str) -> FriendRecord:
        """Block: rejects every future message from that fingerprint."""
        with self._lock:
            existing = self._friends.get(fingerprint)
            if existing:
                existing.status = "blocked"
                existing.permissions = {}
                existing.notes = "blocked by the owner"
                existing.touch()
                rec = existing
            else:
                rec = FriendRecord(fingerprint=fingerprint, name=fingerprint,
                                   status="blocked")
                self._friends[fingerprint] = rec
            self.save()
            return rec
