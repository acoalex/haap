# -*- coding: utf-8 -*-
"""HAAP audit trail: persistent JSON-lines log.

File: ``<HAAP_DIR>/audit.log`` (one JSON entry per line) with simple
size-based rotation. Tests use in-memory mode. Every security decision
(handshake, permissions, rate limits, tasks) leaves a trace: who, what
action, result and NON-sensitive detail.
"""

from __future__ import annotations

import json
import os
import threading
import time

from .identity import haap_dir

AUDIT_FILENAME = "audit.log"
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB -> rotates to audit.log.1
KEEP_ROTATED = 2

# Audit actions that must NEVER appear in logs: they contain secrets or
# task payloads (see threat model T7 in ARQUITECTURA.md).
_SENSITIVE_KEYS = {"challenge_token", "private_key", "signature", "task_payload"}


def _safe(detail: dict | None) -> dict:
    detail = dict(detail or {})
    for key in _SENSITIVE_KEYS:
        if key in detail:
            detail[key] = "<redacted>"
    return detail


class AuditLog:
    """Thread-safe JSON-lines log with in-memory mode (tests) and file mode."""

    def __init__(self, directory: str | None = None, memory: bool = False,
                 max_file_bytes: int = MAX_FILE_BYTES):
        self.directory = directory or haap_dir()
        self.path = os.path.join(self.directory, AUDIT_FILENAME)
        self.memory = memory
        self.max_file_bytes = max_file_bytes
        self._lock = threading.Lock()
        self._entries: list[dict] = []

    def event(self, event: str, friend: str = "", action: str = "",
              result: str = "ok", detail: dict | None = None,
              ts: float | None = None) -> dict:
        entry = {
            "ts": round(ts if ts is not None else time.time(), 3),
            "event": event,
            "friend": friend,
            "action": action,
            "result": result,
            "detail": _safe(detail),
        }
        with self._lock:
            if self.memory:
                self._entries.append(entry)
            else:
                os.makedirs(self.directory, exist_ok=True)
                self._rotate_if_needed()
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def _rotate_if_needed(self) -> None:
        try:
            if os.path.exists(self.path) and \
                    os.path.getsize(self.path) >= self.max_file_bytes:
                for i in range(KEEP_ROTATED, 0, -1):
                    src = f"{self.path}.{i - 1}" if i > 1 else self.path
                    dst = f"{self.path}.{i}"
                    if os.path.exists(src):
                        os.replace(src, dst)
                # remove the oldest if it exceeds the retention count
                old = f"{self.path}.{KEEP_ROTATED + 1}"
                if os.path.exists(old):
                    os.remove(old)
        except OSError:
            pass  # if rotation fails, keep writing

    def recent(self, last: int = 50, since: float | None = None,
               friend: str = "", event_prefix: str = "") -> list[dict]:
        with self._lock:
            if self.memory:
                entries = list(self._entries)
            else:
                entries = self._read_file()
        entries.sort(key=lambda e: e.get("ts", 0))
        if since is not None:
            entries = [e for e in entries if e.get("ts", 0) >= since]
        if friend:
            entries = [e for e in entries if e.get("friend") == friend]
        if event_prefix:
            entries = [e for e in entries
                       if e.get("event", "").startswith(event_prefix)]
        return entries[-last:]

    def _read_file(self) -> list[dict]:
        entries: list[dict] = []
        if not os.path.exists(self.path):
            return entries
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
        return entries

    def __len__(self) -> int:
        with self._lock:
            if self.memory:
                return len(self._entries)
            return len(self._read_file())
