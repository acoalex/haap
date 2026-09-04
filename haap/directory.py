# -*- coding: utf-8 -*-
"""Directorio de amigos local y persistente.

Fichero: ``<HAAP_DIR>/friends.json``. Cada entrada guarda el fingerprint,
la CLAVE PÚBLICA del amigo (necesaria para verificar sus firmas), sus
endpoints de mensajería, capacidades declaradas, permisos concedidos,
rate limits y el estado de la relación:

    pending_out    -> yo envié friend_request; espero friend_accept
    pending_in     -> me enviaron friend_request; esperando aprobación HUMANA
    accepted       -> amistad establecida (ambas partes)
    blocked        -> bloqueado (deny-by-default absoluto)
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
    # Acciones que el AMIGO puede realizar CONTRA este agente.
    # deny-by-default: la matriz local solo lista lo concedido.
}
# Concesiones típicas al aprobar (plantilla conservadora: sin file/exec).
DEFAULT_GRANT_TEMPLATE = {
    "chat:converse": {"allow": True, "scopes": []},
    "task:delegate": {"allow": True, "scopes": []},
    "task:submit": {"allow": True, "scopes": []},
}
DEFAULT_RATE_LIMITS = {
    # por (amigo, acción): capacidad de ráfaga y recarga tokens/segundo.
    "*": {"capacity": 60, "refill_per_sec": 0.5},   # global por amigo
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
    public_key_b64: str = ""      # clave pública del amigo (verificar firmas)
    endpoints: list = field(default_factory=list)   # ["https://host:8443"]
    declared_capabilities: dict = field(default_factory=dict)
    permissions: dict = field(default_factory=dict)  # acción -> {allow,scopes}
    rate_limits: dict = field(default_factory=dict)  # acción -> {capacity,refill}
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    last_seen: str = ""
    notes: str = ""

    # -- API cómoda --------------------------------------------------------
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
            raise HAAPError(f"estado de amistad inválido: {rec.status}")
        return rec


class Directory:
    """Registro local de amigos, persistido en JSON con lock."""

    def __init__(self, directory: str | None = None):
        self.directory = directory or haap_dir()
        self.path = os.path.join(self.directory, FRIENDS_FILENAME)
        self._lock = threading.RLock()
        self._friends: dict[str, FriendRecord] = {}
        self._load()

    # -- persistencia ------------------------------------------------------
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

    # -- consultas ---------------------------------------------------------
    def get(self, fingerprint: str) -> FriendRecord | None:
        with self._lock:
            return self._friends.get(fingerprint)

    def require(self, fingerprint: str, statuses=None) -> FriendRecord:
        rec = self.get(fingerprint)
        if rec is None:
            raise FriendNotFoundError(f"sin relación con {fingerprint}")
        if statuses and rec.status not in statuses:
            raise FriendNotFoundError(
                f"relación con {fingerprint} en estado {rec.status} "
                f"(se esperaba {'/'.join(statuses)})")
        return rec

    def all(self) -> list[FriendRecord]:
        with self._lock:
            return list(self._friends.values())

    def by_status(self, status: str) -> list[FriendRecord]:
        return [r for r in self.all() if r.status == status]

    def public_keys(self) -> dict[str, bytes]:
        """Mapa fingerprint -> clave pública RAW para verificación de firmas.
        Incluye pendientes y bloqueados: así un remitente conocido siempre
        puede ser verificado (y rechazado con el error adecuado)."""
        from .crypto import b64d
        return {
            fp: b64d(rec.public_key_b64)
            for fp, rec in self._friends.items() if rec.public_key_b64
        }

    # -- mutaciones --------------------------------------------------------
    def upsert(self, rec: FriendRecord) -> FriendRecord:
        with self._lock:
            rec.touch()
            self._friends[rec.fingerprint] = rec
            self.save()
            return rec

    def remove(self, fingerprint: str) -> None:
        with self._lock:
            if fingerprint not in self._friends:
                raise FriendNotFoundError(f"sin relación con {fingerprint}")
            del self._friends[fingerprint]
            self.save()

    # -- máquina de estados de amistad -------------------------------------
    def register_known(self, fingerprint: str, public_key_b64: str,
                       name: str = "", endpoints=None,
                       notes: str = "") -> FriendRecord:
        """Registra/actualiza a un remitente verificado (clave pública ya
        validada contra la firma). No cambia el estado de una relación
        existente; crea ``pending_in`` implícito si no existía (el
        friend_request formal lo consolidará)."""
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
        """Inicio manual de amistad desde este lado (``haap friends add``)."""
        with self._lock:
            existing = self._friends.get(fingerprint)
            if existing and existing.status == "blocked":
                raise FriendBlockedError(f"{fingerprint} está bloqueado")
            if existing and existing.status == "accepted":
                raise DuplicateRequestError(
                    f"ya eres amigo de {fingerprint}")
            rec = FriendRecord(
                fingerprint=fingerprint, name=name or fingerprint,
                status="pending_out", public_key_b64=public_key_b64,
                endpoints=list(endpoints or []),
                permissions=dict(permissions or DEFAULT_GRANT_TEMPLATE),
                rate_limits=dict(rate_limits or {}),
                notes="solicitud enviada por este agente")
            self._friends[fingerprint] = rec
            self.save()
            return rec

    def mark_outbound_accepted(self, fingerprint: str,
                               their_endpoints=None) -> FriendRecord:
        """Recibimos friend_accept: pending_out -> accepted. Si la relación
        local estaba en pending_in (ambos iniciaron a la vez) o ya existía
        como conocida, también consolida a accepted (idempotente)."""
        with self._lock:
            rec = self.get(fingerprint)
            if rec is None:
                raise FriendNotFoundError(f"sin relación con {fingerprint}")
            if rec.status == "blocked":
                raise FriendBlockedError(f"{fingerprint} está bloqueado")
            if rec.status not in ("pending_out", "pending_in", "accepted"):
                raise FriendNotFoundError(
                    f"relación con {fingerprint} en estado {rec.status} inesperado")
            rec.status = "accepted"
            if their_endpoints:
                rec.endpoints = list(
                    dict.fromkeys(rec.endpoints + their_endpoints))
            rec.notes = "amistad confirmada por el otro agente"
            rec.touch()
            self.save()
            return rec

    def approve(self, fingerprint: str, grant: dict | None = None,
                rate_limits: dict | None = None) -> FriendRecord:
        """Aprobación HUMANA de una solicitud entrante: pending_in ->
        accepted, con la matriz de permisos que el dueño concede."""
        with self._lock:
            rec = self.require(fingerprint, statuses=("pending_in",))
            rec.status = "accepted"
            rec.permissions = dict(grant or DEFAULT_GRANT_TEMPLATE)
            if rate_limits:
                rec.rate_limits = dict(rate_limits)
            rec.notes = "aprobado por el dueño humano"
            rec.touch()
            self.save()
            return rec

    def deny(self, fingerprint: str) -> None:
        """Rechazo humano de una solicitud entrante: elimina la entrada."""
        with self._lock:
            rec = self.require(fingerprint, statuses=("pending_in",))
            del self._friends[fingerprint]
            self.save()

    def block(self, fingerprint: str) -> FriendRecord:
        """Bloqueo: rechaza todo mensaje futuro de ese fingerprint."""
        with self._lock:
            existing = self._friends.get(fingerprint)
            if existing:
                existing.status = "blocked"
                existing.permissions = {}
                existing.notes = "bloqueado por el dueño"
                existing.touch()
                rec = existing
            else:
                rec = FriendRecord(fingerprint=fingerprint, name=fingerprint,
                                   status="blocked")
                self._friends[fingerprint] = rec
            self.save()
            return rec
