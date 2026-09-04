# -*- coding: utf-8 -*-
"""Registro de tareas HAAP con ciclo de vida alineado con A2A.

Estados (nombres A2A / Linux Foundation):

    submitted -> accepted -> working -> completed
                     |           |
                     +-> rejected +-> failed
                              (cualquier estado -> rejected por el agente
                               receptor; failed si el ejecutor falla)

Transiciones válidas:

    submitted:  creada por el delegador (cliente) o recibida (servidor)
    accepted:   el ejecutor aceptó la tarea
    rejected:   el ejecutor la rechazó (permisos no, eso es error de red;
                rechazo = decisión del ejecutor/agente)
    working:    el ejecutor informa progreso
    completed:  el ejecutor envió task_result con payload final
    failed:     el ejecutor envió task_result con error

El registro es local por agente: guarda las tareas QUE ENVIAMOS
(delegadas a amigos) y las QUE RECIBIMOS (ejecutadas por nosotros), con
``role`` = delegate/submit.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid

from .errors import TaskNotFoundError, TaskStateError
from .identity import haap_dir

TASKS_FILENAME = "tasks.json"

# Estados permitidos (A2A) y transiciones.
STATES = ("submitted", "accepted", "working", "completed", "failed", "rejected")
_TRANSITIONS = {
    "submitted": {"accepted", "rejected", "failed"},
    "accepted": {"working", "completed", "failed", "rejected"},
    "working": {"working", "completed", "failed", "rejected"},
    "completed": set(),
    "failed": set(),
    "rejected": set(),
}


def new_task_id() -> str:
    """Identificador de tarea: 'T' + uuid4 hex corto."""
    return "T" + uuid.uuid4().hex[:16]


class TaskRecord:
    def __init__(self, task_id: str, role: str, friend_fingerprint: str,
                 prompt: str, action: str = "", resource: str = "",
                 state: str = "submitted", detail: dict | None = None,
                 created_at: float | None = None):
        if state not in STATES:
            raise TaskStateError(f"estado inicial inválido: {state}")
        self.task_id = task_id
        self.role = role          # "delegate" (yo envío) | "submit" (yo ejecuto)
        self.friend_fingerprint = friend_fingerprint
        self.prompt = prompt
        self.action = action      # p. ej. "file:read" (para scopes)
        self.resource = resource  # p. ej. ruta/URI (para scopes)
        self.state = state
        self.detail = dict(detail or {})   # progreso/resultado/resumen
        self.created_at = created_at or time.time()
        self.updated_at = self.created_at
        self.progress_log: list[dict] = []

    def transition(self, new_state: str, detail: dict | None = None) -> None:
        if new_state not in STATES:
            raise TaskStateError(f"estado destino inválido: {new_state}")
        if new_state not in _TRANSITIONS.get(self.state, set()):
            raise TaskStateError(
                f"transición inválida {self.state} -> {new_state}")
        self.state = new_state
        if detail:
            self.detail.update(detail)
        self.updated_at = time.time()

    def log_progress(self, message: str, detail: dict | None = None) -> None:
        self.progress_log.append({
            "ts": round(time.time(), 3),
            "message": str(message)[:500],
            "detail": dict(detail or {}),
        })
        self.updated_at = time.time()

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id, "role": self.role,
            "friend_fingerprint": self.friend_fingerprint,
            "prompt": self.prompt, "action": self.action,
            "resource": self.resource, "state": self.state,
            "detail": self.detail,
            "created_at": round(self.created_at, 3),
            "updated_at": round(self.updated_at, 3),
            "progress_log": self.progress_log[-20:],
        }


class TaskRegistry:
    """Registro persistente de tareas local."""

    def __init__(self, directory: str | None = None, memory: bool = False):
        self.directory = directory or haap_dir()
        self.path = os.path.join(self.directory, TASKS_FILENAME)
        self.memory = memory
        self._lock = threading.Lock()
        self._tasks: dict[str, TaskRecord] = {}
        if not memory:
            self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for t in data:
                rec = TaskRecord(
                    task_id=t["task_id"], role=t["role"],
                    friend_fingerprint=t["friend_fingerprint"],
                    prompt=t.get("prompt", ""), action=t.get("action", ""),
                    resource=t.get("resource", ""), state=t["state"],
                    detail=t.get("detail"), created_at=t.get("created_at"))
                rec.progress_log = t.get("progress_log", [])
                self._tasks[rec.task_id] = rec
        except (OSError, ValueError, KeyError):
            pass

    def _save(self) -> None:
        if self.memory:
            return
        os.makedirs(self.directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump([t.to_dict() for t in self._tasks.values()],
                      fh, indent=1, ensure_ascii=False)
        os.replace(tmp, self.path)

    def create(self, role: str, friend_fingerprint: str, prompt: str,
               action: str = "", resource: str = "",
               task_id: str | None = None) -> TaskRecord:
        with self._lock:
            rec = TaskRecord(task_id or new_task_id(), role,
                             friend_fingerprint, prompt, action, resource)
            self._tasks[rec.task_id] = rec
            self._save()
            return rec

    def get(self, task_id: str) -> TaskRecord | None:
        with self._lock:
            return self._tasks.get(task_id)

    def require(self, task_id: str) -> TaskRecord:
        rec = self.get(task_id)
        if rec is None:
            raise TaskNotFoundError(f"tarea desconocida: {task_id}")
        return rec

    def update(self, task_id: str, new_state: str,
               detail: dict | None = None) -> TaskRecord:
        with self._lock:
            rec = self.require(task_id)
            rec.transition(new_state, detail)
            self._save()
            return rec

    def progress(self, task_id: str, message: str,
                 detail: dict | None = None) -> TaskRecord:
        with self._lock:
            rec = self.require(task_id)
            rec.log_progress(message, detail)
            self._save()
            return rec

    def list(self, role: str = "", friend: str = "",
             limit: int = 50) -> list[TaskRecord]:
        with self._lock:
            out = [t for t in self._tasks.values()
                   if (not role or t.role == role)
                   and (not friend or t.friend_fingerprint == friend)]
            out.sort(key=lambda t: t.created_at, reverse=True)
            return out[:limit]

    def __len__(self) -> int:
        return len(self._tasks)
