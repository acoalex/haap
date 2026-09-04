# -*- coding: utf-8 -*-
"""Matriz de permisos por amigo: deny-by-default con scopes.

Catálogo de acciones (cada agente guarda en su Directory, POR AMIGO,
qué puede hacer ese amigo CONTRA este agente; las acciones en sentido
``me -> amigo`` se gobiernan con las mismas claves en el lado local
como guardas de salida — ver ARQUITECTURA.md, tabla de permisos):

  chat:converse     el amigo puede abrir intercambios conversacionales/ping
  read:schedule     el amigo puede consultar la agenda del agente
  read:calendar     el amigo puede consultar el calendario del agente
  file:read         el amigo puede LEER archivos (scopes: globs de rutas)
  file:write        el amigo puede ESCRIBIR archivos (scopes: rutas destino)
  exec:terminal     el amigo puede pedir ejecución de comandos (scopes:
                    prefijos de comando permitidos, p. ej. "haap ")
  task:delegate     (entrante) el amigo puede DELEGARME tareas -> yo ejecuto
  task:submit       (saliente) guarda local: YO puedo delegar tareas a este
                    amigo (el servidor del amigo exigirá a su vez que yo
                    tenga task:delegate en SU matriz)

Semántica de ``scopes``: lista de cadenas. El matcher aplica globs
(fnmatch) sobre el ``resource`` de la petición; una lista vacía o con el
elemento ``"*"`` permite cualquier recurso de la acción. Cualquier
acción NO listada en ``permissions`` del amigo = denegada (deny by
default). Las decisiones se auditan.
"""

from __future__ import annotations

import fnmatch
import threading

# Acciones entrantes que el servidor verifica contra la matriz del amigo.
INBOUND_ACTIONS = (
    "chat:converse", "read:schedule", "read:calendar",
    "file:read", "file:write", "exec:terminal", "task:delegate",
)
# Acciones salientes que el cliente verifica como guarda local.
OUTBOUND_ACTIONS = ("task:submit", "chat:converse")


class PermissionMatrix:
    """Evaluador deny-by-default sobre el registro del amigo.

    El estado vive en ``FriendRecord.permissions`` (serializable); esta
    clase aporta la lógica de evaluación y las operaciones de edición
    con auditoría.
    """

    def __init__(self, audit=None):
        self._lock = threading.RLock()
        self._audit = audit  # AuditLog opcional

    # -- evaluación --------------------------------------------------------
    def check(self, friend_permissions: dict, action: str,
              resource: str = "") -> bool:
        """¿Permite la matriz ``friend_permissions`` la acción sobre el
        resource? deny-by-default: acciones ausentes o allow=False -> False."""
        if not isinstance(friend_permissions, dict):
            return False
        entry = friend_permissions.get(action)
        if not entry:
            return False
        if not entry.get("allow"):
            return False
        return self.scope_allows(action, list(entry.get("scopes") or []), resource)

    def scope_allows(self, action: str, scopes: list[str],
                     resource: str = "") -> bool:
        """Glob-match del recurso contra los scopes concedidos. Sin scopes
        o con ``"*"`` -> cualquier recurso. Un recurso vacío (''), usado
        por acciones sin recurso (p. ej. chat:converse), siempre pasa si
        la acción está concedida."""
        if not resource:
            return True
        if not scopes or "*" in scopes:
            return True
        return any(fnmatch.fnmatch(resource, pat) for pat in scopes)

    # -- edición con auditoría ---------------------------------------------
    def grant(self, friend_permissions: dict, action: str,
              scopes: list[str] | None = None, audit=None) -> dict:
        with self._lock:
            friend_permissions[action] = {
                "allow": True, "scopes": [str(s) for s in (scopes or [])]}
        self._log(audit, "permiso.grant", action=action, result="allow",
                  scopes=scopes)
        return friend_permissions

    def revoke(self, friend_permissions: dict, action: str,
               audit=None) -> dict:
        with self._lock:
            if action in friend_permissions:
                del friend_permissions[action]
        self._log(audit, "permiso.revoke", action=action, result="deny")
        return friend_permissions

    def _log(self, audit, event, **kw):
        if audit is not None:
            audit.event(event, **kw)


# Conveniencia: scopes de ejemplo para archivos/comandos
def path_scopes(*globs: str) -> list[str]:
    """Scopes file:read/file:write como globs de rutas."""
    return list(globs)


def command_scopes(*prefixes: str) -> list[str]:
    """Scopes exec:terminal como prefijos de comando permitidos."""
    return list(prefixes)
