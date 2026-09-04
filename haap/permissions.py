# -*- coding: utf-8 -*-
"""Per-friend permission matrix: deny-by-default with scopes.

Action catalog (each agent stores in its Directory, PER FRIEND, what
that friend may do AGAINST this agent; ``me -> friend`` actions are
governed by the same keys on the local side as outbound guards — see
ARQUITECTURA.md, permission table):

  chat:converse     friend may open conversational exchanges/pings
  read:schedule     friend may query the agent's schedule
  read:calendar     friend may query the agent's calendar
  file:read         friend may READ files (scopes: path globs)
  file:write        friend may WRITE files (scopes: destination paths)
  exec:terminal     friend may request command execution (scopes:
                    allowed command prefixes, e.g. "haap ")
  task:delegate     (inbound) friend may DELEGATE tasks to me -> I execute
  task:submit       (outbound) local guard: I may delegate tasks to this
                    friend (the friend's server will in turn require me
                    to hold task:delegate in THEIR matrix)

``scopes`` semantics: list of strings. The matcher applies globs
(fnmatch) over the request ``resource``; an empty list or a list
containing ``"*"`` allows any resource for that action. Any action NOT
listed in the friend's ``permissions`` = denied (deny by default).
All decisions are audited.
"""

from __future__ import annotations

import fnmatch
import threading

# Inbound actions the server checks against the friend's matrix.
INBOUND_ACTIONS = (
    "chat:converse", "read:schedule", "read:calendar",
    "file:read", "file:write", "exec:terminal", "task:delegate",
)
# Outbound actions the client checks as a local guard.
OUTBOUND_ACTIONS = ("task:submit", "chat:converse")


class PermissionMatrix:
    """Deny-by-default evaluator over the friend record.

    State lives in ``FriendRecord.permissions`` (serializable); this
    class provides the evaluation logic and audited edit operations.
    """

    def __init__(self, audit=None):
        self._lock = threading.RLock()
        self._audit = audit  # optional AuditLog

    # -- evaluation --------------------------------------------------------
    def check(self, friend_permissions: dict, action: str,
              resource: str = "") -> bool:
        """Does ``friend_permissions`` allow ``action`` on ``resource``?
        Deny-by-default: missing actions or allow=False -> False."""
        if not isinstance(friend_permissions, dict):
            return False
        entry = friend_permissions.get(action)
        if not entry:
            return False
        if not entry.get("allow"):
            return False
        return self.scope_allows(action, list(entry.get("scopes") or []),
                                 resource)

    def scope_allows(self, action: str, scopes: list[str],
                     resource: str = "") -> bool:
        """Glob-match the resource against granted scopes. No scopes or
        a ``"*"`` scope -> any resource. An empty resource (''), used by
        actions without a resource (e.g. chat:converse), always passes if
        the action is granted."""
        if not resource:
            return True
        if not scopes or "*" in scopes:
            return True
        return any(fnmatch.fnmatch(resource, pat) for pat in scopes)

    # -- audited edits -----------------------------------------------------
    def grant(self, friend_permissions: dict, action: str,
              scopes: list[str] | None = None, audit=None) -> dict:
        with self._lock:
            friend_permissions[action] = {
                "allow": True, "scopes": [str(s) for s in (scopes or [])]}
        self._log(audit, "permission.grant", action=action, result="allow",
                  scopes=scopes)
        return friend_permissions

    def revoke(self, friend_permissions: dict, action: str,
               audit=None) -> dict:
        with self._lock:
            if action in friend_permissions:
                del friend_permissions[action]
        self._log(audit, "permission.revoke", action=action, result="deny")
        return friend_permissions

    def _log(self, audit, event, **kw):
        if audit is not None:
            audit.event(event, **kw)


# Convenience: example scopes for files/commands
def path_scopes(*globs: str) -> list[str]:
    return [str(g) for g in globs]


def command_scopes(*prefixes: str) -> list[str]:
    return [str(p) for p in prefixes]
