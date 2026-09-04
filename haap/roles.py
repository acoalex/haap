# -*- coding: utf-8 -*-
"""Named permission roles for friend approvals.

A role bundles a permission matrix + rate limits + optional expiry, so
the human owner approves a friend_request with one word instead of
hand-crafting matrices (error-prone).

Built-in roles (overridable per instance via ``$HAAP_DIR/roles.json``):

  guest    — conversational ping only, minimal rate limits
  client   — marketplace-style booking scopes, low rate limits
  partner  — task delegation with broad scopes, medium rate limits
  family   — + calendar/schedule reads, high rate limits
  admin    — everything (file/exec included), maximum rate limits.
             Use only for agents you fully control.

Semantics: a role's matrix describes what the APPROVED agent may do
AGAINST this agent (mirrored as the outbound guard on their side).
"""

from __future__ import annotations

import json
import os

from .identity import haap_dir

ROLES_FILENAME = "roles.json"

BUILTIN_ROLES: dict[str, dict] = {
    "guest": {
        "description": "Conversational access only (pings, chat). No tasks.",
        "permissions": {
            "chat:converse": {"allow": True, "scopes": []},
        },
        "rate_limits": {"*": {"capacity": 10, "refill_per_sec": 0.05}},
        "ttl_days": None,
    },
    "client": {
        "description": "Marketplace client: booking scopes, no file/exec.",
        "permissions": {
            "chat:converse": {"allow": True, "scopes": []},
            "task:delegate": {"allow": True, "scopes": ["booking:*", "service:*"]},
            "task:submit": {"allow": True, "scopes": ["booking:*", "service:*"]},
        },
        "rate_limits": {"*": {"capacity": 20, "refill_per_sec": 0.1},
                        "task_request": {"capacity": 5, "refill_per_sec": 0.05}},
        "ttl_days": None,
    },
    "partner": {
        "description": "Trusted partner: task delegation with broad scopes.",
        "permissions": {
            "chat:converse": {"allow": True, "scopes": []},
            "read:schedule": {"allow": True, "scopes": []},
            "read:calendar": {"allow": True, "scopes": []},
            "task:delegate": {"allow": True, "scopes": ["*"]},
            "task:submit": {"allow": True, "scopes": ["*"]},
        },
        "rate_limits": {"*": {"capacity": 60, "refill_per_sec": 0.5}},
        "ttl_days": None,
    },
    "family": {
        "description": "Family/full-personal: + calendar and schedule reads "
                       "with high rate limits.",
        "permissions": {
            "chat:converse": {"allow": True, "scopes": []},
            "read:schedule": {"allow": True, "scopes": []},
            "read:calendar": {"allow": True, "scopes": []},
            "task:delegate": {"allow": True, "scopes": ["*"]},
            "task:submit": {"allow": True, "scopes": ["*"]},
        },
        "rate_limits": {"*": {"capacity": 120, "refill_per_sec": 1.0}},
        "ttl_days": None,
    },
    "admin": {
        "description": "Full trust (file/exec included). Only for agents "
                       "you fully control.",
        "permissions": {
            "chat:converse": {"allow": True, "scopes": []},
            "read:schedule": {"allow": True, "scopes": []},
            "read:calendar": {"allow": True, "scopes": []},
            "file:read": {"allow": True, "scopes": ["*"]},
            "file:write": {"allow": True, "scopes": ["*"]},
            "exec:terminal": {"allow": True, "scopes": ["haap *"]},
            "task:delegate": {"allow": True, "scopes": ["*"]},
            "task:submit": {"allow": True, "scopes": ["*"]},
        },
        "rate_limits": {"*": {"capacity": 240, "refill_per_sec": 2.0}},
        "ttl_days": None,
    },
}


def roles_path(directory: str | None = None) -> str:
    return os.path.join(directory or haap_dir(), ROLES_FILENAME)


def load_roles(directory: str | None = None) -> dict[str, dict]:
    """Built-in roles merged with user overrides from roles.json.
    A user role may also reference ``extends`` to inherit from a built-in:
    ``{"my-role": {"extends": "partner", "permissions": {...overrides...}}}``.
    Invalid entries are skipped (never break the server)."""
    roles = {k: json.loads(json.dumps(v)) for k, v in BUILTIN_ROLES.items()}
    path = roles_path(directory)
    if not os.path.exists(path):
        return roles
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
    except (OSError, ValueError):
        return roles
    if not isinstance(user, dict):
        return roles
    for name, spec in user.items():
        if not isinstance(name, str) or not isinstance(spec, dict):
            continue
        base_name = spec.get("extends")
        base = dict(roles.get(base_name, {})) if isinstance(base_name, str) else {}
        merged = {**base, **{k: v for k, v in spec.items() if k != "extends"}}
        roles[name] = merged
    return roles


def resolve_role(name: str, directory: str | None = None) -> tuple[str, dict]:
    """Resolve a role name to (name, spec). Raises KeyError-ish ValueError
    on unknown roles."""
    roles = load_roles(directory)
    if name not in roles:
        raise ValueError(f"unknown role '{name}'. Known: {', '.join(sorted(roles))}")
    return name, roles[name]


def role_summary(directory: str | None = None) -> str:
    """One-line-per-role summary for CLI listing."""
    lines = []
    for name, spec in load_roles(directory).items():
        actions = ", ".join(sorted((spec.get("permissions") or {}).keys()))
        lines.append(f"{name:<10} {spec.get('description', '')[:60]}  [{actions}]")
    return "\n".join(lines)
