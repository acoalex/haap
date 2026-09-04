# -*- coding: utf-8 -*-
"""Friend-request policy engine + human notifications.

Every inbound ``friend_request`` is evaluated against a policy with
three outcomes (evaluated in order):

  1. **deny**         — sender is blocklisted (or policy says deny-all):
                        immediate rejection, no owner interaction.
  2. **auto-approve** — a rule matches (explicit fingerprint allowlist,
                        or open policy with a role cap): the friendship is
                        accepted automatically with that role's template.
                        The requester is told exactly what was granted.
  3. **queue**        — default: the request is stored as pending_in and
                        the owner is notified to decide.

The policy lives in ``$HAAP_DIR/policy.json`` (human-editable):

    {
      "default": "queue",            // queue | deny
      "auto_approve": [              // rules, first match wins
        {"fingerprint": "HF-3f7a9c1b2d4e5f60", "role": "partner"},
        {"speciality": "citas-peluqueria", "role": "client"}
      ],
      "max_role": "partner"          // cap for auto-approvals
    }

Notifications are sent through a ``Notifier``; the default writes to
stdout/stderr (visible in the service logs) and ``WebhookNotifier``
POSTs a signed JSON payload (ideal target: a Hermes webhook that lands
in the owner's chat).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

from .errors import PermissionDeniedError
from .identity import haap_dir
from .roles import load_roles, resolve_role

POLICY_FILENAME = "policy.json"
DEFAULT_MAX_ROLE = "partner"     # auto-approval never exceeds this role
PENDING_TTL_DAYS = 7             # undecided requests expire


def policy_path(directory: str | None = None) -> str:
    return os.path.join(directory or haap_dir(), POLICY_FILENAME)


def load_policy(directory: str | None = None) -> dict:
    path = policy_path(directory)
    if not os.path.exists(path):
        return {"default": "queue", "auto_approve": [],
                "max_role": DEFAULT_MAX_ROLE}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            policy = json.load(fh)
    except (OSError, ValueError):
        return {"default": "queue", "auto_approve": [],
                "max_role": DEFAULT_MAX_ROLE}
    policy.setdefault("default", "queue")
    policy.setdefault("auto_approve", [])
    policy.setdefault("max_role", DEFAULT_MAX_ROLE)
    return policy


class RequestPolicy:
    """Evaluates inbound friend_requests against policy.json + roles."""

    def __init__(self, directory: str | None = None):
        self.directory = directory
        self.policy = load_policy(directory)

    # -- evaluation --------------------------------------------------------
    def evaluate(self, sender_fp: str, payload: dict) -> tuple[str, dict]:
        """Return (decision, context) where decision is one of
        'deny' | 'auto' | 'queue' and context carries the resolved role
        and a human-readable reason."""
        requested_role = str(payload.get("requested_role", "")) or None
        speciality = str((payload.get("capabilities") or {}).get(
            "speciality", "")) or str(payload.get("speciality", ""))

        # 1. explicit deny rules / deny-all default
        if self.policy.get("default") == "deny" and not self._auto_rule(
                sender_fp, speciality):
            return "deny", {"reason": "policy default is deny"}

        # 2. auto-approve rules (fingerprint or speciality match)
        rule = self._auto_rule(sender_fp, speciality)
        if rule:
            role = self._cap_role(rule.get("role") or requested_role
                                  or "guest")
            return "auto", {"role": role,
                            "reason": f"matched rule {rule}"}

        # 3. queue for human decision
        role = self._cap_role(requested_role) if requested_role else None
        return "queue", {"role": role,
                         "reason": "no auto-approve rule matched"}

    def _auto_rule(self, sender_fp: str, speciality: str) -> dict | None:
        for rule in self.policy.get("auto_approve") or []:
            if not isinstance(rule, dict):
                continue
            if rule.get("fingerprint") and rule["fingerprint"] == sender_fp:
                return rule
            if rule.get("speciality") and speciality and \
                    speciality.lower() == str(rule["speciality"]).lower():
                return rule
        return None

    def _cap_role(self, role_name: str | None) -> str:
        """Auto-approvals can never exceed max_role (ladder guest < client
        < partner < family < admin; user roles are treated as partner-
        capped unless explicitly allowlisted)."""
        ladder = ["guest", "client", "partner", "family", "admin"]
        max_role = self.policy.get("max_role", DEFAULT_MAX_ROLE)
        if role_name in ladder:
            cap = ladder.index(max_role) if max_role in ladder else \
                ladder.index(DEFAULT_MAX_ROLE)
            return ladder[min(ladder.index(role_name), cap)]
        return "client"  # unknown/custom roles auto-approve capped at client


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------
class BaseNotifier:
    """Interface: notify(request: dict) -> None. Must never raise."""

    def notify(self, request: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class ConsoleNotifier(BaseNotifier):
    """Prints the request to stdout/stderr (visible in service logs)."""

    def __init__(self, stream=None):
        import sys
        self.stream = stream or sys.stderr

    def notify(self, request: dict) -> None:
        try:
            print("\n=== HAAP FRIEND REQUEST (pending your approval) ===",
                  file=self.stream)
            print(f"  from:    {request.get('fingerprint')}", file=self.stream)
            print(f"  name:    {request.get('name', '')}", file=self.stream)
            print(f"  message: {request.get('message', '')}", file=self.stream)
            print(f"  wants:   role '{request.get('requested_role')}' "
                  f"→ would grant '{request.get('suggested_role')}'", file=self.stream)
            print(f"  decide:  haap friends approve {request.get('fingerprint')} "
                  f"--role {request.get('suggested_role')}", file=self.stream)
            print("======================================================\n",
                  file=self.stream)
        except Exception:
            pass


class WebhookNotifier(BaseNotifier):
    """POSTs a signed JSON payload to a URL (HMAC-SHA256 over the body).

    Target: a Hermes webhook subscription that lands in the owner's chat,
    so the approval command can be copied straight from the phone.
    """

    def __init__(self, url: str, secret: str):
        self.url = url
        self.secret = secret.encode()

    def notify(self, request: dict) -> None:
        try:
            body = json.dumps(request, ensure_ascii=False).encode("utf-8")
            sig = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
            req = urllib_request_post(self.url, body, sig)
        except Exception:
            pass  # notification failures never break the protocol


def urllib_request_post(url: str, body: bytes, signature: str) -> None:
    import urllib.request
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "X-HAAP-Signature": f"sha256={signature}"})
    urllib.request.urlopen(req, timeout=5)


class CompositeNotifier(BaseNotifier):
    """Fan-out to several notifiers (all errors swallowed)."""

    def __init__(self, *notifiers: BaseNotifier):
        self.notifiers = notifiers

    def notify(self, request: dict) -> None:
        for n in self.notifiers:
            try:
                n.notify(request)
            except Exception:
                pass


def build_request(fingerprint: str, name: str, message: str,
                  requested_role: str | None, suggested_role: str | None,
                  capabilities: dict | None = None) -> dict:
    """Canonical payload for a human-facing friend-request notification."""
    return {
        "type": "haap.friend_request",
        "ts": round(time.time(), 3),
        "fingerprint": fingerprint,
        "name": name,
        "message": (message or "")[:300],
        "requested_role": requested_role,
        "suggested_role": suggested_role,
        "capabilities": capabilities or {},
        "how_to_approve": f"haap friends approve {fingerprint} --role {suggested_role}",
        "how_to_deny": f"haap friends deny {fingerprint}",
    }
