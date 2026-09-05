# -*- coding: utf-8 -*-
"""Shared HAAP tool surface for agent hosts (Hermes plugin, MCP server).

One implementation, several facades: the Hermes plugin
(``haap.hermes_plugin``) and the MCP server (``haap.mcp_server``) both expose
exactly the tools defined here, so a new tool appears everywhere at once.

* ``merge_config(raw)`` — defaults < ``raw`` dict < ``HAAP_HERMES_*`` env.
* ``HaapRuntime`` — identity bootstrap, optional in-process HAAP server,
  directory registration + heartbeat, lazy ``HAAPClient``; notifier-agnostic
  (hosts pass their own owner-notification objects).
* ``tool_schemas()`` — JSON-Schema descriptions of every ``haap_*`` tool.
* ``build_handlers(runtime)`` — ``name -> handler(params, **kw) -> JSON str``.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Callable, Optional

from . import __version__

TOOLSET = "haap"
DEFAULT_DIRECTORY_URL = "https://acoalex.com/haap-directory"
ENV_PREFIX = "HAAP_HERMES_"

DEFAULTS: dict[str, Any] = {
    "haap_dir": "",                 # "" -> $HAAP_DIR or ~/.haap
    "name": "hermes-agent",         # display name used when creating identity
    "endpoint": "",                 # public messaging URL (…/haap/messages)
    "speciality": "",
    "host": "0.0.0.0",
    "port": 8443,
    "serve": True,                  # run the HAAP server in-process
    "directory_url": DEFAULT_DIRECTORY_URL,
    "auto_register": True,          # register in the directory on startup
    "heartbeat_interval_s": 6 * 3600,
    "notify_owner": True,           # host-native owner notifications
    "webhook_url": "",              # optional WebhookNotifier target (Hermes route)
    "webhook_secret": "",
    "webhook_format": "hermes-v2",  # hermes-v2 | legacy
}

_TRUE = ("1", "true", "yes", "on")


def _coerce(default: Any, value: Any) -> Any:
    if isinstance(default, bool):
        return value.strip().lower() in _TRUE if isinstance(value, str) else bool(value)
    if isinstance(default, int):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    return str(value) if value is not None else default


def merge_config(raw: Optional[dict] = None) -> dict:
    """defaults < ``raw`` (host config) < ``HAAP_HERMES_<KEY>`` environment."""
    raw = raw or {}
    cfg = dict(DEFAULTS)
    for key, default in DEFAULTS.items():
        if key in raw and raw[key] is not None:
            cfg[key] = _coerce(default, raw[key])
        env = os.environ.get(ENV_PREFIX + key.upper())
        if env is not None:
            cfg[key] = _coerce(default, env)
    if not cfg["haap_dir"]:
        cfg["haap_dir"] = os.environ.get("HAAP_DIR", os.path.expanduser("~/.haap"))
    return cfg


def to_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def ok(**fields: Any) -> str:
    return to_json({"success": True, **fields})


def err(exc: BaseException) -> str:
    return to_json({
        "success": False,
        "error": str(exc) or exc.__class__.__name__,
        "code": getattr(exc, "code", None),
    })


class HaapRuntime:
    """Owns identity, the in-process HAAP server, registration and heartbeat."""

    def __init__(
        self,
        cfg: dict,
        log: Optional[Callable[[str], None]] = None,
        notifiers: Optional[list] = None,
    ):
        self.cfg = cfg
        self.log = log or (lambda msg: None)
        self.extra_notifiers = list(notifiers or [])
        self._lock = threading.RLock()
        self.identity = None
        self.server = None
        self.http = None
        self.heartbeat = None
        self.registration: dict = {"status": "not_attempted"}
        self._client = None

    # -- identity ----------------------------------------------------------
    def ensure_identity(self):
        from .identity import IdentityStore

        with self._lock:
            if self.identity is not None:
                return self.identity
            store = IdentityStore(self.cfg["haap_dir"])
            if store.exists():
                ident = store.load()
                if self.cfg["endpoint"] and ident.endpoint_url != self.cfg["endpoint"]:
                    ident.endpoint_url = self.cfg["endpoint"]
                    store.save(ident)
            else:
                ident = store.create(self.cfg["name"], endpoint_url=self.cfg["endpoint"])
                self.log(f"created HAAP identity {ident.fingerprint} in {self.cfg['haap_dir']}")
            self.identity = ident
            return ident

    def directory(self):
        from .directory import Directory

        return Directory(self.cfg["haap_dir"])

    def client(self):
        from .audit import AuditLog
        from .client import HAAPClient

        with self._lock:
            if self._client is None:
                self._client = HAAPClient(
                    self.ensure_identity(), self.directory(),
                    audit=AuditLog(self.cfg["haap_dir"]),
                )
            return self._client

    def _notifier(self):
        from .policy import CompositeNotifier, ConsoleNotifier, WebhookNotifier

        notifiers = [ConsoleNotifier()]
        if self.cfg["notify_owner"]:
            notifiers.extend(self.extra_notifiers)
        if self.cfg["webhook_url"]:
            notifiers.append(WebhookNotifier(
                self.cfg["webhook_url"], self.cfg["webhook_secret"],
                fmt=self.cfg["webhook_format"],
            ))
        return CompositeNotifier(*notifiers)

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        """Idempotent: start the server + registration/heartbeat."""
        with self._lock:
            if self.server is not None:
                return
            ident = self.ensure_identity()
            if self.cfg["serve"]:
                from .audit import AuditLog
                from .server import HAAPServer

                self.server = HAAPServer(
                    ident, self.directory(),
                    audit=AuditLog(self.cfg["haap_dir"]),
                    speciality=self.cfg["speciality"],
                    notifier=self._notifier(),
                )
                self.http = self.server.start(host=self.cfg["host"], port=int(self.cfg["port"]))
                self.log(
                    f"HAAP server {ident.fingerprint} listening on "
                    f"{self.cfg['host']}:{self.http.server_address[1]}"
                )
            if self.cfg["auto_register"] and self.cfg["endpoint"]:
                threading.Thread(target=self._register_and_heartbeat, daemon=True).start()

    def bound_port(self) -> Optional[int]:
        return self.http.server_address[1] if self.http else None

    def _register_and_heartbeat(self) -> None:
        try:
            result = self.register_now()
            self.log(f"registered in directory: {result}")
        except Exception as exc:  # noqa: BLE001
            self.registration = {"status": "error", "error": str(exc)}
            self.log(f"directory registration failed: {exc}")
        try:
            from .registry_client import HeartbeatLoop

            self.heartbeat = HeartbeatLoop(
                self.cfg["directory_url"], self.ensure_identity().fingerprint,
                interval_s=int(self.cfg["heartbeat_interval_s"]),
            ).start()
        except Exception as exc:  # noqa: BLE001
            self.log(f"heartbeat loop not started: {exc}")

    def register_now(self, directory_url: Optional[str] = None) -> dict:
        from .registry_client import register

        url = directory_url or self.cfg["directory_url"]
        result = register(
            url, self.ensure_identity(), self.cfg["endpoint"],
            speciality=self.cfg["speciality"],
        )
        self.registration = {"status": "registered", "directory_url": url, **result}
        return result

    def stop(self) -> None:
        with self._lock:
            if self.heartbeat is not None:
                self.heartbeat.stop()
                self.heartbeat = None
            if self.server is not None:
                self.server.stop()
                self.server = None
                self.http = None

    def status(self) -> dict:
        ident = self.ensure_identity()
        return {
            "haap_version": __version__,
            "fingerprint": ident.fingerprint,
            "name": ident.display_name,
            "endpoint": ident.endpoint_url,
            "speciality": self.cfg["speciality"],
            "haap_dir": self.cfg["haap_dir"],
            "server_running": self.server is not None,
            "server_port": self.bound_port(),
            "directory_url": self.cfg["directory_url"],
            "registration": self.registration,
            "heartbeat_running": self.heartbeat is not None,
        }


# -- tool schemas -------------------------------------------------------------
def _fp(desc: str = "HAAP fingerprint (HF-…)") -> dict:
    return {"type": "string", "description": desc}


def tool_schemas() -> dict[str, dict]:
    """``name -> {description, parameters}`` (JSON Schema for parameters)."""
    return {
        "haap_whoami": {
            "description": "Show this agent's HAAP identity, server/registration status and directory.",
            "parameters": {"type": "object", "properties": {}},
        },
        "haap_friends": {
            "description": (
                "Manage HAAP friendships: list friends, list pending requests, "
                "approve (with a role: guest|client|partner|family|admin), deny, block or remove."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string",
                               "enum": ["list", "requests", "approve", "deny", "block", "remove"]},
                    "fingerprint": _fp("Target fingerprint (approve/deny/block/remove)"),
                    "role": {"type": "string", "description": "Role to grant on approve (default guest)"},
                },
                "required": ["action"],
            },
        },
        "haap_add_friend": {
            "description": "Start a friendship handshake with another HAAP agent (hello → challenge → friend_request).",
            "parameters": {
                "type": "object",
                "properties": {
                    "fingerprint": _fp(),
                    "public_key_b64": {"type": "string", "description": "Peer Ed25519 public key (base64)"},
                    "endpoint": {"type": "string", "description": "Peer base endpoint URL"},
                    "name": {"type": "string"},
                    "speciality": {"type": "string"},
                },
                "required": ["fingerprint", "public_key_b64", "endpoint"],
            },
        },
        "haap_delegate_task": {
            "description": "Delegate a task to an accepted HAAP friend and return its result.",
            "parameters": {
                "type": "object",
                "properties": {
                    "fingerprint": _fp("Friend fingerprint"),
                    "prompt": {"type": "string", "description": "Task description"},
                    "action": {"type": "string", "description": "Permission action (default task:submit)"},
                    "resource": {"type": "string"},
                },
                "required": ["fingerprint", "prompt"],
            },
        },
        "haap_service_search": {
            "description": "Query a business agent's open service catalog (marketplace, no friendship needed).",
            "parameters": {
                "type": "object",
                "properties": {
                    "fingerprint": _fp("Business fingerprint"),
                    "endpoint": {"type": "string", "description": "Business base endpoint URL"},
                    "services": {"type": "string"},
                    "date": {"type": "string", "description": "YYYY-MM-DD"},
                },
                "required": ["fingerprint", "endpoint"],
            },
        },
        "haap_service_book": {
            "description": "Book an open service at a business agent (marketplace).",
            "parameters": {
                "type": "object",
                "properties": {
                    "fingerprint": _fp("Business fingerprint"),
                    "endpoint": {"type": "string", "description": "Business base endpoint URL"},
                    "service": {"type": "string"},
                    "when": {"type": "string", "description": "ISO datetime, e.g. 2026-09-10T17:00"},
                },
                "required": ["fingerprint", "endpoint", "service", "when"],
            },
        },
        "haap_registry_search": {
            "description": "Discover HAAP agents in the public directory by capability and/or free text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "capability": {"type": "string"},
                    "q": {"type": "string", "description": "Free-text query"},
                    "directory_url": {"type": "string", "description": "Override the directory URL"},
                },
            },
        },
        "haap_registry_register": {
            "description": "Register (or refresh) this agent in the public HAAP directory now.",
            "parameters": {"type": "object", "properties": {"directory_url": {"type": "string"}}},
        },
    }


def build_handlers(runtime: HaapRuntime) -> dict[str, Callable[..., str]]:
    def whoami(params: dict, **_: Any) -> str:
        try:
            return ok(**runtime.status())
        except Exception as exc:  # noqa: BLE001
            return err(exc)

    def friends(params: dict, **_: Any) -> str:
        try:
            directory = runtime.directory()
            action = str(params.get("action", "list"))
            fp = str(params.get("fingerprint", "") or "")
            if action == "list":
                return ok(friends=[r.to_dict() for r in directory.all()])
            if action == "requests":
                return ok(requests=[r.to_dict() for r in directory.by_status("pending_in")])
            if not fp:
                raise ValueError("fingerprint is required for this action")
            if action == "approve":
                from .roles import resolve_role

                role = str(params.get("role") or "guest")
                _, spec = resolve_role(role, runtime.cfg["haap_dir"])
                rec = directory.approve(
                    fp, grant=dict(spec.get("permissions") or {}),
                    rate_limits=dict(spec.get("rate_limits") or {}),
                )
                return ok(fingerprint=fp, status=rec.status, role=role,
                          granted=sorted(rec.permissions))
            if action == "deny":
                directory.deny(fp)
                return ok(fingerprint=fp, status="denied")
            if action == "block":
                rec = directory.block(fp)
                return ok(fingerprint=fp, status=rec.status)
            if action == "remove":
                directory.remove(fp)
                return ok(fingerprint=fp, status="removed")
            raise ValueError(f"unknown action '{action}'")
        except Exception as exc:  # noqa: BLE001
            return err(exc)

    def add_friend(params: dict, **_: Any) -> str:
        try:
            result = runtime.client().start_friendship(
                str(params["fingerprint"]), str(params["public_key_b64"]),
                str(params["endpoint"]), name=str(params.get("name") or ""),
                speciality=str(params.get("speciality") or ""),
            )
            return ok(result=result)
        except Exception as exc:  # noqa: BLE001
            return err(exc)

    def delegate(params: dict, **_: Any) -> str:
        try:
            result = runtime.client().delegate_task(
                str(params["fingerprint"]), str(params["prompt"]),
                action=str(params.get("action") or "task:submit"),
                resource=str(params.get("resource") or ""),
            )
            return ok(result=result)
        except Exception as exc:  # noqa: BLE001
            return err(exc)

    def service_search(params: dict, **_: Any) -> str:
        try:
            result = runtime.client().service_search(
                str(params["fingerprint"]), str(params["endpoint"]),
                services=str(params.get("services") or ""), date=str(params.get("date") or ""),
            )
            return ok(result=result)
        except Exception as exc:  # noqa: BLE001
            return err(exc)

    def service_book(params: dict, **_: Any) -> str:
        try:
            result = runtime.client().service_book(
                str(params["fingerprint"]), str(params["endpoint"]),
                service=str(params["service"]), when=str(params["when"]),
            )
            return ok(result=result)
        except Exception as exc:  # noqa: BLE001
            return err(exc)

    def registry_search(params: dict, **_: Any) -> str:
        try:
            from .registry_client import search

            url = str(params.get("directory_url") or runtime.cfg["directory_url"])
            results = search(url, capability=str(params.get("capability") or ""),
                             q=str(params.get("q") or ""))
            return ok(directory_url=url, total=len(results), results=results)
        except Exception as exc:  # noqa: BLE001
            return err(exc)

    def registry_register(params: dict, **_: Any) -> str:
        try:
            if not runtime.cfg["endpoint"]:
                raise ValueError("configure the public 'endpoint' first")
            return ok(result=runtime.register_now(params.get("directory_url") or None))
        except Exception as exc:  # noqa: BLE001
            return err(exc)

    return {
        "haap_whoami": whoami,
        "haap_friends": friends,
        "haap_add_friend": add_friend,
        "haap_delegate_task": delegate,
        "haap_service_search": service_search,
        "haap_service_book": service_book,
        "haap_registry_search": registry_search,
        "haap_registry_register": registry_register,
    }
