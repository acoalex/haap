# -*- coding: utf-8 -*-
"""Hermes Agent plugin for HAAP (``hermes-haap``).

Turns HAAP into a native Hermes capability with a single install step:

* **Tools** the model can call (``haap_*``): whoami, friends, delegate a task,
  marketplace search/book, directory search/register, add a friend.
* **Gateway runtime**: on ``gateway:startup`` the HAAP messaging server is
  started *inside* the gateway process (no separate ``haap serve`` service),
  the agent is registered in the public directory and a heartbeat loop keeps
  the entry alive. Identity is created automatically on first run.
* **Owner notifications**: queued friend requests are injected into the
  owner's Hermes chat with the ready-to-copy approve/deny commands.
* **Slash command** ``/haap`` and ``hermes haap <cmd>`` CLI subcommands.

Discovery: pip entry point ``hermes_agent.plugins`` (``hermes-haap``), or a
drop-in directory (``hermes plugins install acoalex/haap``) via the repo-root
shim. Configuration lives in ``~/.hermes/config.yaml`` under
``plugins.entries.hermes-haap`` (env ``HAAP_HERMES_*`` overrides):

    plugins:
      enabled: [hermes-haap]
      entries:
        hermes-haap:
          endpoint: "https://my-agent.example.com:8443/haap/messages"
          speciality: "asistente-personal"
          port: 8443
          directory_url: "https://acoalex.com/haap-directory"

Everything is defensive: a failure inside the plugin never breaks Hermes.
"""

from __future__ import annotations

import json
import os
import shlex
import threading
import traceback
from typing import Any, Callable, Optional

from .. import __version__

PLUGIN_NAME = "hermes-haap"
TOOLSET = "haap"
DEFAULT_DIRECTORY_URL = "https://acoalex.com/haap-directory"

DEFAULTS: dict[str, Any] = {
    "haap_dir": "",                 # "" -> $HAAP_DIR or ~/.haap
    "name": "hermes-agent",         # display name used when creating identity
    "endpoint": "",                 # public messaging URL (…/haap/messages)
    "speciality": "",
    "host": "0.0.0.0",
    "port": 8443,
    "serve": True,                  # run the HAAP server inside the gateway
    "directory_url": DEFAULT_DIRECTORY_URL,
    "auto_register": True,          # register in the directory on startup
    "heartbeat_interval_s": 6 * 3600,
    "notify_owner": True,           # inject friend-request cards into chat
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


def resolve_config(ctx: Any) -> dict:
    """Merge defaults < plugin entries in config.yaml < ``HAAP_HERMES_*`` env.

    Hermes may hand a plugin either its own ``plugins.entries.<id>`` block or
    the full config dict; both shapes are accepted.
    """
    raw = getattr(ctx, "config", None) or {}
    if not isinstance(raw, dict):
        raw = {}
    plugins = raw.get("plugins")
    if isinstance(plugins, dict):
        raw = (plugins.get("entries") or {}).get(PLUGIN_NAME) or {}
    cfg = dict(DEFAULTS)
    for key, default in DEFAULTS.items():
        if key in raw and raw[key] is not None:
            cfg[key] = _coerce(default, raw[key])
        env = os.environ.get("HAAP_HERMES_" + key.upper())
        if env is not None:
            cfg[key] = _coerce(default, env)
    if not cfg["haap_dir"]:
        cfg["haap_dir"] = os.environ.get("HAAP_DIR", os.path.expanduser("~/.haap"))
    return cfg


def _json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def _ok(**fields: Any) -> str:
    return _json({"success": True, **fields})


def _err(exc: BaseException) -> str:
    return _json({
        "success": False,
        "error": str(exc) or exc.__class__.__name__,
        "code": getattr(exc, "code", None),
    })


class HermesChatNotifier:
    """Delivers the friend-request card into the owner's Hermes chat.

    Uses ``ctx.inject_message`` when available; never raises.
    """

    def __init__(self, ctx: Any):
        self.ctx = ctx
        self.delivered: list[dict] = []

    @staticmethod
    def render(card: dict) -> str:
        caps = card.get("capabilities") or {}
        lines = [
            "🤝 HAAP friend request pending your approval",
            f"from: {card.get('name') or '(unnamed)'}  [{card.get('fingerprint')}]",
        ]
        if card.get("message"):
            lines.append(f"message: {card['message']}")
        if caps.get("speciality"):
            lines.append(f"speciality: {caps['speciality']}")
        lines.append(
            f"requested role: {card.get('requested_role') or '-'} → "
            f"suggested: {card.get('suggested_role')}"
        )
        lines.append(f"approve: {card.get('how_to_approve')}")
        lines.append(f"deny:    {card.get('how_to_deny')}")
        return "\n".join(lines)

    def notify(self, card: dict) -> None:
        try:
            text = self.render(card)
            inject = getattr(self.ctx, "inject_message", None)
            if inject is not None:
                try:
                    inject(text, role="user")
                except TypeError:
                    inject(text)
            self.delivered.append(card)
        except Exception:  # noqa: BLE001 - notifications never break the protocol
            pass


class HaapRuntime:
    """Owns identity, the in-gateway HAAP server, registration and heartbeat."""

    def __init__(self, ctx: Any, cfg: dict, log: Optional[Callable[[str], None]] = None):
        self.ctx = ctx
        self.cfg = cfg
        self.log = log or (lambda msg: None)
        self._lock = threading.RLock()
        self.identity = None
        self.server = None
        self.http = None
        self.heartbeat = None
        self.chat_notifier = HermesChatNotifier(ctx)
        self.registration: dict = {"status": "not_attempted"}
        self._client = None

    # -- identity ----------------------------------------------------------
    def ensure_identity(self):
        from ..identity import IdentityStore

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
        from ..directory import Directory

        return Directory(self.cfg["haap_dir"])

    def client(self):
        from ..audit import AuditLog
        from ..client import HAAPClient

        with self._lock:
            if self._client is None:
                self._client = HAAPClient(
                    self.ensure_identity(), self.directory(),
                    audit=AuditLog(self.cfg["haap_dir"]),
                )
            return self._client

    # -- gateway lifecycle -------------------------------------------------
    def start(self) -> None:
        """Idempotent: start server + registration/heartbeat (gateway only)."""
        with self._lock:
            if self.server is not None:
                return
            ident = self.ensure_identity()
            if self.cfg["serve"]:
                from ..audit import AuditLog
                from ..policy import CompositeNotifier, ConsoleNotifier
                from ..server import HAAPServer

                notifiers = [ConsoleNotifier()]
                if self.cfg["notify_owner"]:
                    notifiers.append(self.chat_notifier)
                self.server = HAAPServer(
                    ident, self.directory(),
                    audit=AuditLog(self.cfg["haap_dir"]),
                    speciality=self.cfg["speciality"],
                    notifier=CompositeNotifier(*notifiers),
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
            from ..registry_client import HeartbeatLoop

            self.heartbeat = HeartbeatLoop(
                self.cfg["directory_url"], self.ensure_identity().fingerprint,
                interval_s=int(self.cfg["heartbeat_interval_s"]),
            ).start()
        except Exception as exc:  # noqa: BLE001
            self.log(f"heartbeat loop not started: {exc}")

    def register_now(self, directory_url: Optional[str] = None) -> dict:
        from ..registry_client import register

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
            "plugin": PLUGIN_NAME,
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
def _fp_prop(desc: str = "HAAP fingerprint (HF-… )") -> dict:
    return {"type": "string", "description": desc}


def _schemas() -> dict[str, dict]:
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
                    "fingerprint": _fp_prop("Target fingerprint (approve/deny/block/remove)"),
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
                    "fingerprint": _fp_prop(),
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
                    "fingerprint": _fp_prop("Friend fingerprint"),
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
                    "fingerprint": _fp_prop("Business fingerprint"),
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
                    "fingerprint": _fp_prop("Business fingerprint"),
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
            "parameters": {
                "type": "object",
                "properties": {"directory_url": {"type": "string"}},
            },
        },
    }


def _build_handlers(runtime: HaapRuntime) -> dict[str, Callable[..., str]]:
    def whoami(params: dict, **_: Any) -> str:
        try:
            return _ok(**runtime.status())
        except Exception as exc:  # noqa: BLE001
            return _err(exc)

    def friends(params: dict, **_: Any) -> str:
        try:
            directory = runtime.directory()
            action = str(params.get("action", "list"))
            fp = str(params.get("fingerprint", "") or "")
            if action == "list":
                return _ok(friends=[r.to_dict() for r in directory.all()])
            if action == "requests":
                return _ok(requests=[r.to_dict() for r in directory.by_status("pending_in")])
            if not fp:
                raise ValueError("fingerprint is required for this action")
            if action == "approve":
                from ..roles import resolve_role

                role = str(params.get("role") or "guest")
                _, spec = resolve_role(role, runtime.cfg["haap_dir"])
                rec = directory.approve(
                    fp, grant=dict(spec.get("permissions") or {}),
                    rate_limits=dict(spec.get("rate_limits") or {}),
                )
                return _ok(fingerprint=fp, status=rec.status, role=role,
                           granted=sorted(rec.permissions))
            if action == "deny":
                directory.deny(fp)
                return _ok(fingerprint=fp, status="denied")
            if action == "block":
                rec = directory.block(fp)
                return _ok(fingerprint=fp, status=rec.status)
            if action == "remove":
                directory.remove(fp)
                return _ok(fingerprint=fp, status="removed")
            raise ValueError(f"unknown action '{action}'")
        except Exception as exc:  # noqa: BLE001
            return _err(exc)

    def add_friend(params: dict, **_: Any) -> str:
        try:
            result = runtime.client().start_friendship(
                str(params["fingerprint"]), str(params["public_key_b64"]),
                str(params["endpoint"]), name=str(params.get("name") or ""),
                speciality=str(params.get("speciality") or ""),
            )
            return _ok(result=result)
        except Exception as exc:  # noqa: BLE001
            return _err(exc)

    def delegate(params: dict, **_: Any) -> str:
        try:
            result = runtime.client().delegate_task(
                str(params["fingerprint"]), str(params["prompt"]),
                action=str(params.get("action") or "task:submit"),
                resource=str(params.get("resource") or ""),
            )
            return _ok(result=result)
        except Exception as exc:  # noqa: BLE001
            return _err(exc)

    def service_search(params: dict, **_: Any) -> str:
        try:
            result = runtime.client().service_search(
                str(params["fingerprint"]), str(params["endpoint"]),
                services=str(params.get("services") or ""), date=str(params.get("date") or ""),
            )
            return _ok(result=result)
        except Exception as exc:  # noqa: BLE001
            return _err(exc)

    def service_book(params: dict, **_: Any) -> str:
        try:
            result = runtime.client().service_book(
                str(params["fingerprint"]), str(params["endpoint"]),
                service=str(params["service"]), when=str(params["when"]),
            )
            return _ok(result=result)
        except Exception as exc:  # noqa: BLE001
            return _err(exc)

    def registry_search(params: dict, **_: Any) -> str:
        try:
            from ..registry_client import search

            url = str(params.get("directory_url") or runtime.cfg["directory_url"])
            results = search(url, capability=str(params.get("capability") or ""),
                             q=str(params.get("q") or ""))
            return _ok(directory_url=url, total=len(results), results=results)
        except Exception as exc:  # noqa: BLE001
            return _err(exc)

    def registry_register(params: dict, **_: Any) -> str:
        try:
            if not runtime.cfg["endpoint"]:
                raise ValueError("configure plugins.entries.hermes-haap.endpoint first")
            return _ok(result=runtime.register_now(params.get("directory_url") or None))
        except Exception as exc:  # noqa: BLE001
            return _err(exc)

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


# -- slash command & CLI ------------------------------------------------------
def _slash_haap(runtime: HaapRuntime, handlers: dict) -> Callable[..., str]:
    def handle(args: str = "", **_: Any) -> str:
        parts = shlex.split(args or "")
        sub = parts[0] if parts else "status"
        if sub == "status":
            return _json(runtime.status())
        if sub in ("friends", "requests"):
            return handlers["haap_friends"]({"action": sub if sub == "requests" else "list"})
        if sub == "search":
            return handlers["haap_registry_search"]({"capability": " ".join(parts[1:])})
        if sub == "register":
            return handlers["haap_registry_register"]({})
        return "usage: /haap [status|friends|requests|search <capability>|register]"

    return handle


def _cli_forwarder(runtime: HaapRuntime, subcommand: str) -> Callable[..., Any]:
    """Forward ``hermes haap <subcommand> …`` to the ``haap`` CLI."""

    def handler(args: Any = None, **_: Any) -> Any:
        from ..cli import main as haap_main

        if isinstance(args, str):
            rest = shlex.split(args)
        elif isinstance(args, (list, tuple)):
            rest = [str(a) for a in args]
        elif args is None:
            rest = []
        else:  # argparse.Namespace or similar
            rest = [str(a) for a in (getattr(args, "argv", None) or getattr(args, "args", None) or [])]
        argv = ["--dir", runtime.cfg["haap_dir"], subcommand, *rest]
        return haap_main(argv)

    return handler


_CLI_SUBCOMMANDS = ("init", "whoami", "friends", "capabilities", "task", "registry", "audit")


# -- entry point --------------------------------------------------------------
def register(ctx: Any) -> HaapRuntime:
    """Hermes plugin entry point. Returns the runtime (handy for tests)."""
    log = getattr(ctx, "log", None)
    if not callable(log):
        def log(msg: str) -> None:  # noqa: E306
            print(f"[{PLUGIN_NAME}] {msg}")

    cfg = resolve_config(ctx)
    runtime = HaapRuntime(ctx, cfg, log=log)
    handlers = _build_handlers(runtime)

    for name, schema in _schemas().items():
        try:
            ctx.register_tool(
                name=name, toolset=TOOLSET,
                schema={"name": name, **schema},
                handler=handlers[name],
            )
        except Exception:  # noqa: BLE001 - never break Hermes on a surface mismatch
            log(f"could not register tool {name}: {traceback.format_exc(limit=1).strip()}")

    if hasattr(ctx, "register_hook"):
        try:
            ctx.register_hook("gateway:startup", lambda *a, **k: runtime.start())
        except Exception:  # noqa: BLE001
            log("could not register gateway:startup hook")

    if hasattr(ctx, "register_command"):
        try:
            ctx.register_command(
                name="haap", handler=_slash_haap(runtime, handlers),
                description="HAAP status, friends, directory search",
            )
        except Exception:  # noqa: BLE001
            log("could not register /haap command")

    if hasattr(ctx, "register_cli_command"):
        for sub in _CLI_SUBCOMMANDS:
            try:
                ctx.register_cli_command(
                    name=sub, help=f"haap {sub} (forwarded to the haap CLI)",
                    setup_fn=lambda *a, **k: None, handler_fn=_cli_forwarder(runtime, sub),
                )
            except Exception:  # noqa: BLE001
                log(f"could not register CLI subcommand {sub}")

    if hasattr(ctx, "register_skill"):
        skill_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skill")
        if os.path.exists(os.path.join(skill_path, "SKILL.md")):
            try:
                ctx.register_skill("haap", skill_path)
            except Exception:  # noqa: BLE001
                log("could not register the haap skill")

    setattr(ctx, "haap_runtime", runtime)
    return runtime
