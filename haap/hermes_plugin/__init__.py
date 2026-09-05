# -*- coding: utf-8 -*-
"""Hermes Agent plugin for HAAP (``hermes-haap``).

Turns HAAP into a native Hermes capability with a single install step:

* **Tools** the model can call (``haap_*``) — defined once in ``haap.tools``
  and shared with the MCP server (``haap.mcp_server``).
* **Gateway runtime**: on ``gateway:startup`` the HAAP messaging server is
  started *inside* the gateway process, the agent is registered in the public
  directory and a heartbeat loop keeps the entry alive. Identity is created
  automatically on first run.
* **Owner notifications**: queued friend requests are injected into the
  owner's Hermes chat with the ready-to-copy approve/deny commands (and,
  optionally, POSTed to a Hermes webhook route — see ``webhook_url``).
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

import os
import shlex
import traceback
from typing import Any, Callable

from ..tools import (  # noqa: F401 - re-exported for hosts/tests
    DEFAULTS,
    TOOLSET,
    HaapRuntime,
    build_handlers,
    merge_config,
    to_json,
    tool_schemas,
)

PLUGIN_NAME = "hermes-haap"


def resolve_config(ctx: Any) -> dict:
    """Accept either the plugin's ``plugins.entries.<id>`` block or the full
    Hermes config dict, then apply defaults and ``HAAP_HERMES_*`` env."""
    raw = getattr(ctx, "config", None) or {}
    if not isinstance(raw, dict):
        raw = {}
    plugins = raw.get("plugins")
    if isinstance(plugins, dict):
        raw = (plugins.get("entries") or {}).get(PLUGIN_NAME) or {}
    return merge_config(raw)


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


# -- slash command & CLI ------------------------------------------------------
def _slash_haap(runtime: HaapRuntime, handlers: dict) -> Callable[..., str]:
    def handle(args: str = "", **_: Any) -> str:
        parts = shlex.split(args or "")
        sub = parts[0] if parts else "status"
        if sub == "status":
            return to_json({"plugin": PLUGIN_NAME, **runtime.status()})
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
        return haap_main(["--dir", runtime.cfg["haap_dir"], subcommand, *rest])

    return handler


_CLI_SUBCOMMANDS = ("init", "whoami", "friends", "capabilities", "task", "registry", "audit", "mcp")


# -- entry point --------------------------------------------------------------
def register(ctx: Any) -> HaapRuntime:
    """Hermes plugin entry point. Returns the runtime (handy for tests)."""
    log = getattr(ctx, "log", None)
    if not callable(log):
        def log(msg: str) -> None:  # noqa: E306
            print(f"[{PLUGIN_NAME}] {msg}")

    cfg = resolve_config(ctx)
    chat_notifier = HermesChatNotifier(ctx)
    runtime = HaapRuntime(cfg, log=log, notifiers=[chat_notifier])
    runtime.chat_notifier = chat_notifier  # type: ignore[attr-defined]
    handlers = build_handlers(runtime)

    for name, schema in tool_schemas().items():
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
