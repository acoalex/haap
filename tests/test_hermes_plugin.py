# -*- coding: utf-8 -*-
"""Tests for the Hermes Agent plugin (``haap.hermes_plugin``).

A ``FakeCtx`` mimics the Hermes plugin context (register_tool / register_hook /
register_command / register_cli_command / register_skill / inject_message) so
the plugin is exercised end-to-end without a Hermes install: tool registration,
identity bootstrap, in-gateway server start, owner chat notification on friend
requests, friendship approval, directory search/registration and config
resolution.
"""
import base64
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap import envelope as env_mod
from haap.hermes_plugin import PLUGIN_NAME, DEFAULTS, register, resolve_config
from haap.identity import IdentityStore
from haap.registry import RegistryServer
from haap.registry_client import register as registry_register


class FakeCtx:
    """Minimal stand-in for the Hermes plugin ``ctx``."""

    def __init__(self, config=None):
        self.config = config or {}
        self.tools, self.hooks, self.commands, self.cli, self.skills = {}, {}, {}, {}, {}
        self.injected = []

    def register_tool(self, name, toolset, schema, handler, description=None):
        self.tools[name] = (toolset, schema, handler)

    def register_hook(self, event, callback):
        self.hooks.setdefault(event, []).append(callback)

    def register_command(self, name, handler, description=""):
        self.commands[name] = handler

    def register_cli_command(self, name, help, setup_fn, handler_fn):
        self.cli[name] = handler_fn

    def register_skill(self, name, path):
        self.skills[name] = path

    def inject_message(self, content, role="user", **kwargs):
        self.injected.append((role, content))

    def log(self, msg):
        pass


def _entries(tmp_path, **over):
    base = {"haap_dir": str(tmp_path / "haap"), "name": "Plugin Agent",
            "host": "127.0.0.1", "port": 0, "auto_register": False,
            "speciality": "asistente-personal"}
    base.update(over)
    return {"plugins": {"entries": {PLUGIN_NAME: base}}}


def _call(ctx, name, **params):
    return json.loads(ctx.tools[name][2](params))


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def _pub_b64(identity):
    return base64.b64encode(identity.keypair.public_key).decode()


@pytest.fixture()
def plugin(tmp_path):
    ctx = FakeCtx(_entries(tmp_path))
    runtime = register(ctx)
    yield ctx, runtime
    runtime.stop()


@pytest.fixture()
def reference_registry():
    rs = RegistryServer()
    http = rs.start(host="127.0.0.1", port=0)
    yield f"http://127.0.0.1:{http.server_address[1]}"
    rs.stop()


# -- registration surface ---------------------------------------------------
def test_registers_all_surfaces(plugin):
    ctx, _ = plugin
    assert set(ctx.tools) == {
        "haap_whoami", "haap_friends", "haap_add_friend", "haap_delegate_task",
        "haap_service_search", "haap_service_book", "haap_registry_search",
        "haap_registry_register",
    }
    assert all(t[0] == "haap" for t in ctx.tools.values())
    assert "gateway:startup" in ctx.hooks
    assert "haap" in ctx.commands
    assert {"init", "whoami", "friends", "registry"} <= set(ctx.cli)
    assert "haap" in ctx.skills and os.path.exists(os.path.join(ctx.skills["haap"], "SKILL.md"))


def test_identity_bootstrapped_and_whoami(plugin, tmp_path):
    ctx, runtime = plugin
    out = _call(ctx, "haap_whoami")
    assert out["success"] is True
    assert out["fingerprint"].startswith("HF-")
    assert out["server_running"] is False  # gateway hook not fired yet
    assert (tmp_path / "haap" / "identity.json").exists()
    # Re-register with the same dir reuses the identity (no new keys).
    ctx2 = FakeCtx(_entries(tmp_path))
    rt2 = register(ctx2)
    assert rt2.ensure_identity().fingerprint == out["fingerprint"]


# -- gateway runtime ----------------------------------------------------------
def test_gateway_startup_starts_server(plugin):
    ctx, runtime = plugin
    ctx.hooks["gateway:startup"][0]()
    port = runtime.bound_port()
    assert port
    base = f"http://127.0.0.1:{port}"
    assert _get(f"{base}/health")["status"] == "ok"
    manifest = _get(f"{base}/.well-known/haap.json")
    assert manifest["agent"]["fingerprint"] == runtime.identity.fingerprint
    assert manifest["agent"]["speciality"] == "asistente-personal"
    assert _call(ctx, "haap_whoami")["server_running"] is True
    # Idempotent: a second startup does not rebind.
    ctx.hooks["gateway:startup"][0]()
    assert runtime.bound_port() == port


def test_friend_request_reaches_owner_chat_and_can_be_approved(plugin, tmp_path):
    ctx, runtime = plugin
    ctx.hooks["gateway:startup"][0]()
    server, me = runtime.server, runtime.identity
    peer = IdentityStore(str(tmp_path / "peer")).create("Peer Agent")

    # hello -> challenge -> friend_request against the in-gateway router.
    reply = server.handle_message(env_mod.sign_body(
        peer, "hello", me.fingerprint, {"public_key_b64": _pub_b64(peer), "name": "Peer Agent"}))
    challenge = reply["payload"]["challenge"]
    sig = base64.b64encode(peer.keypair.sign(challenge.encode("ascii"))).decode()
    server.handle_message(env_mod.sign_body(
        peer, "challenge", me.fingerprint,
        {"challenge": challenge, "signature": sig, "public_key_b64": _pub_b64(peer),
         "name": "Peer Agent"}))
    reply3 = server.handle_message(env_mod.sign_body(
        peer, "friend_request", me.fingerprint,
        {"public_key_b64": _pub_b64(peer), "name": "Peer Agent",
         "message": "let's collaborate",
         "capabilities": {"speciality": "citas-peluqueria"}}))
    assert reply3["payload"]["pending_human"] is True

    # The owner sees an actionable card in the Hermes chat.
    assert len(ctx.injected) == 1
    role, text = ctx.injected[0]
    assert role == "user"
    assert f"haap friends approve {peer.fingerprint}" in text
    assert "let's collaborate" in text

    # And can decide through the tool.
    pending = _call(ctx, "haap_friends", action="requests")
    assert [r["fingerprint"] for r in pending["requests"]] == [peer.fingerprint]
    approved = _call(ctx, "haap_friends", action="approve", fingerprint=peer.fingerprint, role="client")
    assert approved["success"] and approved["status"] == "accepted" and approved["granted"]
    listed = _call(ctx, "haap_friends", action="list")
    assert listed["friends"][0]["status"] == "accepted"


def test_friends_tool_validates_input(plugin):
    ctx, _ = plugin
    out = _call(ctx, "haap_friends", action="approve")  # missing fingerprint
    assert out["success"] is False and "fingerprint" in out["error"]
    out2 = _call(ctx, "haap_friends", action="bogus", fingerprint="HF-0000000000000000")
    assert out2["success"] is False


# -- directory --------------------------------------------------------------
def test_registry_search_tool(plugin, reference_registry, tmp_path):
    ctx, _ = plugin
    biz = IdentityStore(str(tmp_path / "biz")).create("Peluqueria")
    registry_register(reference_registry, biz, "http://biz.example:8443/haap/messages",
                      speciality="citas-peluqueria")
    out = _call(ctx, "haap_registry_search", capability="citas-peluqueria",
                directory_url=reference_registry)
    assert out["success"] and out["total"] == 1
    assert out["results"][0]["agent"]["fingerprint"] == biz.fingerprint


def test_registry_register_requires_endpoint(plugin):
    ctx, _ = plugin
    out = _call(ctx, "haap_registry_register")
    assert out["success"] is False and "endpoint" in out["error"]


def test_auto_register_and_heartbeat_on_startup(tmp_path, reference_registry):
    ctx = FakeCtx(_entries(
        tmp_path, endpoint="http://127.0.0.1:9/haap/messages", auto_register=True,
        directory_url=reference_registry, serve=False, heartbeat_interval_s=3600))
    runtime = register(ctx)
    try:
        ctx.hooks["gateway:startup"][0]()
        deadline = time.time() + 5
        while runtime.registration.get("status") == "not_attempted" and time.time() < deadline:
            time.sleep(0.05)
        assert runtime.registration["status"] == "registered", runtime.registration
        assert runtime.registration["directory_url"] == reference_registry
        # Listed in the directory and heartbeat loop armed.
        found = _get(f"{reference_registry}/search?capability=asistente-personal")["results"]
        assert found and found[0]["agent"]["fingerprint"] == runtime.identity.fingerprint
        deadline = time.time() + 2
        while runtime.heartbeat is None and time.time() < deadline:
            time.sleep(0.05)
        assert runtime.heartbeat is not None
    finally:
        runtime.stop()


# -- config, slash command, CLI ---------------------------------------------
def test_resolve_config_shapes_and_env(tmp_path, monkeypatch):
    full = FakeCtx({"plugins": {"entries": {PLUGIN_NAME: {"port": "9001", "serve": "false"}}}})
    cfg = resolve_config(full)
    assert cfg["port"] == 9001 and cfg["serve"] is False
    assert cfg["directory_url"] == DEFAULTS["directory_url"]
    entries_only = FakeCtx({"port": 9002})
    assert resolve_config(entries_only)["port"] == 9002
    monkeypatch.setenv("HAAP_HERMES_PORT", "9003")
    monkeypatch.setenv("HAAP_HERMES_HAAP_DIR", str(tmp_path / "x"))
    cfg3 = resolve_config(entries_only)
    assert cfg3["port"] == 9003 and cfg3["haap_dir"] == str(tmp_path / "x")


def test_slash_command_and_cli_forwarding(plugin, capsys):
    ctx, runtime = plugin
    status = json.loads(ctx.commands["haap"]("status"))
    assert status["fingerprint"] == runtime.identity.fingerprint
    assert "usage" in ctx.commands["haap"]("nonsense")
    rc = ctx.cli["whoami"]([])
    assert rc == 0
    assert runtime.identity.fingerprint in capsys.readouterr().out


# -- marketplace over real HTTP ----------------------------------------------
def test_marketplace_tools_over_http(plugin, tmp_path):
    """service_search/service_book go through HttpTransport to a business agent."""
    from haap.audit import AuditLog
    from haap.directory import Directory
    from haap.server import HAAPServer

    ctx, _ = plugin
    biz = IdentityStore(str(tmp_path / "biz")).create("Peluqueria Euraka")
    bookings = []

    def write_to_calendar(task_id, payload):
        bookings.append(payload)
        return {"estado": "reservada", "cita": payload.get("when")}

    business = HAAPServer(
        biz, Directory(str(tmp_path / "biz")), audit=AuditLog(memory=True),
        speciality="citas-peluqueria",
        marketplace_catalog={"corte": {"price_eur": 15, "duration_min": 30}},
        marketplace_policy={"auto_accept": True, "open_hours": "10:00-19:00"},
    )
    business.on_task = write_to_calendar
    http = business.start(host="127.0.0.1", port=0)
    endpoint = f"http://127.0.0.1:{http.server_address[1]}"
    try:
        quote = _call(ctx, "haap_service_search", fingerprint=biz.fingerprint,
                      endpoint=endpoint, services="corte", date="2026-09-10")
        assert quote["success"], quote
        assert "corte" in json.dumps(quote["result"])
        booked = _call(ctx, "haap_service_book", fingerprint=biz.fingerprint,
                       endpoint=endpoint, service="corte", when="2026-09-10T17:00")
        assert booked["success"], booked
        assert bookings and bookings[0]["service"] == "corte"
    finally:
        business.stop()
