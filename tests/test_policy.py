# -*- coding: utf-8 -*-
"""Tests for roles + friend-request policy + notifications."""
import base64
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap import envelope as env_mod
from haap.audit import AuditLog
from haap.directory import Directory
from haap.identity import IdentityStore
from haap.policy import (
    ConsoleNotifier, RequestPolicy, build_request, load_policy,
)
from haap.roles import BUILTIN_ROLES, load_roles, resolve_role
from haap.server import HAAPServer


def _pub(ident):
    return base64.b64encode(ident.keypair.public_key).decode()


def _mp_env(sender, recipient_fp, payload):
    payload = dict(payload)
    payload["public_key_b64"] = _pub(sender)
    return env_mod.sign_body(sender, "friend_request", recipient_fp, payload)


# ------------------------------------------------------------------- roles
def test_builtin_roles_load_and_shape(tmp_path):
    roles = load_roles(str(tmp_path))
    assert set(roles) >= {"guest", "client", "partner", "family", "admin"}
    # deny-by-default respected: guest cannot delegate tasks
    assert "task:delegate" not in roles["guest"]["permissions"]
    # admin includes exec
    assert roles["admin"]["permissions"]["exec:terminal"]["allow"] is True


def test_user_role_override_with_extends(tmp_path):
    (tmp_path / "roles.json").write_text(json.dumps({
        "vip": {"extends": "partner",
                "description": "VIP clients",
                "rate_limits": {"*": {"capacity": 500,
                                      "refill_per_sec": 5.0}}}}))
    name, spec = resolve_role("vip", str(tmp_path))
    assert name == "vip"
    # inherited from partner:
    assert spec["permissions"]["task:submit"]["allow"] is True
    # overridden rate limits:
    assert spec["rate_limits"]["*"]["capacity"] == 500


def test_unknown_role_raises(tmp_path):
    with pytest.raises(ValueError):
        resolve_role("noexiste", str(tmp_path))


# ------------------------------------------------------------------ policy
def test_policy_default_queues(tmp_path):
    policy = RequestPolicy(str(tmp_path))
    decision, ctx = policy.evaluate("HF-aaaaaaaaaaaaaaaa", {})
    assert decision == "queue"


def test_policy_auto_approve_by_fingerprint(tmp_path):
    (tmp_path / "policy.json").write_text(json.dumps({
        "auto_approve": [{"fingerprint": "HF-bbbbbbbbbbbbbbbb",
                          "role": "partner"}]}))
    policy = RequestPolicy(str(tmp_path))
    decision, ctx = policy.evaluate("HF-bbbbbbbbbbbbbbbb", {})
    assert decision == "auto"
    assert ctx["role"] == "partner"


def test_policy_auto_approve_by_speciality_capped(tmp_path):
    (tmp_path / "policy.json").write_text(json.dumps({
        "auto_approve": [{"speciality": "citas-peluqueria",
                          "role": "admin"}],
        "max_role": "client"}))
    policy = RequestPolicy(str(tmp_path))
    # even though the rule says admin, the cap is client
    decision, ctx = policy.evaluate(
        "HF-cccccccccccccccc",
        {"capabilities": {"speciality": "citas-peluqueria"}})
    assert decision == "auto"
    assert ctx["role"] == "client"


def test_policy_deny_default(tmp_path):
    (tmp_path / "policy.json").write_text(json.dumps({"default": "deny"}))
    policy = RequestPolicy(str(tmp_path))
    decision, _ = policy.evaluate("HF-dddddddddddddddd", {})
    assert decision == "deny"


# ------------------------------------------------------- server integration
def _pair(tmp_path, policy_obj=None, notifier=None):
    id_biz = IdentityStore(str(tmp_path / "biz")).create("Negocio")
    server = HAAPServer(
        id_biz, Directory(str(tmp_path / "biz")), audit=AuditLog(memory=True),
        speciality="citas-peluqueria",
        policy=policy_obj, notifier=notifier)
    client_id = IdentityStore(str(tmp_path / "cli")).create("Cliente")
    return id_biz, server, client_id


def test_queued_request_notifies_and_stays_pending(tmp_path):
    notified = []
    class Capture:
        def notify(self, req):
            notified.append(req)
    id_biz, server, client = _pair(
        tmp_path, notifier=type("N", (), {"notify": Capture().notify})())
    env = _mp_env(client, id_biz.fingerprint, {
        "name": "Agente de Ana", "message": "Hola, soy el asistente de Ana",
        "requested_role": "partner"})
    reply = server.handle_message(env)
    assert reply["message_type"] == "friend_request"
    assert reply["payload"]["pending_human"] is True
    assert len(notified) == 1
    card = notified[0]
    assert card["fingerprint"] == client.fingerprint
    assert "approve" in card["how_to_approve"]
    assert server.directory.get(client.fingerprint).status == "pending_in"


def test_auto_approve_grants_role_and_informs_peer(tmp_path):
    biz_dir = tmp_path / "biz"
    biz_dir.mkdir(parents=True)
    client_dir = tmp_path / "cli"
    # policy first: allow this specific client as 'client' role
    (biz_dir / "policy.json").write_text(json.dumps({
        "auto_approve": [{"fingerprint": "HF-cccccccccccccccc",
                          "role": "client"}],
        "max_role": "partner"}))
    id_biz = IdentityStore(str(biz_dir)).create("Negocio")
    server = HAAPServer(id_biz, Directory(str(biz_dir)),
                        audit=AuditLog(memory=True),
                        speciality="citas-peluqueria")
    # the fingerprint rule must match the actual client; rewrite with it
    client = IdentityStore(str(client_dir)).create("Ana")
    (biz_dir / "policy.json").write_text(json.dumps({
        "auto_approve": [{"fingerprint": client.fingerprint,
                          "role": "client"}],
        "max_role": "partner"}))
    server.policy = RequestPolicy(str(biz_dir))
    env = _mp_env(client, id_biz.fingerprint, {"name": "Ana"})
    reply = server.handle_message(env)
    # auto-approve answers with friend_accept and the exact granted matrix
    assert reply["message_type"] == "friend_accept"
    assert reply["payload"]["granted_role"] == "client"
    granted = reply["payload"]["granted"]
    assert granted["task:submit"]["allow"] is True
    assert "file:write" not in granted  # client role has no file rights
    assert server.directory.get(client.fingerprint).status == "accepted"


def test_policy_deny_rejects_immediately(tmp_path):
    biz_dir = tmp_path / "biz"
    biz_dir.mkdir(parents=True)
    (biz_dir / "policy.json").write_text(json.dumps({"default": "deny"}))
    id_biz = IdentityStore(str(biz_dir)).create("Negocio")
    server = HAAPServer(id_biz, Directory(str(biz_dir)),
                        audit=AuditLog(memory=True))
    client = IdentityStore(str(tmp_path / "cli")).create("Cliente")
    env = _mp_env(client, id_biz.fingerprint, {"name": "X"})
    reply = server.handle_message(env)
    assert reply["message_type"] == "error"
    assert reply["payload"]["error_code"] == "FRIEND_REQUEST_DENIED"
    assert server.directory.get(client.fingerprint) is None


def test_console_notifier_prints_card(tmp_path):
    id_biz, server, client = _pair(tmp_path)
    stream = io.StringIO()
    server.notifier = ConsoleNotifier(stream=stream)
    env = _mp_env(client, id_biz.fingerprint, {"name": "Ana",
                                               "requested_role": "client"})
    server.handle_message(env)
    out = stream.getvalue()
    assert "FRIEND REQUEST" in out
    assert client.fingerprint in out
    assert "approve" in out


# ---------------------------------------------------------------- CLI layer
def test_approve_with_role_template(tmp_path):
    id_biz, server, client = _pair(tmp_path)
    env = _mp_env(client, id_biz.fingerprint, {"name": "Ana"})
    server.handle_message(env)  # queued as pending_in
    directory = server.directory
    # human approves with a named role (same code path as the CLI)
    from haap.roles import resolve_role
    _, spec = resolve_role("client", str(tmp_path / "biz"))
    rec = directory.approve(client.fingerprint,
                            grant=dict(spec["permissions"]),
                            rate_limits=dict(spec["rate_limits"]))
    assert rec.status == "accepted"
    assert rec.rate_limits["task_request"]["capacity"] == 5
    # the granted matrix is exactly the role template
    assert rec.permissions == spec["permissions"]
