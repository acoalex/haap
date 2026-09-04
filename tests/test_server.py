# -*- coding: utf-8 -*-
"""Tests del servidor HAAP: handshake completo, autorización y abuso.

Dos agentes (A y B) en proceso, acoplados directamente al router de B
(el mismo código que ejecuta la capa HTTP). Los mensajes de bootstrap
(hello, friend_request) llevan la clave pública del emisor en el payload
(verificación autocontenida: fingerprint == SHA-256(clave)).
"""
import base64
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap import envelope as env_mod
from haap.audit import AuditLog
from haap.directory import Directory
from haap.identity import IdentityStore
from haap.rate_limiter import RateLimiter
from haap.server import HAAPServer


@pytest.fixture()
def two_agents(tmp_path):
    """(id_A, id_B, server_A, server_B) con routers en memoria."""
    dir_a = tmp_path / "a"; dir_b = tmp_path / "b"
    id_a = IdentityStore(str(dir_a)).create("Agente A")
    id_b = IdentityStore(str(dir_b)).create("Agente B (negocio)")

    server_a = HAAPServer(id_a, Directory(str(dir_a)), audit=AuditLog(memory=True))
    server_b = HAAPServer(id_b, Directory(str(dir_b)), audit=AuditLog(memory=True),
                          speciality="citas-peluqueria")
    return id_a, id_b, server_a, server_b


def _pub_b64(identity) -> str:
    return base64.b64encode(identity.keypair.public_key).decode()


def test_handshake_completo_hasta_amistad(two_agents):
    id_a, id_b, sa, sb = two_agents

    # 1. A -> B: hello (incluye clave pública; B devuelve challenge)
    env = env_mod.sign_body(id_a, "hello", id_b.fingerprint,
                            {"public_key_b64": _pub_b64(id_a),
                             "name": "Agente Personal"})
    reply = sb.handle_message(env)
    assert reply["message_type"] == "hello_ack"
    challenge = reply["payload"]["challenge"]

    # 2. A firma el challenge (prueba de posesión de la clave privada)
    sig = base64.b64encode(
        id_a.keypair.sign(challenge.encode("ascii"))).decode()
    env2 = env_mod.sign_body(id_a, "challenge", id_b.fingerprint,
                             {"challenge": challenge, "signature": sig,
                              "public_key_b64": _pub_b64(id_a),
                              "name": "Agente Personal"})
    reply2 = sb.handle_message(env2)
    assert reply2["message_type"] == "verify"
    assert reply2["payload"]["verified"] is True
    assert sb.directory.get(id_a.fingerprint) is not None

    # 3. A -> B: friend_request formal (queda pending_in en B)
    env3 = env_mod.sign_body(id_a, "friend_request", id_b.fingerprint,
                             {"public_key_b64": _pub_b64(id_a),
                              "name": "Agente Personal",
                              "capabilities": {"speciality": "asistente-personal"}})
    reply3 = sb.handle_message(env3)
    assert reply3["message_type"] == "friend_request"
    assert sb.directory.get(id_a.fingerprint).status == "pending_in"

    # 4. APROBACIÓN HUMANA en B (con permisos concretos)
    rec = sb.directory.approve(
        id_a.fingerprint,
        grant={"task:submit": {"allow": True, "scopes": ["booking:*"]}})
    assert rec.status == "accepted"

    # 5. B -> A: friend_accept (A ya tenía pending_out) -> accepted
    sa.directory.add_pending_out(id_b.fingerprint, _pub_b64(id_b), "Negocio")
    env4 = env_mod.sign_body(id_b, "friend_accept", id_a.fingerprint,
                             {"endpoint": "http://negocio.example:8443/haap/messages"})
    reply4 = sa.handle_message(env4)
    assert sa.directory.get(id_b.fingerprint).status == "accepted"
    assert sb.directory.get(id_a.fingerprint).status == "accepted"


def _establecer_amistad(sb, sa, id_a, id_b, grant=None, rate_limits=None):
    """Atajo: amistad ya aprobada en B y conocida en A."""
    sb.directory.register_known(id_a.fingerprint, _pub_b64(id_a), name="A")
    sb.directory.approve(id_a.fingerprint, grant=grant, rate_limits=rate_limits)
    sa.directory.register_known(id_b.fingerprint, _pub_b64(id_b), name="B")
    sa.directory.mark_outbound_accepted(id_b.fingerprint)


def test_task_request_aceptada_con_permiso(two_agents):
    id_a, id_b, sa, sb = two_agents
    _establecer_amistad(sb, sa, id_a, id_b,
                        grant={"task:submit": {"allow": True, "scopes": ["booking:*"]}})
    resultados = {}
    sb.on_task = lambda task_id, payload: (
        resultados.update({task_id: payload}),
        {"cita": "jueves 17:00", "estado": "reservada"})[1]
    env = env_mod.sign_body(id_a, "task_request", id_b.fingerprint,
                            {"action": "task:submit", "resource": "booking:peluqueria-x",
                             "prompt": "Reservar jueves 17:00 corte"})
    reply = sb.handle_message(env)
    assert reply["message_type"] == "task_result"
    assert reply["payload"]["state"] == "completed"
    assert reply["payload"]["detail"]["estado"] == "reservada"
    assert resultados


def test_task_sin_amistad_rechazada(two_agents):
    id_a, id_b, sa, sb = two_agents
    sb.directory.register_known(id_a.fingerprint, _pub_b64(id_a), name="A")
    env = env_mod.sign_body(id_a, "task_request", id_b.fingerprint,
                            {"action": "task:submit", "prompt": "hola"})
    reply = sb.handle_message(env)
    assert reply["message_type"] == "error"
    assert reply["payload"]["error_code"] == "FRIEND_NOT_FOUND"


def test_task_permiso_denegado(two_agents):
    id_a, id_b, sa, sb = two_agents
    sb.directory.register_known(id_a.fingerprint, _pub_b64(id_a), name="A")
    sb.directory.approve(id_a.fingerprint,
                         grant={"task:submit": {"allow": False, "scopes": []}})
    env = env_mod.sign_body(id_a, "task_request", id_b.fingerprint,
                            {"action": "task:submit", "prompt": "x"})
    reply = sb.handle_message(env)
    assert reply["message_type"] == "error"
    assert reply["payload"]["error_code"] == "PERMISSION_DENIED"


def test_task_rate_limit(two_agents):
    id_a, id_b, sa, sb = two_agents
    _establecer_amistad(sb, sa, id_a, id_b,
                        grant={"task:submit": {"allow": True, "scopes": ["*"]}},
                        rate_limits={"task:submit": {"capacity": 1,
                                                     "refill_per_sec": 0.0001}})
    sb.on_task = lambda task_id, payload: {"done": True}
    r1 = sb.handle_message(env_mod.sign_body(
        id_a, "task_request", id_b.fingerprint,
        {"action": "task:submit", "prompt": "uno"}))
    assert r1["message_type"] == "task_result"
    r2 = sb.handle_message(env_mod.sign_body(
        id_a, "task_request", id_b.fingerprint,
        {"action": "task:submit", "prompt": "dos"}))
    assert r2["message_type"] == "error"
    assert r2["payload"]["error_code"] == "RATE_LIMITED"


# --------------------------------------------------------------- seguridad
def test_firma_invalida_rechazada(two_agents):
    id_a, id_b, sa, sb = two_agents
    sb.directory.register_known(id_a.fingerprint, _pub_b64(id_a), name="A")
    env = env_mod.sign_body(id_a, "ping", id_b.fingerprint, {})
    env["signature"] = base64.b64encode(b"x" * 64).decode()
    reply = sb.handle_message(env)
    assert reply["message_type"] == "error"
    assert reply["payload"]["error_code"] == "BAD_SIGNATURE"


def test_replay_rechazado(two_agents):
    id_a, id_b, sa, sb = two_agents
    sb.directory.register_known(id_a.fingerprint, _pub_b64(id_a), name="A")
    env = env_mod.sign_body(id_a, "ping", id_b.fingerprint, {"n": 1})
    r1 = sb.handle_message(env)
    assert r1["message_type"] == "ping"
    r2 = sb.handle_message(env)  # mismo envelope: nonce repetido
    assert r2["message_type"] == "error"
    assert r2["payload"]["error_code"] == "NONCE_REPLAY"


def test_timestamp_fuera_de_ventana(two_agents):
    id_a, id_b, sa, sb = two_agents
    sb.directory.register_known(id_a.fingerprint, _pub_b64(id_a), name="A")
    old = env_mod.sign_body(id_a, "ping", id_b.fingerprint, {},
                            timestamp=int(time.time()) - 4000)
    reply = sb.handle_message(old)
    assert reply["message_type"] == "error"
    assert reply["payload"]["error_code"] == "CLOCK_SKEW"


def test_emisor_desconocido_rechazado(two_agents):
    id_a, id_b, sa, sb = two_agents
    env = env_mod.sign_body(id_a, "ping", id_b.fingerprint, {})
    reply = sb.handle_message(env)  # ping no es bootstrap: no hay clave
    assert reply["message_type"] == "error"
    assert reply["payload"]["error_code"] == "BAD_SIGNATURE"


def test_bootstrap_con_clave_falsa_rechazado(two_agents):
    """Un impostor no puede hacerse pasar por A ni con clave propia
    (el fingerprint no coincidiría) ni con la fingerprint de A."""
    id_a, id_b, sa, sb = two_agents
    impostor = IdentityStore(str(two_agents[0].keypair)[:0] or None) \
        if False else None
    # clave aleatoria falsa con el fingerprint de A: SHA-256 no coincidirá
    from haap.crypto import KeyPair
    fake = KeyPair.generate()
    fake_b64 = base64.b64encode(fake.public_key).decode()
    env = env_mod.sign_body(id_a, "hello", id_b.fingerprint,
                            {"public_key_b64": fake_b64})
    reply = sb.handle_message(env)
    assert reply["message_type"] == "error"
    assert reply["payload"]["error_code"] == "BAD_SIGNATURE"


# -------------------------------------------------------------- well-known
def test_well_known_manifest_sin_claves(two_agents):
    id_a, id_b, sa, sb = two_agents
    manifest = sb.well_known_manifest()
    assert manifest["agent"]["fingerprint"] == id_b.fingerprint
    assert manifest["agent"]["speciality"] == "citas-peluqueria"
    raw = str(manifest)
    assert "private" not in raw.lower()


# -------------------------------------------------------------------- HTTP
def test_http_layer_end_to_end(two_agents):
    """La capa HTTP real (ThreadingHTTPServer) entrega al router correcto."""
    import json as _json
    import urllib.request
    id_a, id_b, sa, sb = two_agents
    http = sb.start(host="127.0.0.1", port=0)
    port = http.server_address[1]
    try:
        # health + manifest
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health", timeout=5) as r:
            assert _json.loads(r.read())["status"] == "ok"
        env = env_mod.sign_body(id_a, "hello", id_b.fingerprint,
                                {"public_key_b64": _pub_b64(id_a), "name": "A"})
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/haap/messages",
            data=env_mod.envelope_to_bytes(env),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            reply = _json.loads(r.read())
        assert reply["message_type"] == "hello_ack"
        assert "challenge" in reply["payload"]
    finally:
        sb.stop()
