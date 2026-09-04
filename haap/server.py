# -*- coding: utf-8 -*-
"""Servidor de mensajería HAAP.

HTTP puro (``http.server`` ThreadingHTTPServer, cero dependencias nuevas):

  * ``POST /haap/messages``          — punto de entrada de envelopes firmados.
  * ``GET  /.well-known/haap.json``  — manifest público (A2A-style, sin claves).
  * ``GET  /health``                 — liveness.

Máquina de estados de amistad (ambos lados):

    hello -> (challenge) -> friend_request -> [aprobación HUMANA] ->
    friend_accept -> task_request/task_accept/task_result

Los handlers son inyectables: ``on_friend_request`` y ``on_task`` permiten
cablear el servidor a Hermes (webhook → chat del dueño; ejecución de tareas).
"""
from __future__ import annotations

import base64
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import PROTOCOL_VERSION
from . import capabilities as capabilities_mod
from . import envelope as env_mod
from .audit import AuditLog
from .directory import Directory
from .errors import (
    HAAPError, PermissionDeniedError, RateLimitedError, SignatureError,
)
from .permissions import PermissionMatrix
from .rate_limiter import RateLimiter
from .tasks import TaskRegistry


def _b64(n: int = 32) -> str:
    return base64.b64encode(secrets.token_bytes(n)).decode("ascii")


class HAAPServer:
    """Servidor HAAP de un agente. ``directory``/``identity`` vienen de
    los módulos homónimos; los callbacks conectan con el mundo (Hermes,
    humano dueño, ejecutor de tareas)."""

    def __init__(self, identity, directory: Directory, *,
                 audit: AuditLog | None = None,
                 permissions: PermissionMatrix | None = None,
                 rate_limiter: RateLimiter | None = None,
                 tasks: TaskRegistry | None = None,
                 speciality: str = "",
                 on_friend_request=None,   # cb(fp, manifest) -> None (notificar dueño)
                 on_task=None,             # cb(task_id, payload) -> None | dict (resultado)
                 skills_dirs: list[str] | None = None,
                 extra_tools: list[str] | None = None):
        self.identity = identity
        self.directory = directory
        self.audit = audit or AuditLog(memory=True)
        self.permissions = permissions or PermissionMatrix(audit=self.audit)
        self.rate_limiter = rate_limiter or RateLimiter()
        self.tasks = tasks or TaskRegistry(memory=True)
        self.speciality = speciality
        self.on_friend_request = on_friend_request
        self.on_task = on_task
        self.skills_dirs = skills_dirs
        self.extra_tools = extra_tools
        self.nonces = env_mod.NonceManager()
        self._pending_challenges: dict[str, tuple[str, float]] = {}
        self._lock = threading.RLock()
        self._http = None

    # ------------------------------------------------------------------ util
    def public_keys(self) -> dict[str, bytes]:
        """Claves confiables: amigos (incl. pendientes) + yo mismo."""
        keys = self.directory.public_keys()
        keys.setdefault(self.identity.fingerprint,
                        self.identity.keypair.public_key)
        return keys

    def _audit(self, event, sender, result="ok", **kw):
        self.audit.event(event, friend=sender, result=result, **kw)

    # ------------------------------------------------------- manifest / well-known
    def well_known_manifest(self) -> dict:
        return capabilities_mod.public_manifest(
            self.identity, speciality=self.speciality,
            skills_dirs=self.skills_dirs, extra_tools=self.extra_tools)

    # ------------------------------------------------------------- routing
    BOOTSTRAP_TYPES = frozenset({"hello", "challenge", "friend_request"})

    def _resolve_sender_pubkey(self, envelope: dict) -> bytes | None:
        """Clave pública del remitente: del directorio si es conocido; para
        mensajes de bootstrap (hello, friend_request) también la incluida en
        el payload (verificación autocontenida: fingerprint == SHA-256(clave)
        y firma válida con esa clave — la confianza la da luego el challenge
        y la aprobación humana, no la clave auto-declarada)."""
        sender = envelope["sender_fingerprint"]
        known = self.directory.public_keys().get(sender)
        if known is not None or envelope["message_type"] not in self.BOOTSTRAP_TYPES:
            return known
        from .crypto import b64d
        from .identity import fingerprint_of_public_key
        pub_b64 = str((envelope.get("payload") or {}).get("public_key_b64", ""))
        if not pub_b64:
            return None
        raw = b64d(pub_b64)
        if fingerprint_of_public_key(raw) != sender:
            raise SignatureError(
                "fingerprint no corresponde a la clave pública declarada")
        return raw

    def handle_message(self, envelope: dict) -> dict:
        """Router puro (útil también para tests con MemoryTransport).
        Verifica y despacha; convierte HAAPError en envelope ``error``."""
        sender = envelope.get("sender_fingerprint", "?")
        try:
            env_mod.envelope_from_bytes(env_mod.envelope_to_bytes(envelope))
            sender_pub = self._resolve_sender_pubkey(envelope)
            if sender_pub is None:
                raise SignatureError(
                    f"remitente {sender} sin clave pública registrada; "
                    "no se puede verificar la firma")
            verified = env_mod.verify_envelope(
                envelope, {sender: sender_pub}, nonces=self.nonces)
        except HAAPError as exc:
            self._audit("mensaje.rechazado", sender, result="error",
                        detail={"error": type(exc).__name__, "msg": str(exc)[:120]})
            return self._error_reply(envelope, exc)
        mtype = verified["message_type"]
        handler = getattr(self, f"_on_{mtype}", None)
        if handler is None:
            return self._error_reply(envelope,
                                     HAAPError(f"tipo no manejado: {mtype}"))
        try:
            reply = handler(verified)
        except HAAPError as exc:
            self._audit(f"mensaje.{mtype}", sender, result="error",
                        detail={"error": type(exc).__name__})
            return self._error_reply(envelope, exc)
        self._audit(f"mensaje.{mtype}", sender)
        return reply or {}

    def _error_reply(self, envelope: dict, exc: HAAPError) -> dict:
        code = getattr(exc, "code", type(exc).__name__)
        return env_mod.sign_body(
            self.identity, "error", envelope.get("sender_fingerprint", ""),
            {"error_code": code, "detail": str(exc)[:200],
             "in_reply_to_nonce": envelope.get("nonce", "")})

    # ------------------------------------------------------ handshake amistad
    def _on_hello(self, env: dict) -> dict:
        challenge = _b64(32)
        with self._lock:
            self._pending_challenges[env["sender_fingerprint"]] = (
                challenge, time.time())
        return env_mod.sign_body(self.identity, "hello_ack", env["sender_fingerprint"],
                                 {"challenge": challenge,
                                  "protocol_version": PROTOCOL_VERSION})

    def _on_challenge(self, env: dict) -> dict:
        payload = env["payload"]
        challenge = str(payload.get("challenge", ""))
        sig_b64 = str(payload.get("signature", ""))
        with self._lock:
            pending = self._pending_challenges.pop(env["sender_fingerprint"], None)
        if not pending:
            raise HAAPError("sin challenge pendiente para este emisor")
        expected, issued = pending
        if time.time() - issued > 120:
            raise HAAPError("challenge expirado (>120s)")
        if challenge != expected:
            raise HAAPError("challenge no coincide")
        # En bootstrap el emisor declara su clave pública en el payload;
        # el router ya verificó que fingerprint == SHA-256(clave) y que la
        # firma del envelope es válida con ella.
        from .crypto import b64d, KeyPair
        raw_pub = b64d(str(payload.get("public_key_b64", ""))) \
            if payload.get("public_key_b64") else \
            self.directory.public_keys().get(env["sender_fingerprint"])
        if raw_pub is None:
            raise SignatureError("clave pública del emisor desconocida")
        if not KeyPair.verify_with(
                raw_pub, challenge.encode("ascii"), base64.b64decode(sig_b64)):
            raise SignatureError("firma del challenge inválida")
        # Identidad probada: registrar como remitente conocido (pending_in)
        self.directory.register_known(
            env["sender_fingerprint"],
            base64.b64encode(raw_pub).decode("ascii"),
            name=str(payload.get("name", "")),
            endpoints=[str(payload.get("endpoint", ""))] if payload.get("endpoint") else None)
        return env_mod.sign_body(self.identity, "verify", env["sender_fingerprint"],
                                 {"verified": True})

    def _on_friend_request(self, env: dict) -> dict:
        payload = env["payload"]
        fp = env["sender_fingerprint"]
        rec = self.directory.register_known(
            fp, str(payload.get("public_key_b64", "")),
            name=str(payload.get("name", "")))
        rec.status = "pending_in"
        rec.declared_capabilities = dict(payload.get("capabilities") or {})
        rec.notes = "friend_request recibido"
        self.directory.upsert(rec)
        if self.on_friend_request:
            try:
                self.on_friend_request(fp, payload.get("capabilities") or {})
            except Exception:
                pass  # la notificación nunca rompe el protocolo
        return env_mod.sign_body(self.identity, "friend_request", fp,
                                 {"received": True,
                                  "note": "pendiente de aprobación humana"})

    def _on_friend_accept(self, env: dict) -> dict:
        self.directory.mark_outbound_accepted(
            env["sender_fingerprint"],
            their_endpoints=[str(env["payload"].get("endpoint", ""))]
            if env["payload"].get("endpoint") else None)
        return env_mod.sign_body(self.identity, "ping", env["sender_fingerprint"],
                                 {"note": "amistad establecida"})

    # ---------------------------------------------------------------- tareas
    def _on_task_request(self, env: dict) -> dict:
        sender = env["sender_fingerprint"]
        rec = self.directory.require(sender, statuses=("accepted",))
        action = str(env["payload"].get("action") or "task:submit")
        resource = str(env["payload"].get("resource") or "")
        if not rec.has_permission(action) or not self.permissions.check(
                rec.permissions, action, resource):
            raise PermissionDeniedError(f"permiso {action} denegado para {sender}")
        cap, refill = self.rate_limiter.config_for(rec.rate_limits, action)
        self.rate_limiter.check(sender, action, rec.rate_limits)  # lanza si supera
        task = self.tasks.create(
            role="server", friend_fingerprint=sender,
            prompt=str(env["payload"].get("prompt", "")),
            action=action, resource=resource)
        result = None
        if self.on_task:
            try:
                result = self.on_task(task.task_id, env["payload"])
            except Exception as exc:
                self.tasks.update(task.task_id, "failed",
                                  detail={"error": str(exc)[:200]})
                return env_mod.sign_body(self.identity, "task_result", sender,
                                         {"task_id": task.task_id,
                                          "state": "failed",
                                          "detail": {"error": str(exc)[:200]}})
        if result is not None:
            result_out = result if isinstance(result, dict) else {}
            # Path síncrono: submitted -> accepted -> completed (transiciones legales)
            self.tasks.update(task.task_id, "accepted")
            self.tasks.update(task.task_id, "completed", detail=result_out)
            return env_mod.sign_body(self.identity, "task_result", sender,
                                     {"task_id": task.task_id, "state": "completed",
                                      "detail": result_out})
        # Path asíncrono: submitted -> accepted (el resultado llegará con task_result)
        self.tasks.update(task.task_id, "accepted")
        self.tasks.update(task.task_id, "working")
        return env_mod.sign_body(self.identity, "task_accept", sender,
                                 {"task_id": task.task_id})

    def _on_task_result(self, env: dict) -> dict:
        p = env["payload"]
        self.tasks.update(str(p.get("task_id", "")), str(p.get("state", "completed")),
                          detail=p.get("detail") or {})
        return {}

    def _on_ping(self, env: dict) -> dict:
        return env_mod.sign_body(self.identity, "ping", env["sender_fingerprint"],
                                 {"pong": True, "ts": int(time.time())})

    # -------------------------------------------------------------- HTTP layer
    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silenciar logging por defecto
                pass

            def _send_json(self, code, obj):
                body = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/health":
                    return self._send_json(200, {"status": "ok"})
                if self.path == "/.well-known/haap.json":
                    return self._send_json(200, server.well_known_manifest())
                return self._send_json(404, {"error": "not found"})

            def do_POST(self):
                if self.path != "/haap/messages":
                    return self._send_json(404, {"error": "not found"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw = self.rfile.read(length) if length else b"{}"
                    envelope = env_mod.envelope_from_bytes(raw)
                except HAAPError as exc:
                    return self._send_json(400, {"error": str(exc)[:150]})
                reply = server.handle_message(envelope)
                if reply:
                    return self._send_json(200, reply)
                return self._send_json(202, {"status": "accepted"})

        return Handler

    def start(self, host: str = "0.0.0.0", port: int = 8443) -> ThreadingHTTPServer:
        self._http = ThreadingHTTPServer((host, port), self._make_handler())
        self._http.daemon_threads = True
        thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        thread.start()
        return self._http

    def stop(self):
        if self._http:
            self._http.shutdown()
            self._http.server_close()
            self._http = None
