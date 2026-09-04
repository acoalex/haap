# -*- coding: utf-8 -*-
"""HAAP messaging server.

Pure HTTP (``http.server`` ThreadingHTTPServer, zero new dependencies):

  * ``POST /haap/messages``          — entry point for signed envelopes.
  * ``GET  /.well-known/haap.json``  — public manifest (A2A-style, no keys).
  * ``GET  /health``                 — liveness.

Friendship state machine (both sides):

    hello -> (challenge) -> friend_request -> [HUMAN approval] ->
    friend_accept -> task_request/task_accept/task_result

Handlers are injectable: ``on_friend_request`` and ``on_task`` let you
wire the server into Hermes (webhook -> owner chat; task execution).
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
    """HAAP server for one agent. ``directory``/``identity`` come from
    the eponymous modules; the callbacks connect to the outside world
    (Hermes, the human owner, task executors)."""

    def __init__(self, identity, directory: Directory, *,
                 audit: AuditLog | None = None,
                 permissions: PermissionMatrix | None = None,
                 rate_limiter: RateLimiter | None = None,
                 tasks: TaskRegistry | None = None,
                 speciality: str = "",
                 marketplace_catalog: dict | None = None,
                 marketplace_policy: dict | None = None,
                 on_friend_request=None,   # cb(fp, manifest) -> None (notify owner)
                 on_task=None,             # cb(task_id, payload) -> None | dict (result)
                 skills_dirs: list[str] | None = None,
                 extra_tools: list[str] | None = None):
        self.identity = identity
        self.directory = directory
        self.audit = audit or AuditLog(memory=True)
        self.permissions = permissions or PermissionMatrix(audit=self.audit)
        self.rate_limiter = rate_limiter or RateLimiter()
        self.tasks = tasks or TaskRegistry(memory=True)
        self.speciality = speciality
        self.marketplace_catalog = marketplace_catalog  # service -> info/price
        self.marketplace_policy = marketplace_policy    # e.g. {"auto_accept": True}
        self.on_friend_request = on_friend_request
        self.on_task = on_task
        self.skills_dirs = skills_dirs
        self.extra_tools = extra_tools
        self.nonces = env_mod.NonceManager()
        self._pending_challenges: dict[str, tuple[str, float]] = {}
        self._lock = threading.RLock()
        self._http = None

    # ------------------------------------------------------------------ utils
    def public_keys(self) -> dict[str, bytes]:
        """Trusted keys: friends (incl. pending) + ourselves."""
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
    # Bootstrap messages carry the sender's public key in the payload:
    # they arrive precisely when the receiver does not know the sender yet
    # (friendship bootstrap AND marketplace open-services).
    BOOTSTRAP_TYPES = frozenset({"hello", "challenge", "friend_request",
                                 "service_search", "service_book",
                                 "service_cancel", "service_quote"})

    def _resolve_sender_pubkey(self, envelope: dict) -> bytes | None:
        """Sender's public key: from the directory if known; for bootstrap
        messages (hello, friend_request) also the one embedded in the
        payload (self-contained verification: fingerprint == SHA-256(key)
        and a valid signature with that key — trust comes later from the
        challenge and human approval, not from the self-declared key)."""
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
                "fingerprint does not match the declared public key")
        return raw

    def handle_message(self, envelope: dict) -> dict:
        """Pure router (also useful for tests with MemoryTransport).
        Verifies and dispatches; converts HAAPError into an ``error`` envelope."""
        sender = envelope.get("sender_fingerprint", "?")
        try:
            env_mod.envelope_from_bytes(env_mod.envelope_to_bytes(envelope))
            sender_pub = self._resolve_sender_pubkey(envelope)
            if sender_pub is None:
                raise SignatureError(
                    f"sender {sender} has no registered public key; "
                    "signature cannot be verified")
            verified = env_mod.verify_envelope(
                envelope, {sender: sender_pub}, nonces=self.nonces)
        except HAAPError as exc:
            self._audit("message.rejected", sender, result="error",
                        detail={"error": type(exc).__name__, "msg": str(exc)[:120]})
            return self._error_reply(envelope, exc)
        mtype = verified["message_type"]
        handler = getattr(self, f"_on_{mtype}", None)
        if handler is None:
            return self._error_reply(envelope,
                                     HAAPError(f"unhandled type: {mtype}"))
        try:
            reply = handler(verified)
        except HAAPError as exc:
            self._audit(f"message.{mtype}", sender, result="error",
                        detail={"error": type(exc).__name__})
            return self._error_reply(envelope, exc)
        self._audit(f"message.{mtype}", sender)
        return reply or {}

    def _error_reply(self, envelope: dict, exc: HAAPError) -> dict:
        code = getattr(exc, "code", type(exc).__name__)
        return env_mod.sign_body(
            self.identity, "error", envelope.get("sender_fingerprint", ""),
            {"error_code": code, "detail": str(exc)[:200],
             "in_reply_to_nonce": envelope.get("nonce", "")})

    # ------------------------------------------------------ friendship handshake
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
            raise HAAPError("no pending challenge for this sender")
        expected, issued = pending
        if time.time() - issued > 120:
            raise HAAPError("challenge expired (>120s)")
        if challenge != expected:
            raise HAAPError("challenge mismatch")
        # In bootstrap the sender declares its public key in the payload;
        # the router already verified fingerprint == SHA-256(key) and that
        # the envelope signature is valid with it.
        from .crypto import b64d, KeyPair
        raw_pub = b64d(str(payload.get("public_key_b64", ""))) \
            if payload.get("public_key_b64") else \
            self.directory.public_keys().get(env["sender_fingerprint"])
        if raw_pub is None:
            raise SignatureError("sender's public key unknown")
        if not KeyPair.verify_with(
                raw_pub, challenge.encode("ascii"), base64.b64decode(sig_b64)):
            raise SignatureError("invalid challenge signature")
        # Identity proven: register as a known sender (pending_in)
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
        rec.notes = "friend_request received"
        self.directory.upsert(rec)
        if self.on_friend_request:
            try:
                self.on_friend_request(fp, payload.get("capabilities") or {})
            except Exception:
                pass  # notifications must never break the protocol
        return env_mod.sign_body(self.identity, "friend_request", fp,
                                 {"received": True,
                                  "note": "awaiting human approval"})

    def _on_friend_accept(self, env: dict) -> dict:
        self.directory.mark_outbound_accepted(
            env["sender_fingerprint"],
            their_endpoints=[str(env["payload"].get("endpoint", ""))]
            if env["payload"].get("endpoint") else None)
        return env_mod.sign_body(self.identity, "ping", env["sender_fingerprint"],
                                 {"note": "friendship established"})

    # ---------------------------------------------------------------- tasks
    def _on_task_request(self, env: dict) -> dict:
        sender = env["sender_fingerprint"]
        rec = self.directory.require(sender, statuses=("accepted",))
        action = str(env["payload"].get("action") or "task:submit")
        resource = str(env["payload"].get("resource") or "")
        if not rec.has_permission(action) or not self.permissions.check(
                rec.permissions, action, resource):
            raise PermissionDeniedError(f"permission {action} denied for {sender}")
        self.rate_limiter.check(sender, action, rec.rate_limits)  # raises if exceeded
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
            # Synchronous path: submitted -> accepted -> completed (legal transitions)
            self.tasks.update(task.task_id, "accepted")
            self.tasks.update(task.task_id, "completed", detail=result_out)
            return env_mod.sign_body(self.identity, "task_result", sender,
                                     {"task_id": task.task_id, "state": "completed",
                                      "detail": result_out})
        # Asynchronous path: submitted -> accepted (result will arrive as task_result)
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

    # ------------------------------------------------------------ marketplace
    # Open-services handlers: no friendship required, but the sender MUST
    # pass self-contained verification (signed envelope + fingerprint/key
    # binding, already enforced by the router for bootstrap types) and the
    # business policy (rate limit + service rules) decides acceptance.

    def _check_marketplace_sender(self, env: dict) -> str:
        """Shared checks for open-service messages: fingerprint validity,
        not blocked, and marketplace rate limit. Returns the sender fp."""
        sender = env["sender_fingerprint"]
        rec = self.directory.get(sender)
        if rec is not None and rec.status == "blocked":
            raise PermissionDeniedError(f"{sender} is blocked")
        # dedicated marketplace rate limit (stricter than friend limits)
        self.rate_limiter.check(sender, "marketplace",
                                {"marketplace": {"capacity": 10,
                                                 "refill_per_sec": 0.05},
                                 "*": {"capacity": 20,
                                       "refill_per_sec": 0.1}})
        return sender

    def _on_service_search(self, env: dict) -> dict:
        sender = self._check_marketplace_sender(env)
        p = env["payload"]
        services = str(p.get("services", "")).lower()
        service_date = str(p.get("date", ""))
        # the business answers with its availability from its own policy;
        # the default implementation reports the catalog it publishes
        catalog = self.marketplace_catalog or {}
        matched = {k: v for k, v in catalog.items()
                   if not services or services in k.lower()
                   or k.lower() in services}
        self._audit("marketplace.search", sender)
        return env_mod.sign_body(self.identity, "service_quote", sender,
                                 {"query": {"services": services,
                                            "date": service_date},
                                  "available": bool(matched),
                                  "services": matched,
                                  "policy": self.marketplace_policy})

    def _on_service_book(self, env: dict) -> dict:
        sender = self._check_marketplace_sender(env)
        p = env["payload"]
        service = str(p.get("service", ""))
        when = str(p.get("when", ""))
        policy = self.marketplace_policy or {}
        if not policy.get("auto_accept", False):
            raise PermissionDeniedError(
                "this business does not accept automated bookings "
                "(auto_accept disabled)")
        booking = {"service": service, "when": when,
                   "client_fingerprint": sender, "status": "reserved"}
        if self.on_task:
            # reuse the task pipeline so the booking hits the business
            # backend (e.g. CalDAV calendar write)
            task = self.tasks.create(role="server",
                                     friend_fingerprint=sender,
                                     prompt=f"marketplace booking {service} {when}",
                                     action="booking:reserve",
                                     resource=service)
            try:
                result = self.on_task(task.task_id, p)
            except Exception as exc:
                self.tasks.update(task.task_id, "failed",
                                  detail={"error": str(exc)[:200]})
                return env_mod.sign_body(self.identity, "error", sender,
                                         {"error_code": "TASK_ERROR",
                                          "detail": str(exc)[:200],
                                          "in_reply_to_nonce": env["nonce"]})
            booking.update(result if isinstance(result, dict) else {})
            self.tasks.update(task.task_id, "accepted")
            self.tasks.update(task.task_id, "completed", detail=booking)
        self._audit("marketplace.book", sender, detail={"service": service})
        return env_mod.sign_body(self.identity, "task_result", sender,
                                 {"task_id": f"MKT-{int(time.time())}",
                                  "state": "completed", "detail": booking})

    def _on_service_cancel(self, env: dict) -> dict:
        sender = self._check_marketplace_sender(env)
        p = env["payload"]
        self._audit("marketplace.cancel", sender,
                    detail={"booking_id": str(p.get("booking_id", ""))[:40]})
        return env_mod.sign_body(self.identity, "task_result", sender,
                                 {"task_id": str(p.get("booking_id", "")),
                                  "state": "completed",
                                  "detail": {"cancelled": True}})

    def _on_service_quote(self, env: dict) -> dict:
        # a quote arriving at a business is unexpected; acknowledge politely
        return self._error_reply(env, HAAPError("service_quote not expected here"))

    # -------------------------------------------------------------- HTTP layer
    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence default logging
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
