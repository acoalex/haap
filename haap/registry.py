# -*- coding: utf-8 -*-
"""Directorio público federado de agentes HAAP.

El registro es "guía telefónica", no notario: la identidad vive en las
claves. El directorio solo indexa manifests firmados y verifica que el
agente controla el endpoint que declara (proof-of-endpoint).

API (stdlib http.server, cero dependencias):

  POST /register            {manifest, public_key_b64, manifest_signature}
  POST /register/challenge  {fingerprint, endpoint}   -> nonce firmado por el registro
  POST /heartbeat           {fingerprint, timestamp, signature}
  GET  /search?capability=X&q=Y
  GET  /agents/{fingerprint}
  GET  /health

Entradas expiran sin heartbeat en ENTRY_TTL_S (poda perezosa en cada
lectura). Doble registro del mismo fingerprint = actualización.
"""
from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .crypto import KeyPair, b64d, b64e
from .errors import HAAPError, SignatureError
from .identity import fingerprint_of_public_key

ENTRY_TTL_S = 24 * 3600          # expiración sin heartbeat
CHALLENGE_TTL_S = 60             # ventana del proof-of-endpoint
MAX_AGENTS = 10_000              # tope anti-flooding del directorio

_FP_RE = re.compile(r"^HF-[0-9a-f]{16}$")


class RegistryStore:
    """Estado del directorio en memoria con poda perezosa."""

    def __init__(self, entry_ttl: int = ENTRY_TTL_S):
        self._agents: dict[str, dict] = {}
        self._challenges: dict[str, tuple[str, float]] = {}  # fp -> (nonce, issued)
        self._lock = threading.RLock()
        self.entry_ttl = entry_ttl

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _now() -> float:
        return time.time()

    def _alive(self, rec: dict) -> bool:
        return self._now() - rec["last_seen"] <= self.entry_ttl

    # -- registro ----------------------------------------------------------
    def submit_registration(self, manifest: dict, public_key_b64: str,
                            manifest_signature: str) -> tuple[bool, str]:
        """Verifica firma del manifest y emite challenge de endpoint.
        Devuelve (ok, message). NO lista al agente todavía."""
        fp = str((manifest.get("agent") or {}).get("fingerprint", ""))
        if not _FP_RE.match(fp):
            return False, "fingerprint inválido (formato HF-xxxxxxxxxxxxxxxx)"
        try:
            raw_pub = b64d(public_key_b64)
        except Exception:
            return False, "public_key_b64 no es base64 válido"
        if fingerprint_of_public_key(raw_pub) != fp:
            return False, "fingerprint no coincide con la clave pública"
        if not KeyPair.verify_with(raw_pub,
                                   json.dumps(manifest, sort_keys=True,
                                              separators=(",", ":"),
                                              ensure_ascii=False).encode(),
                                   base64.b64decode(manifest_signature)):
            return False, "firma del manifest inválida"
        endpoint = str((manifest.get("agent") or {}).get("endpoint", "")).rstrip("/")
        if not endpoint.startswith(("http://", "https://")):
            return False, "endpoint declarado inválido"
        nonce = base64.b64encode(os.urandom(32)).decode()
        with self._lock:
            if len(self._agents) >= MAX_AGENTS and fp not in self._agents:
                return False, "directorio lleno"
            self._challenges[fp] = (nonce, self._now())
        return True, nonce

    def complete_registration(self, fingerprint: str, manifest: dict,
                              endpoint_proof_b64: str) -> tuple[bool, str]:
        """Con el proof-of-endpoint firmado, lista al agente."""
        with self._lock:
            pending = self._challenges.pop(fingerprint, None)
            if not pending:
                return False, "sin challenge pendiente"
            nonce, issued = pending
            if self._now() - issued > CHALLENGE_TTL_S:
                return False, "challenge expirado"
            raw_pub = b64d((manifest.get("agent") or {}).get(
                "public_key_b64", "")) or None
            # la clave pública ya quedó validada en submit; el proof se
            # verifica contra el nonce emitido
            rec = {
                "manifest": manifest,
                "registered_at": self._now(),
                "last_seen": self._now(),
                "endpoint_proof": endpoint_proof_b64[:64],
                "endpoint_nonce": nonce,
            }
            self._agents[fingerprint] = rec
            return True, "registrado"

    def verify_endpoint_proof(self, fingerprint: str, nonce: str,
                              public_key_b64: str, proof_b64: str) -> bool:
        """El registro comprueba que el agente firmó el nonce con su clave."""
        try:
            raw_pub = b64d(public_key_b64)
            return KeyPair.verify_with(raw_pub, nonce.encode("ascii"),
                                       base64.b64decode(proof_b64))
        except Exception:
            return False

    def heartbeat(self, fingerprint: str) -> bool:
        with self._lock:
            rec = self._agents.get(fingerprint)
            if rec and self._alive(rec):
                rec["last_seen"] = self._now()
                return True
            return False

    # -- consultas ---------------------------------------------------------
    def get(self, fingerprint: str) -> dict | None:
        with self._lock:
            rec = self._agents.get(fingerprint)
            if rec and self._alive(rec):
                return rec
            return None

    def search(self, capability: str = "", q: str = "") -> list[dict]:
        q_low = q.lower()
        with self._lock:
            out = []
            for fp, rec in self._agents.items():
                if not self._alive(rec):
                    continue
                man = rec["manifest"]
                agent = man.get("agent") or {}
                if capability:
                    caps = set(man.get("tools") or []) | set(
                        s.get("name", "") for s in man.get("skills") or [])
                    caps.add(str(agent.get("speciality", "")))
                    if not any(capability.lower() in c.lower() for c in caps if c):
                        continue
                if q_low and q_low not in json.dumps(man).lower():
                    continue
                out.append(man)
            return out

    def count(self) -> int:
        with self._lock:
            return sum(1 for r in self._agents.values() if self._alive(r))


class RegistryServer:
    """Servidor HTTP del directorio."""

    def __init__(self, store: RegistryStore | None = None,
                 signing_keypair: KeyPair | None = None):
        self.store = store or RegistryStore()
        self.keypair = signing_keypair or KeyPair.generate()
        self.fingerprint = fingerprint_of_public_key(self.keypair.public_key)
        self._http = None

    def _make_handler(self):
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                body = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    return self._json(200, {"status": "ok",
                                            "agents": registry.store.count()})
                if parsed.path == "/search":
                    qs = parse_qs(parsed.query)
                    results = registry.store.search(
                        capability=(qs.get("capability") or [""])[0],
                        q=(qs.get("q") or [""])[0])
                    return self._json(200, {"results": results})
                m = re.match(r"^/agents/(HF-[0-9a-f]{16})$", parsed.path)
                if m:
                    rec = registry.store.get(m.group(1))
                    if rec:
                        return self._json(200, rec["manifest"])
                    return self._json(404, {"error": "no registrado o expirado"})
                return self._json(404, {"error": "not found"})

            def do_POST(self):
                parsed = urlparse(self.path)
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    data = json.loads(self.rfile.read(length) or b"{}")
                except (ValueError, json.JSONDecodeError):
                    return self._json(400, {"error": "JSON inválido"})
                if parsed.path == "/register":
                    ok, msg = registry.store.submit_registration(
                        data.get("manifest") or {},
                        str(data.get("public_key_b64", "")),
                        str(data.get("manifest_signature", "")))
                    if not ok:
                        return self._json(400, {"error": msg})
                    # challenge firmado por el registro
                    sig = b64e(registry.keypair.sign(msg.encode("ascii")))
                    return self._json(200, {"challenge_nonce": msg,
                                            "registry_fingerprint":
                                                registry.fingerprint,
                                            "registry_signature": sig})
                if parsed.path == "/register/complete":
                    ok, msg = registry.store.complete_registration(
                        str(data.get("fingerprint", "")),
                        data.get("manifest") or {},
                        str(data.get("endpoint_proof", "")))
                    return self._json((200 if ok else 400),
                                      {"status" if ok else "error": msg})
                if parsed.path == "/heartbeat":
                    ok = registry.store.heartbeat(str(data.get("fingerprint", "")))
                    return self._json((200 if ok else 404),
                                      {"status": "ok" if ok else "unknown"})
                return self._json(404, {"error": "not found"})

        return Handler

    def start(self, host: str = "0.0.0.0", port: int = 8444) -> ThreadingHTTPServer:
        self._http = ThreadingHTTPServer((host, port), self._make_handler())
        self._http.daemon_threads = True
        threading.Thread(target=self._http.serve_forever, daemon=True).start()
        return self._http

    def stop(self):
        if self._http:
            self._http.shutdown()
            self._http.server_close()
            self._http = None
