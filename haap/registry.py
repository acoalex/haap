# -*- coding: utf-8 -*-
"""HAAP federated public directory of agents.

The registry is a "phone book", not a notary: identity lives in the
keys. The directory only indexes signed manifests and verifies that the
agent controls the endpoint it declares (proof-of-endpoint).

API (stdlib http.server, zero dependencies):

  POST /register            {manifest, public_key_b64, manifest_signature}
  POST /register/complete   {fingerprint, manifest, endpoint_proof}
  POST /heartbeat           {fingerprint, timestamp, signature}
  GET  /search?capability=X&q=Y
  GET  /agents/{fingerprint}
  GET  /health

Entries expire without a heartbeat after ENTRY_TTL_S (lazy pruning on
every read). Re-registering the same fingerprint = update.
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

ENTRY_TTL_S = 24 * 3600          # expiry without heartbeat
CHALLENGE_TTL_S = 60             # proof-of-endpoint window
MAX_AGENTS = 10_000              # anti-flooding cap for the directory

_FP_RE = re.compile(r"^HF-[0-9a-f]{16}$")


class RegistryStore:
    """Directory state in memory with lazy pruning."""

    def __init__(self, entry_ttl: int = ENTRY_TTL_S):
        self._agents: dict[str, dict] = {}
        self._challenges: dict[str, tuple[str, float, str]] = {}  # fp -> (nonce, issued, pubkey_b64)
        self._lock = threading.RLock()
        self.entry_ttl = entry_ttl

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _now() -> float:
        return time.time()

    def _alive(self, rec: dict) -> bool:
        return self._now() - rec["last_seen"] <= self.entry_ttl

    # -- registration ------------------------------------------------------
    def submit_registration(self, manifest: dict, public_key_b64: str,
                            manifest_signature: str) -> tuple[bool, str]:
        """Verify the manifest signature and issue an endpoint challenge.
        Returns (ok, message). Does NOT list the agent yet."""
        fp = str((manifest.get("agent") or {}).get("fingerprint", ""))
        if not _FP_RE.match(fp):
            return False, "invalid fingerprint (HF-xxxxxxxxxxxxxxxx format)"
        try:
            raw_pub = b64d(public_key_b64)
        except Exception:
            return False, "public_key_b64 is not valid base64"
        if fingerprint_of_public_key(raw_pub) != fp:
            return False, "fingerprint does not match the public key"
        if not KeyPair.verify_with(raw_pub,
                                   json.dumps(manifest, sort_keys=True,
                                              separators=(",", ":"),
                                              ensure_ascii=False).encode(),
                                   base64.b64decode(manifest_signature)):
            return False, "invalid manifest signature"
        endpoint = str((manifest.get("agent") or {}).get("endpoint", "")).rstrip("/")
        if not endpoint.startswith(("http://", "https://")):
            return False, "invalid declared endpoint"
        nonce = base64.b64encode(os.urandom(32)).decode()
        with self._lock:
            if len(self._agents) >= MAX_AGENTS and fp not in self._agents:
                return False, "directory full"
            # remember the verified key: the manifest itself never carries keys
            self._challenges[fp] = (nonce, self._now(), public_key_b64)
        return True, nonce

    def complete_registration(self, fingerprint: str, manifest: dict,
                              endpoint_proof_b64: str,
                              public_key_b64: str = "") -> tuple[bool, str]:
        """With the signed endpoint proof, list the agent. The proof MUST
        verify against the public key validated at submit time (kept in
        the pending challenge); anything else is rejected and the agent
        is NOT listed."""
        with self._lock:
            pending = self._challenges.pop(fingerprint, None)
            if not pending:
                return False, "no pending challenge"
            nonce, issued, verified_key_b64 = pending
            if self._now() - issued > CHALLENGE_TTL_S:
                return False, "challenge expired"
            if public_key_b64 and public_key_b64 != verified_key_b64:
                return False, "public key does not match the registered challenge"
            if not self.verify_endpoint_proof(
                    fingerprint, nonce, verified_key_b64, endpoint_proof_b64):
                return False, "invalid endpoint proof (signed by a different key)"
            rec = {
                "manifest": manifest,
                "registered_at": self._now(),
                "last_seen": self._now(),
                "endpoint_proof": endpoint_proof_b64[:64],
                "endpoint_nonce": nonce,
            }
            self._agents[fingerprint] = rec
            return True, "registered"

    def verify_endpoint_proof(self, fingerprint: str, nonce: str,
                              public_key_b64: str, proof_b64: str) -> bool:
        """The registry checks that the agent signed the nonce with its key."""
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

    # -- queries -----------------------------------------------------------
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
    """HTTP server for the directory."""

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
                    return self._json(404, {"error": "not registered or expired"})
                return self._json(404, {"error": "not found"})

            def do_POST(self):
                parsed = urlparse(self.path)
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    data = json.loads(self.rfile.read(length) or b"{}")
                except (ValueError, json.JSONDecodeError):
                    return self._json(400, {"error": "invalid JSON"})
                if parsed.path == "/register":
                    ok, msg = registry.store.submit_registration(
                        data.get("manifest") or {},
                        str(data.get("public_key_b64", "")),
                        str(data.get("manifest_signature", "")))
                    if not ok:
                        return self._json(400, {"error": msg})
                    # challenge signed by the registry
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
