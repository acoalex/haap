# -*- coding: utf-8 -*-
"""HAAP directory client: register, search, heartbeat.

Talks to a federated directory server (``haap/registry.py``). The
client keeps the agent's manifest signed and proves endpoint ownership
by signing the registry's challenge nonce.

``heartbeat_loop`` runs a daemon thread renewing the entry periodically
(safe default: every 6 h, well below the 24 h entry TTL).
"""
from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from .capabilities import public_manifest
from .errors import DiscoveryError

DEFAULT_HEARTBEAT_S = 6 * 3600


def _request(url: str, payload: dict | None = None,
             timeout: float = 10.0) -> dict:
    """GET (payload=None) or POST JSON; parses the JSON body of any
    status (4xx bodies carry protocol error messages)."""
    data = None
    headers = {"Accept": "application/json",
               "User-Agent": f"haap-client/{__version__}"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST" if payload is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read() or b"{}")
        except ValueError:
            return {"error": f"HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DiscoveryError(f"directory unreachable at {url}: {exc}") from exc


def build_registration(identity, endpoint_url: str, speciality: str = "",
                       skills_dirs: list[str] | None = None,
                       extra_tools: list[str] | None = None) -> tuple[dict, str, str]:
    """Build (manifest, public_key_b64, manifest_signature) for /register."""
    manifest = public_manifest(identity, speciality=speciality,
                               skills_dirs=skills_dirs,
                               messaging_url=endpoint_url,
                               extra_tools=extra_tools)
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode()
    signature = base64.b64encode(identity.keypair.sign(canonical)).decode()
    pub_b64 = base64.b64encode(identity.keypair.public_key).decode()
    return manifest, pub_b64, signature


def register(registry_url: str, identity, endpoint_url: str,
             speciality: str = "", skills_dirs: list[str] | None = None,
             extra_tools: list[str] | None = None) -> dict:
    """Full registration flow: submit -> sign challenge -> complete.

    Returns the registry's final response. Raises DiscoveryError on
    any rejection (the error message travels in ``error``).
    """
    manifest, pub_b64, signature = build_registration(
        identity, endpoint_url, speciality, skills_dirs, extra_tools)
    resp = _request(registry_url.rstrip("/") + "/register", {
        "manifest": manifest, "public_key_b64": pub_b64,
        "manifest_signature": signature})
    if "challenge_nonce" not in resp:
        raise DiscoveryError(f"registration rejected: {resp.get('error')}")
    nonce = resp["challenge_nonce"]
    proof = base64.b64encode(identity.keypair.sign(nonce.encode("ascii"))).decode()
    resp2 = _request(registry_url.rstrip("/") + "/register/complete", {
        "fingerprint": identity.fingerprint, "manifest": manifest,
        "endpoint_proof": proof, "public_key_b64": pub_b64})
    if resp2.get("status") != "registered":
        raise DiscoveryError(f"registration incomplete: {resp2.get('error')}")
    return resp2


def search(registry_url: str, capability: str = "", q: str = "") -> list[dict]:
    """Search the directory; returns a list of agent manifests."""
    qs = urllib.parse.urlencode({"capability": capability, "q": q})
    resp = _request(registry_url.rstrip("/") + f"/search?{qs}")
    return resp.get("results", [])


def heartbeat(registry_url: str, fingerprint: str) -> bool:
    resp = _request(registry_url.rstrip("/") + "/heartbeat",
                    {"fingerprint": fingerprint})
    return resp.get("status") == "ok"


class HeartbeatLoop:
    """Daemon thread renewing this agent's directory entry."""

    def __init__(self, registry_url: str, fingerprint: str,
                 interval_s: int = DEFAULT_HEARTBEAT_S):
        self.registry_url = registry_url
        self.fingerprint = fingerprint
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_ok = False

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.wait(self.interval_s):
            try:
                self.last_ok = heartbeat(self.registry_url, self.fingerprint)
            except DiscoveryError:
                self.last_ok = False

    def stop(self):
        self._stop.set()
