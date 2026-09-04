# -*- coding: utf-8 -*-
"""HAAP client: delegate tasks to friend agents and collect results.

``HAAPClient`` is the outbound counterpart of ``HAAPServer``: it starts
friendships (hello -> challenge -> friend_request), waits for the human
approval on the other side (friend_accept), and delegates tasks
(task_request -> task_accept -> task_result), enforcing the local
permission guard and the friendship state before anything leaves the
machine.

Discovery of a friend's messaging URL: from the local ``FriendRecord``
endpoints; optionally refreshed from the friend's /.well-known/haap.json
(``refresh_endpoint``).
"""
from __future__ import annotations

import base64
import json
import secrets
import threading
import time
import urllib.error
import urllib.request

from . import envelope as env_mod
from .directory import Directory
from .errors import (
    DiscoveryError, FriendNotFoundError, HAAPError, PermissionDeniedError,
    RateLimitedError, TransportError,
)
from .errors import error_from_code
from .permissions import PermissionMatrix
from .rate_limiter import RateLimiter
from .tasks import TaskRegistry

DEFAULT_TIMEOUT_S = 30.0


def _fetch_json(url: str, payload: dict | None = None,
                timeout: float = 10.0) -> dict:
    """GET (payload=None) or POST JSON, returning the parsed body."""
    data = None
    headers = {"Accept": "application/json",
               "User-Agent": "haap-client/1.0"}
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
        raise DiscoveryError(f"endpoint unreachable at {url}: {exc}") from exc


class HAAPClient:
    """Outbound HAAP agent operations against a friend's server."""

    def __init__(self, identity, directory: Directory, *,
                 transport=None,          # object with .send(env, url) -> dict|None
                 permissions: PermissionMatrix | None = None,
                 rate_limiter: RateLimiter | None = None,
                 tasks: TaskRegistry | None = None,
                 audit=None):
        self.identity = identity
        self.directory = directory
        # default transport: HTTP; MemoryTransport can be injected in tests
        if transport is None:
            from .transport import HttpTransport
            transport = HttpTransport()
        self.transport = transport
        self.permissions = permissions or PermissionMatrix()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.tasks = tasks or TaskRegistry(memory=True)
        self.audit = audit

    # ------------------------------------------------------------------ utils
    def _audit(self, event, friend, result="ok", **kw):
        if self.audit is not None:
            self.audit.event(event, friend=friend, result=result, **kw)

    def _friend_endpoint(self, fingerprint: str) -> str:
        rec = self.directory.require(fingerprint, statuses=("accepted",))
        if not rec.endpoints:
            raise DiscoveryError(
                f"friend {fingerprint} has no known messaging endpoint")
        return rec.endpoints[0]

    def _send(self, message_type: str, friend_fp: str, payload: dict,
              timeout_s: float | None = None) -> dict:
        """Sign, enforce the outbound guard, send, and normalize errors."""
        # outbound permission guard (local decision, mirrored matrix)
        if message_type == "task_request":
            action = str(payload.get("action") or "task:submit")
            resource = str(payload.get("resource") or "")
            rec = self.directory.require(friend_fp, statuses=("accepted",))
            if not rec.has_permission(action) or not self.permissions.check(
                    rec.permissions, action, resource):
                raise PermissionDeniedError(
                    f"local guard: {action} not allowed toward {friend_fp}")
            self.rate_limiter.check(self.identity.fingerprint, "task:submit")
        env = env_mod.sign_body(self.identity, message_type, friend_fp, payload)
        url = self._friend_endpoint(friend_fp)
        reply = self.transport.send(env, url, timeout_s=timeout_s or DEFAULT_TIMEOUT_S)
        if reply and reply.get("message_type") == "error":
            p = reply.get("payload") or {}
            self._audit(f"client.{message_type}.error", friend_fp,
                        result="error", detail={"code": p.get("error_code")})
            raise error_from_code(str(p.get("error_code", "HAAP_ERROR")),
                                  str(p.get("detail", "")))
        return reply or {}

    # ------------------------------------------------------------- friendship
    def start_friendship(self, friend_fp: str, friend_pubkey_b64: str,
                         endpoint: str, name: str = "",
                         speciality: str = "") -> dict:
        """Full outbound handshake: hello -> challenge -> friend_request.
        The request stays pending until the REMOTE owner approves it
        (their friend_accept consolidates our pending_out)."""
        from .capabilities import build_manifest
        # record the friend locally first (pending_out)
        self.directory.add_pending_out(friend_fp, friend_pubkey_b64,
                                       name or friend_fp, endpoints=[endpoint])
        url = endpoint.rstrip("/")
        # 1. hello (self-contained: our public key travels in the payload)
        reply = self._raw_send(url, "hello", {
            "public_key_b64": base64.b64encode(
                self.identity.keypair.public_key).decode(),
            "name": self.identity.display_name,
        }, friend_fp)
        challenge = str(reply.get("payload", {}).get("challenge", ""))
        if not challenge:
            raise HAAPError("peer did not issue a challenge")
        # 2. prove key possession
        sig = base64.b64encode(
            self.identity.keypair.sign(challenge.encode("ascii"))).decode()
        reply2 = self._raw_send(url, "challenge", {
            "challenge": challenge, "signature": sig,
            "public_key_b64": base64.b64encode(
                self.identity.keypair.public_key).decode(),
            "name": self.identity.display_name,
        }, friend_fp)
        if reply2.get("message_type") != "verify":
            raise HAAPError("peer did not verify the challenge response")
        # 3. formal friend request with our capability manifest
        manifest = build_manifest(self.identity.public_claims(),
                                  speciality=speciality)
        reply3 = self._raw_send(url, "friend_request", {
            "public_key_b64": base64.b64encode(
                self.identity.keypair.public_key).decode(),
            "name": self.identity.display_name,
            "capabilities": {"speciality": speciality,
                             "format": manifest.get("format")},
        }, friend_fp)
        self._audit("client.friend_request.sent", friend_fp)
        return reply3

    def _raw_send(self, url: str, message_type: str, payload: dict,
                  friend_fp: str) -> dict:
        """Send an envelope to a raw URL (used during bootstrap, before the
        friendship is accepted and endpoints are in the directory)."""
        env = env_mod.sign_body(self.identity, message_type, friend_fp, payload)
        reply = self.transport.send(env, url, timeout_s=DEFAULT_TIMEOUT_S)
        if reply and reply.get("message_type") == "error":
            p = reply.get("payload") or {}
            raise error_from_code(str(p.get("error_code", "HAAP_ERROR")),
                                  str(p.get("detail", "")))
        return reply or {}

    # ------------------------------------------------------------------ tasks
    def delegate_task(self, friend_fp: str, prompt: str, *,
                      action: str = "task:submit", resource: str = "",
                      timeout_s: float = 120.0,
                      poll_interval: float = 2.0,
                      poll_max: int = 30) -> dict:
        """Delegate a task to a friend.

        Synchronous executor: the task_result arrives as the direct
        reply. Asynchronous executor: we get task_accept and then poll
        the friend's server for task_result (up to ``poll_max`` tries).

        Returns the final task payload {task_id, state, detail}.
        """
        payload = {"action": action, "resource": resource, "prompt": prompt}
        reply = self._send("task_request", friend_fp, payload,
                           timeout_s=timeout_s)
        mtype = reply.get("message_type")
        p = reply.get("payload") or {}
        if mtype == "task_result":
            # local mirror of the delegated task (legal transitions:
            # submitted -> accepted -> completed)
            rec = self.tasks.create(role="delegate",
                                    friend_fingerprint=friend_fp,
                                    prompt=prompt, action=action,
                                    resource=resource,
                                    task_id=str(p.get("task_id")))
            state = str(p.get("state", "completed"))
            if state == "completed":
                self.tasks.update(rec.task_id, "accepted")
                self.tasks.update(rec.task_id, "completed",
                                  detail=p.get("detail") or {})
            else:
                self.tasks.update(rec.task_id, state,
                                  detail=p.get("detail") or {})
            self._audit("client.task.completed", friend_fp)
            return p
        if mtype == "task_accept":
            task_id = str(p.get("task_id", ""))
            rec = self.tasks.create(role="delegate",
                                    friend_fingerprint=friend_fp,
                                    prompt=prompt, action=action,
                                    resource=resource, task_id=task_id)
            # legal transitions: submitted -> accepted -> working
            self.tasks.update(task_id, "accepted")
            self.tasks.update(task_id, "working")
            # poll for the async result via ping/task_result envelope
            url = self._friend_endpoint(friend_fp)
            for _ in range(poll_max):
                time.sleep(poll_interval)
                probe = self._send("ping", friend_fp, {})
                # NOTE: async result collection requires the friend to push
                # task_result (documented); polling via ping keeps the
                # friendship alive while we wait.
                if rec := self.tasks.get(task_id):
                    if rec.state in ("completed", "failed", "rejected"):
                        return rec.to_dict()
            return {"task_id": task_id, "state": "working",
                    "detail": {"note": "still working; result will be pushed"}}
        raise HAAPError(f"unexpected reply to task_request: {mtype}")

    # ------------------------------------------------------------- marketplace
    def service_search(self, business_fp: str, business_endpoint: str,
                       services: str = "", date: str = "") -> dict:
        """Query a business agent's open catalog (no friendship needed).
        Returns the service_quote payload."""
        env = env_mod.sign_body(
            self.identity, "service_search", business_fp,
            {"services": services, "date": date,
             "public_key_b64": base64.b64encode(
                 self.identity.keypair.public_key).decode()})
        reply = self.transport.send(env, business_endpoint.rstrip("/") + "/haap/messages")
        if reply and reply.get("message_type") == "error":
            p = reply.get("payload") or {}
            raise error_from_code(str(p.get("error_code", "HAAP_ERROR")),
                                  str(p.get("detail", "")))
        return reply.get("payload") or {}

    def service_book(self, business_fp: str, business_endpoint: str,
                     service: str, when: str) -> dict:
        """Book an open service at a business agent (no friendship needed).
        Returns the booking result payload {status, cita, ...}."""
        env = env_mod.sign_body(
            self.identity, "service_book", business_fp,
            {"service": service, "when": when,
             "public_key_b64": base64.b64encode(
                 self.identity.keypair.public_key).decode()})
        reply = self.transport.send(env, business_endpoint.rstrip("/") + "/haap/messages")
        if reply and reply.get("message_type") == "error":
            p = reply.get("payload") or {}
            self._audit("client.marketplace.book.error", business_fp,
                        result="error", detail={"code": p.get("error_code")})
            raise error_from_code(str(p.get("error_code", "HAAP_ERROR")),
                                  str(p.get("detail", "")))
        payload = reply.get("payload") or {}
        self._audit("client.marketplace.booked", business_fp,
                    detail={"service": service, "when": when})
        return payload

    # ------------------------------------------------------------- discovery
    def refresh_endpoint(self, friend_fp: str) -> str:
        """Fetch the friend's current messaging URL from their
        /.well-known/haap.json and store it. Fingerprint must match what
        we have recorded (anti-substitution)."""
        rec = self.directory.get(friend_fp)
        if rec is None:
            raise FriendNotFoundError(f"no relationship with {friend_fp}")
        if not rec.endpoints:
            raise DiscoveryError(f"no known endpoint for {friend_fp}")
        base = rec.endpoints[0].rsplit("/", 1)[0]  # strip /haap/messages
        manifest = _fetch_json(base + "/.well-known/haap.json")
        agent = manifest.get("agent") or {}
        if agent.get("fingerprint") != friend_fp:
            raise DiscoveryError(
                "well-known manifest fingerprint mismatch — possible "
                "endpoint substitution")
        new_url = str(agent.get("endpoint", "")).rstrip("/") + "/haap/messages"
        if new_url and new_url not in rec.endpoints:
            rec.endpoints.insert(0, new_url)
            self.directory.upsert(rec)
        return new_url or rec.endpoints[0]
