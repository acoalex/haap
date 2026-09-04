# -*- coding: utf-8 -*-
"""HAAP transport layers.

The protocol is transport-agnostic: messages are signed JSON envelopes.
This module holds:

  * ``MemoryTransport``  — direct in-process coupling (tests, local
    integration, in-memory fixtures).
  * ``HttpTransport``    — HTTPS POST of the envelope to the friend's
    endpoint (Hermes inbound webhook / ``haap serve`` server); synchronous
    responses = reply envelope; status 202 = no response.
  * ``MatrixTransport`` / ``EmailTransport`` — documented in
    ARQUITECTURA.md (section "Transport portability") as equivalent
    adapters that only implement ``send()``.

A transport only needs: ``send(envelope_bytes, url) -> bytes | None``
(where the return value is the reply envelope, or None for
fire-and-forget).
"""

from __future__ import annotations

import threading
import time

from .errors import TransportError

DEFAULT_TIMEOUT_S = 30
DEFAULT_RETRIES = 3
RETRY_BACKOFF_S = [0.5, 2.0, 5.0]
# HTTP errors considered retryable (the peer may be restarting or
# saturated); validation 4xx errors are NOT retried.
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


class MemoryTransport:
    """In-memory transport: hands the envelope to a delivery function
    (typically the remote server's ``handle_message``) and returns the
    reply. No network, no threads: ideal for tests and for two agents in
    the same process."""

    def __init__(self, deliver):
        """``deliver(envelope_dict, url_hint) -> dict | None``"""
        self.deliver = deliver
        self.calls = 0

    def send(self, envelope: dict, url: str = "", timeout_s: float = 30.0) -> dict | None:
        self.calls += 1
        try:
            return self.deliver(envelope, url)
        except TransportError:
            raise
        except Exception as exc:  # the router raises HAAPError; anything else
            raise TransportError(f"in-memory delivery failed: {exc}") from exc


class HttpTransport:
    """HTTPS transport: JSON POST of the envelope to ``<url>`` with
    backoff retries for transient errors and a timeout.

    The remote endpoint must be the peer agent's HAAP inbound webhook
    (``haap serve`` or the Hermes webhook bridge, which signs and
    forwards to the HAAP router — see ARQUITECTURA.md).
    """

    def __init__(self, session=None, timeout_s: float = DEFAULT_TIMEOUT_S,
                 retries: int = DEFAULT_RETRIES, headers: dict | None = None):
        self.session = session
        self.timeout_s = timeout_s
        self.retries = retries
        self.headers = headers or {"Content-Type": "application/json"}
        self._lock = threading.Lock()

    def _post(self, envelope: dict, url: str) -> tuple[int, bytes]:
        import requests  # deferred import: optional in minimal environments

        session = self.session
        if session is None:
            with self._lock:
                if self.session is None:
                    self.session = requests.Session()
                session = self.session
        resp = session.post(
            url,
            data=envelope_to_bytes(envelope),
            headers=self.headers,
            timeout=self.timeout_s,
        )
        return resp.status_code, resp.content

    def send(self, envelope: dict, url: str, timeout_s: float | None = None) -> dict | None:
        """POST the envelope; return the reply envelope if the server
        responded 200, or None on 202 (fire-and-forget)."""
        from .envelope import envelope_from_bytes

        if timeout_s is not None:
            self.timeout_s = timeout_s
        last_err: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                status, body = self._post(envelope, url)
            except TransportError:
                raise
            except Exception as exc:  # requests.ConnectionError, Timeout...
                last_err = exc
                if attempt < self.retries:
                    time.sleep(RETRY_BACKOFF_S[min(attempt, len(RETRY_BACKOFF_S) - 1)])
                    continue
                break
            if status == 200 and body:
                return envelope_from_bytes(body)
            if status == 202:
                return None
            if status in RETRYABLE_STATUS and attempt < self.retries:
                last_err = TransportError(f"HTTP {status} (retryable)")
                time.sleep(RETRY_BACKOFF_S[min(attempt, len(RETRY_BACKOFF_S) - 1)])
                continue
            raise TransportError(
                f"HTTP {status} from endpoint {url}", status=status)
        raise TransportError(f"network error after {self.retries + 1} attempts: "
                             f"{last_err}")


def envelope_to_bytes(envelope: dict) -> bytes:
    from .envelope import envelope_to_bytes as _b
    return _b(envelope)
