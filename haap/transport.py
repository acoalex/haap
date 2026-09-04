# -*- coding: utf-8 -*-
"""Capas de transporte de HAAP.

El protocolo es agnóstico al transporte: los mensajes son envelopes JSON
firmados. Aquí viven:

  * ``MemoryTransport``  — acoplamiento directo en proceso (tests,
    integración local, fixtures in-memory).
  * ``HttpTransport``    — HTTPS POST del envelope al endpoint del amigo
    (webhook entrante de Hermes / servidor ``haap serve``); respuestas
    síncronas = envelope de respuesta; código 202 = sin respuesta.
  * ``MatrixTransport`` / ``EmailTransport`` — documentados en
    ARQUITECTURA.md (sección "Portabilidad de transporte") como
    adaptadores equivalentes que solo implementan ``send()``.

Un transporte solo necesita: ``send(envelope_bytes, url) -> bytes | None``
(donde el retorno es la respuesta envelope o None para fire-and-forget).
"""

from __future__ import annotations

import threading
import time

from .errors import TransportError

DEFAULT_TIMEOUT_S = 30
DEFAULT_RETRIES = 3
RETRY_BACKOFF_S = [0.5, 2.0, 5.0]
# Errores HTTP considerados reintentables (el destinatario puede estar
# reiniciándose o saturado); 4xx de validación NO se reintentan.
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


class MemoryTransport:
    """Transporte en memoria: entrega el envelope a una función de
    entrega (típicamente el ``handle_message`` del servidor remoto) y
    devuelve la respuesta. Sin red, sin hilos: ideal para tests y para
    dos agentes en el mismo proceso."""

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
        except Exception as exc:  # el router lanza HAAPError; cualquier otra
            raise TransportError(f"entrega en memoria falló: {exc}") from exc


class HttpTransport:
    """Transporte HTTPS: POST JSON del envelope a ``<url>`` con
    reintentos con backoff para errores transitorios y timeout.

    El endpoint remoto debe ser el webhook entrante HAAP del otro
    agente (``haap serve`` o el puente de webhooks de Hermes, que firma
    y reenvía al router HAAP — ver ARQUITECTURA.md).
    """

    def __init__(self, session=None, timeout_s: float = DEFAULT_TIMEOUT_S,
                 retries: int = DEFAULT_RETRIES, headers: dict | None = None):
        self.session = session
        self.timeout_s = timeout_s
        self.retries = retries
        self.headers = headers or {"Content-Type": "application/json"}
        self._lock = threading.Lock()

    def _post(self, envelope: dict, url: str) -> tuple[int, bytes]:
        import requests  # import diferido: opcional en entornos mínimos

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
        """POST del envelope; devuelve el envelope de respuesta si el
        servidor respondió 200, o None si respondió 202 (fire-and-forget)."""
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
                last_err = TransportError(f"HTTP {status} (reintentable)")
                time.sleep(RETRY_BACKOFF_S[min(attempt, len(RETRY_BACKOFF_S) - 1)])
                continue
            raise TransportError(
                f"HTTP {status} del endpoint {url}", status=status)
        raise TransportError(f"error de red tras {self.retries + 1} intentos: "
                             f"{last_err}")


def envelope_to_bytes(envelope: dict) -> bytes:
    from .envelope import envelope_to_bytes as _b
    return _b(envelope)
