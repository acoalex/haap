# -*- coding: utf-8 -*-
"""Envelope HAAP: serialización, canonicalización JSON determinista,
firma Ed25519, ventana de tiempo (±300 s) y anti-replay por nonce.

Estructura de un mensaje (JSON, UTF-8):

    {
      "protocol_version":     "1.0",
      "message_type":         "task_request",
      "sender_fingerprint":   "HF-...",
      "recipient_fingerprint":"HF-...",
      "timestamp":            1780000000,      # epoch segundos UTC
      "nonce":                "<base64 16 bytes aleatorios>",
      "payload":              { ... }          # cuerpo específico del tipo
      "signature":            "<base64 Ed25519 de 64 B>"
    }

La firma cubre el JSON canónico (claves ordenadas, sin espacios,
``ensure_ascii=False``, recursivo) de TODOS los campos excepto
``signature`` — de modo que el nonce, remitente, destinatario y
timestamp quedan vinculados al cuerpo firmado (anti-reemplazo de campos).
"""

from __future__ import annotations

import json
import secrets
import threading
import time

from . import PROTOCOL_VERSION
from .crypto import b64d, b64e
from .errors import (
    ClockSkewError,
    MalformedEnvelopeError,
    ProtocolVersionError,
    ReplayError,
    SignatureError,
)
from .identity import fingerprint_of_public_key

# Ventana de tolerancia de reloj (±300 s) para timestamps.
MAX_CLOCK_SKEW = 300
# Tipos de mensaje versionados soportados por el protocolo 1.0.
MESSAGE_TYPES = frozenset({
    "hello", "hello_ack", "challenge", "verify", "friend_request", "friend_accept",
    "capabilities", "task_request", "task_accept", "task_result",
    "task_progress", "error", "ping",
})
SIGNED_FIELDS = (
    "protocol_version", "message_type", "sender_fingerprint",
    "recipient_fingerprint", "timestamp", "nonce", "payload",
)
MAX_PAYLOAD_BYTES = 1_000_000  # 1 MB de cuerpo máximo (anti-flooding)


def canonical_json(obj) -> bytes:
    """JSON canónico determinista: claves ordenadas recursivamente,
    separadores compactos, sin espacios, UTF-8 sin escapes innecesarios.

    Solo se permiten tipos JSON nativos (dict/list/str/int/bool/None).
    Los floats quedan PROHIBIDOS en payloads firmados (ambigüedad de
    representación entre plataformas): se serializan como error.
    """
    if isinstance(obj, dict):
        items = b",".join(
            _q(str(k)) + b":" + canonical_json(v) for k, v in sorted(
                obj.items(), key=lambda kv: str(kv[0])))
        return b"{" + items + b"}"
    if isinstance(obj, list):
        return b"[" + b",".join(canonical_json(v) for v in obj) + b"]"
    if isinstance(obj, str):
        return _q(obj)
    if obj is True:
        return b"true"
    if obj is False:
        return b"false"
    if obj is None:
        return b"null"
    if isinstance(obj, int):
        return str(obj).encode("ascii")
    if isinstance(obj, float):
        raise MalformedEnvelopeError(
            "floats no permitidos en JSON canónico firmado; usa enteros "
            "(epoch ms) o cadenas")
    raise MalformedEnvelopeError(
        f"tipo no serializable en JSON canónico: {type(obj).__name__}")


def _q(s: str) -> bytes:
    # Escapado mínimo determinista: json.dumps de un str ya es canónico
    # y no depende del orden de un dict.
    return json.dumps(s, ensure_ascii=False).encode("utf-8")


def _check_payload_jsonable(payload) -> None:
    """Valida recursivamente que el payload sea JSON nativo (sin floats)."""
    if isinstance(payload, dict):
        for k, v in payload.items():
            if not isinstance(k, str):
                raise MalformedEnvelopeError(f"clave no-string en payload: {k!r}")
            _check_payload_jsonable(v)
    elif isinstance(payload, list):
        for v in payload:
            _check_payload_jsonable(v)
    elif isinstance(payload, (str, int, bool)) or payload is None:
        return
    elif isinstance(payload, float):
        raise MalformedEnvelopeError("floats prohibidos en payload firmado")
    else:
        raise MalformedEnvelopeError(
            f"tipo no JSON en payload: {type(payload).__name__}")


def signing_payload(envelope: dict) -> bytes:
    """Bytes canónicos a firmar/verificar: envelope sin el campo signature."""
    to_sign = {k: v for k, v in envelope.items() if k != "signature"}
    return canonical_json(to_sign)


def sign_body(identity, message_type: str, recipient_fingerprint: str,
              payload: dict, timestamp: int | None = None,
              nonce: str | None = None) -> dict:
    """Construye un envelope completo y firmado.

    ``identity``: objeto ``Identity`` del remitente (clave privada local).
    """
    if message_type not in MESSAGE_TYPES:
        raise MalformedEnvelopeError(f"message_type desconocido: {message_type}")
    _check_payload_jsonable(payload)
    envelope = {
        "protocol_version": PROTOCOL_VERSION,
        "message_type": message_type,
        "sender_fingerprint": identity.fingerprint,
        "recipient_fingerprint": recipient_fingerprint,
        "timestamp": int(timestamp if timestamp is not None else time.time()),
        "nonce": nonce or b64e(secrets.token_bytes(16)),
        "payload": payload,
    }
    envelope["signature"] = b64e(identity.keypair.sign(signing_payload(envelope)))
    return envelope


def envelope_to_bytes(envelope: dict) -> bytes:
    """Serialización del envelope a JSON canónico (bytes UTF-8)."""
    return canonical_json(envelope)


def envelope_from_bytes(data: bytes | str) -> dict:
    """Deserializa bytes/cadena JSON a dict envelope, con validación
    estructural básica (campos requeridos y tipos)."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    if len(data.encode("utf-8")) > MAX_PAYLOAD_BYTES + 4096:
        raise MalformedEnvelopeError("mensaje excede el tamaño máximo")
    try:
        env = json.loads(data)
    except ValueError as exc:
        raise MalformedEnvelopeError(f"JSON inválido: {exc}") from exc
    if not isinstance(env, dict):
        raise MalformedEnvelopeError("envelope debe ser un objeto JSON")
    for fld in ("protocol_version", "message_type", "sender_fingerprint",
                "recipient_fingerprint", "signature"):
        if not isinstance(env.get(fld), str) or not env[fld]:
            raise MalformedEnvelopeError(f"campo requerido ausente/vacío: {fld}")
    if not isinstance(env.get("timestamp"), int):
        raise MalformedEnvelopeError("timestamp debe ser entero epoch")
    if not isinstance(env.get("nonce"), str) or not env["nonce"]:
        raise MalformedEnvelopeError("nonce ausente")
    if env.get("protocol_version") != PROTOCOL_VERSION:
        raise ProtocolVersionError(
            f"versión de protocolo {env.get('protocol_version')!r} no soportada "
            f"(esperada {PROTOCOL_VERSION})")
    if env["message_type"] not in MESSAGE_TYPES:
        raise MalformedEnvelopeError(
            f"message_type no soportado: {env['message_type']}")
    payload = env.get("payload")
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise MalformedEnvelopeError("payload debe ser un objeto JSON")
    env["payload"] = payload
    return env


def check_timestamp(envelope: dict, now: int | None = None) -> None:
    """Rechaza mensajes con timestamp fuera de ``now ± MAX_CLOCK_SKEW``."""
    now = int(now if now is not None else time.time())
    ts = envelope["timestamp"]
    if abs(now - ts) > MAX_CLOCK_SKEW:
        raise ClockSkewError(
            f"timestamp {ts} fuera de la ventana ±{MAX_CLOCK_SKEW}s "
            f"(ahora {now})")


class NonceManager:
    """Anti-replay: recuerda nonces vistos por (emisor, nonce) durante la
    ventana de replay relevante (2×MAX_CLOCK_SKEW + margen), con poda
    perezosa y tope de memoria.

    No depende del reloj del emisor: un mensaje capturado y reenviado
    dentro de ±300 s es rechazado; reenviado después de 10 min ya queda
    fuera de la ventana de timestamp y es rechazado igualmente por
    ``check_timestamp``.
    """

    TTL = 2 * MAX_CLOCK_SKEW + 60  # 660 s
    MAX_SEEN = 100_000

    def __init__(self):
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def check_and_mark(self, sender_fingerprint: str, nonce: str,
                       now: float | None = None) -> None:
        """Marca el nonce como visto; lanza ReplayError si ya estaba."""
        now = time.time() if now is None else now
        key = (sender_fingerprint, nonce)
        with self._lock:
            if len(self._seen) > self.MAX_SEEN:
                self._prune(now)
            if key in self._seen:
                raise ReplayError(
                    f"nonce repetido del emisor {sender_fingerprint}")
            self._seen[key] = now

    def _prune(self, now: float) -> None:
        cutoff = now - self.TTL
        stale = [k for k, t in self._seen.items() if t < cutoff]
        for k in stale:
            del self._seen[k]

    def __len__(self) -> int:
        return len(self._seen)


def verify_envelope(envelope: dict, trusted_pubkeys: dict[str, bytes],
                    nonces: NonceManager | None = None,
                    now: int | None = None) -> dict:
    """Verificación completa de un envelope entrante:

    1. estructura/versión (hecha por ``envelope_from_bytes``),
    2. ventana de timestamp ±300 s,
    3. firma Ed25519 contra la clave pública del remitente (búsqueda por
       fingerprint en ``trusted_pubkeys``; si el fingerprint no está
       mapeado a clave -> SignatureError/UNKNOWN_SENDER),
    4. anti-replay por nonce (si se pasa un NonceManager).

    Devuelve el envelope verificado (payload accesible en env["payload"]).
    """
    check_timestamp(envelope, now)
    sender = envelope["sender_fingerprint"]
    raw_pub = trusted_pubkeys.get(sender)
    if raw_pub is None:
        raise SignatureError(
            f"remitente {sender} sin clave pública registrada; "
            "no se puede verificar la firma")
    # Comprobación de coherencia fingerprint <-> clave pública
    if fingerprint_of_public_key(raw_pub) != sender:
        raise SignatureError(
            "fingerprint del envelope no corresponde a su clave pública")
    sig = b64d(envelope["signature"])
    from .crypto import KeyPair
    if not KeyPair.verify_with(raw_pub, signing_payload(envelope), sig):
        raise SignatureError("firma Ed25519 inválida")
    if nonces is not None:
        nonces.check_and_mark(sender, envelope["nonce"], now)
    return envelope
