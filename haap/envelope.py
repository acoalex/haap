# -*- coding: utf-8 -*-
"""HAAP envelope: serialization, deterministic JSON canonicalization,
Ed25519 signing, time window (±300 s) and nonce-based anti-replay.

Message structure (JSON, UTF-8):

    {
      "protocol_version":     "1.0",
      "message_type":         "task_request",
      "sender_fingerprint":   "HF-...",
      "recipient_fingerprint":"HF-...",
      "timestamp":            1780000000,      # UTC epoch seconds
      "nonce":                "<base64 16 random bytes>",
      "payload":              { ... }          # type-specific body
      "signature":            "<base64 64 B Ed25519>"
    }

The signature covers the canonical JSON (sorted keys, no spaces,
``ensure_ascii=False``, recursive) of ALL fields except ``signature`` —
so nonce, sender, recipient and timestamp are bound to the signed body
(field-substitution protection).
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

# Clock tolerance window (±300 s) for timestamps.
MAX_CLOCK_SKEW = 300
# Versioned message types supported by protocol 1.0.
MESSAGE_TYPES = frozenset({
    "hello", "hello_ack", "challenge", "verify", "friend_request", "friend_accept",
    "capabilities", "task_request", "task_accept", "task_result",
    "task_progress", "error", "ping",
})
SIGNED_FIELDS = (
    "protocol_version", "message_type", "sender_fingerprint",
    "recipient_fingerprint", "timestamp", "nonce", "payload",
)
MAX_PAYLOAD_BYTES = 1_000_000  # 1 MB max body (anti-flooding)


def canonical_json(obj) -> bytes:
    """Deterministic canonical JSON: recursively sorted keys, compact
    separators, no spaces, UTF-8 without unnecessary escapes.

    Only native JSON types are allowed (dict/list/str/int/bool/None).
    Floats are FORBIDDEN in signed payloads (representation ambiguity
    across platforms): they raise an error.
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
            "floats are not allowed in signed canonical JSON; use integers "
            "(epoch ms) or strings")
    raise MalformedEnvelopeError(
        f"type not serializable in canonical JSON: {type(obj).__name__}")


def _q(s: str) -> bytes:
    # Minimal deterministic escaping: json.dumps of a str is already
    # canonical and independent of dict ordering.
    return json.dumps(s, ensure_ascii=False).encode("utf-8")


def _check_payload_jsonable(payload) -> None:
    """Recursively validate that the payload is native JSON (no floats)."""
    if isinstance(payload, dict):
        for k, v in payload.items():
            if not isinstance(k, str):
                raise MalformedEnvelopeError(f"non-string payload key: {k!r}")
            _check_payload_jsonable(v)
    elif isinstance(payload, list):
        for v in payload:
            _check_payload_jsonable(v)
    elif isinstance(payload, (str, int, bool)) or payload is None:
        return
    elif isinstance(payload, float):
        raise MalformedEnvelopeError("floats forbidden in signed payload")
    else:
        raise MalformedEnvelopeError(
            f"non-JSON type in payload: {type(payload).__name__}")


def signing_payload(envelope: dict) -> bytes:
    """Canonical bytes to sign/verify: the envelope minus the signature field."""
    to_sign = {k: v for k, v in envelope.items() if k != "signature"}
    return canonical_json(to_sign)


def sign_body(identity, message_type: str, recipient_fingerprint: str,
              payload: dict, timestamp: int | None = None,
              nonce: str | None = None) -> dict:
    """Build a complete, signed envelope.

    ``identity``: the sender's ``Identity`` object (local private key).
    """
    if message_type not in MESSAGE_TYPES:
        raise MalformedEnvelopeError(f"unknown message_type: {message_type}")
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
    """Serialize the envelope to canonical JSON (UTF-8 bytes)."""
    return canonical_json(envelope)


def envelope_from_bytes(data: bytes | str) -> dict:
    """Deserialize JSON bytes/str into an envelope dict with basic
    structural validation (required fields and types)."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    if len(data.encode("utf-8")) > MAX_PAYLOAD_BYTES + 4096:
        raise MalformedEnvelopeError("message exceeds maximum size")
    try:
        env = json.loads(data)
    except ValueError as exc:
        raise MalformedEnvelopeError(f"invalid JSON: {exc}") from exc
    if not isinstance(env, dict):
        raise MalformedEnvelopeError("envelope must be a JSON object")
    for fld in ("protocol_version", "message_type", "sender_fingerprint",
                "recipient_fingerprint", "signature"):
        if not isinstance(env.get(fld), str) or not env[fld]:
            raise MalformedEnvelopeError(f"required field missing/empty: {fld}")
    if not isinstance(env.get("timestamp"), int):
        raise MalformedEnvelopeError("timestamp must be an epoch integer")
    if not isinstance(env.get("nonce"), str) or not env["nonce"]:
        raise MalformedEnvelopeError("missing nonce")
    if env.get("protocol_version") != PROTOCOL_VERSION:
        raise ProtocolVersionError(
            f"unsupported protocol version {env.get('protocol_version')!r} "
            f"(expected {PROTOCOL_VERSION})")
    if env["message_type"] not in MESSAGE_TYPES:
        raise MalformedEnvelopeError(
            f"unsupported message_type: {env['message_type']}")
    payload = env.get("payload")
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise MalformedEnvelopeError("payload must be a JSON object")
    env["payload"] = payload
    return env


def check_timestamp(envelope: dict, now: int | None = None) -> None:
    """Reject messages whose timestamp falls outside ``now ± MAX_CLOCK_SKEW``."""
    now = int(now if now is not None else time.time())
    ts = envelope["timestamp"]
    if abs(now - ts) > MAX_CLOCK_SKEW:
        raise ClockSkewError(
            f"timestamp {ts} outside the ±{MAX_CLOCK_SKEW}s window "
            f"(now {now})")


class NonceManager:
    """Anti-replay: remembers seen (sender, nonce) pairs for the relevant
    replay window (2×MAX_CLOCK_SKEW + margin), with lazy pruning and a
    memory cap.

    Does not depend on the sender's clock: a captured message replayed
    within ±300 s is rejected; replayed after 10 min it is already out of
    the timestamp window and rejected by ``check_timestamp`` anyway.
    """

    TTL = 2 * MAX_CLOCK_SKEW + 60  # 660 s
    MAX_SEEN = 100_000

    def __init__(self):
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def check_and_mark(self, sender_fingerprint: str, nonce: str,
                       now: float | None = None) -> None:
        """Mark the nonce as seen; raise ReplayError if already present."""
        now = time.time() if now is None else now
        key = (sender_fingerprint, nonce)
        with self._lock:
            if len(self._seen) > self.MAX_SEEN:
                self._prune(now)
            if key in self._seen:
                raise ReplayError(
                    f"duplicate nonce from sender {sender_fingerprint}")
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
    """Full verification of an inbound envelope:

    1. structure/version (done by ``envelope_from_bytes``),
    2. ±300 s timestamp window,
    3. Ed25519 signature against the sender's public key (looked up by
       fingerprint in ``trusted_pubkeys``; if the fingerprint is not
       mapped to a key -> SignatureError/UNKNOWN_SENDER),
    4. nonce anti-replay (if a NonceManager is provided).

    Returns the verified envelope (payload available at env["payload"]).
    """
    check_timestamp(envelope, now)
    sender = envelope["sender_fingerprint"]
    raw_pub = trusted_pubkeys.get(sender)
    if raw_pub is None:
        raise SignatureError(
            f"sender {sender} has no registered public key; "
            "signature cannot be verified")
    # Fingerprint <-> public key consistency check
    if fingerprint_of_public_key(raw_pub) != sender:
        raise SignatureError(
            "envelope fingerprint does not match its public key")
    sig = b64d(envelope["signature"])
    from .crypto import KeyPair
    if not KeyPair.verify_with(raw_pub, signing_payload(envelope), sig):
        raise SignatureError("invalid Ed25519 signature")
    if nonces is not None:
        nonces.check_and_mark(sender, envelope["nonce"], now)
    return envelope
