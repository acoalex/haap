# -*- coding: utf-8 -*-
"""Jerarquía de errores de HAAP.

Los errores llevan un ``code`` corto y estable (ASCII, sin datos
sensibles) que viaja en mensajes de tipo ``error`` a través de la red,
más un mensaje humano ``detail`` que NUNCA debe exponer secretos ni
trazas internas (ver threat model en ARQUITECTURA.md).
"""


class HAAPError(Exception):
    """Error base de HAAP."""

    code = "HAAP_ERROR"

    def __init__(self, detail="", code=None, transient=False):
        self.detail = detail
        self.code = code or self.code
        # transient=True -> el emisor puede reintentar (5xx de red, rate limit)
        self.transient = transient
        super().__init__(detail)

    def to_dict(self):
        return {"code": self.code, "detail": self.detail, "transient": self.transient}


# --------------------------------------------------------------------------
# Envelope / criptografía
# --------------------------------------------------------------------------
class ProtocolVersionError(HAAPError):
    code = "PROTOCOL_VERSION_UNSUPPORTED"


class SignatureError(HAAPError):
    code = "BAD_SIGNATURE"


class UnknownSenderError(HAAPError):
    code = "UNKNOWN_SENDER"


class ClockSkewError(HAAPError):
    code = "CLOCK_SKEW"


class ReplayError(HAAPError):
    code = "NONCE_REPLAY"


class MalformedEnvelopeError(HAAPError):
    code = "MALFORMED_ENVELOPE"


class ChallengeError(HAAPError):
    """Fallo en challenge-response (desconocido, caducado, reutilizado)."""

    code = "CHALLENGE_REQUIRED"


# --------------------------------------------------------------------------
# Estado / autorización
# --------------------------------------------------------------------------
class NotInitializedError(HAAPError):
    code = "NOT_INITIALIZED"


class FriendNotFoundError(HAAPError):
    code = "FRIEND_NOT_FOUND"


class FriendBlockedError(HAAPError):
    code = "FRIEND_BLOCKED"


class FriendNotAcceptedError(HAAPError):
    code = "FRIEND_NOT_ACCEPTED"


class DuplicateRequestError(HAAPError):
    code = "DUPLICATE_REQUEST"


class PermissionDeniedError(HAAPError):
    code = "PERMISSION_DENIED"


class RateLimitedError(HAAPError):
    code = "RATE_LIMITED"

    def __init__(self, detail="", retry_after=0):
        super().__init__(detail, code=self.code, transient=True)
        self.retry_after = retry_after


# --------------------------------------------------------------------------
# Transporte
# --------------------------------------------------------------------------
class TransportError(HAAPError):
    code = "TRANSPORT_ERROR"

    def __init__(self, detail="", status=None):
        super().__init__(detail, code=self.code, transient=True)
        self.status = status


class DiscoveryError(HAAPError):
    """No se pudo resolver una URL de mensajería para un fingerprint."""

    code = "DISCOVERY_FAILED"


class TaskError(HAAPError):
    """Errores del ciclo de vida de tareas."""

    code = "TASK_ERROR"


class TaskNotFoundError(HAAPError):
    code = "TASK_NOT_FOUND"


class TaskStateError(HAAPError):
    code = "TASK_STATE_INVALID"


class TaskOverloadError(HAAPError):
    """El ejecutor local está saturado (tareas concurrentes máximas)."""

    code = "TASK_LIMIT_REACHED"

    def __init__(self, detail="", retry_after=0):
        super().__init__(detail, code=self.code, transient=True)
        self.retry_after = retry_after


class UnexpectedMessageError(HAAPError):
    """Mensaje recibido fuera de contexto (estado de amistad/flow)."""

    code = "UNEXPECTED_MESSAGE"


class FriendRequestDeniedError(HAAPError):
    """El dueño remoto rechazó la solicitud de amistad."""

    code = "FRIEND_REQUEST_DENIED"


# Mapa code -> clase, usado por el cliente para traducir envelopes de tipo
# ``error`` recibidos como respuesta en excepciones locales.
ERROR_MAP = {
    cls.code: cls for cls in (
        ProtocolVersionError, SignatureError, UnknownSenderError,
        ClockSkewError, ReplayError, MalformedEnvelopeError, ChallengeError,
        NotInitializedError, FriendNotFoundError, FriendBlockedError,
        FriendNotAcceptedError, DuplicateRequestError, PermissionDeniedError,
        RateLimitedError, TransportError, DiscoveryError, TaskError,
        TaskNotFoundError, TaskStateError, TaskOverloadError,
        UnexpectedMessageError, FriendRequestDeniedError,
    )
}


def error_from_code(code: str, detail: str = "") -> HAAPError:
    """Instancia la excepción correcta a partir de un code de error."""
    cls = ERROR_MAP.get(code)
    if cls is None:
        return HAAPError(detail, code=code)
    try:
        return cls(detail)
    except TypeError:
        return cls()
