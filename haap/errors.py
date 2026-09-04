# -*- coding: utf-8 -*-
"""HAAP error hierarchy.

Errors carry a short, stable ASCII ``code`` (no sensitive data) that
travels in ``error``-type messages over the wire, plus a human-readable
``detail`` string that must NEVER expose secrets or internal tracebacks
(see the threat model in ARQUITECTURA.md).
"""


class HAAPError(Exception):
    """Base HAAP error."""

    code = "HAAP_ERROR"

    def __init__(self, detail="", code=None, transient=False):
        self.detail = detail
        self.code = code or self.code
        # transient=True -> the sender may retry (network 5xx, rate limit)
        self.transient = transient
        super().__init__(detail)

    def to_dict(self):
        return {"code": self.code, "detail": self.detail, "transient": self.transient}


# --------------------------------------------------------------------------
# Envelope / cryptography
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
    """Challenge-response failure (unknown, expired, reused)."""

    code = "CHALLENGE_REQUIRED"


# --------------------------------------------------------------------------
# State / authorization
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
# Transport
# --------------------------------------------------------------------------
class TransportError(HAAPError):
    code = "TRANSPORT_ERROR"

    def __init__(self, detail="", status=None):
        super().__init__(detail, code=self.code, transient=True)
        self.status = status


class DiscoveryError(HAAPError):
    """Could not resolve a messaging URL for a fingerprint."""

    code = "DISCOVERY_FAILED"


class TaskError(HAAPError):
    """Task lifecycle errors."""

    code = "TASK_ERROR"


class TaskNotFoundError(HAAPError):
    code = "TASK_NOT_FOUND"


class TaskStateError(HAAPError):
    code = "TASK_STATE_INVALID"


class TaskOverloadError(HAAPError):
    """The local executor is saturated (max concurrent tasks)."""

    code = "TASK_LIMIT_REACHED"

    def __init__(self, detail="", retry_after=0):
        super().__init__(detail, code=self.code, transient=True)
        self.retry_after = retry_after


class UnexpectedMessageError(HAAPError):
    """Message received out of context (friendship/task state)."""

    code = "UNEXPECTED_MESSAGE"


class FriendRequestDeniedError(HAAPError):
    """The remote owner rejected the friend request."""

    code = "FRIEND_REQUEST_DENIED"


# Map of error code -> exception class, used by clients to translate
# received ``error`` envelopes back into local exceptions.
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
    """Instantiate the proper exception from an error code."""
    cls = ERROR_MAP.get(code)
    if cls is None:
        return HAAPError(detail, code=code)
    try:
        return cls(detail)
    except TypeError:
        return cls()
