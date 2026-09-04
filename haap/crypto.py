# -*- coding: utf-8 -*-
"""HAAP cryptography: Ed25519 key primitives.

Each agent owns an Ed25519 key pair (32-byte raw keys) generated with the
``cryptography`` library. The high-level identity (the ``Identity``
dataclass and its persistence) lives in ``identity.py``; this module only
holds signing/verification primitives and encoding helpers.

The private key NEVER leaves this machine and is never included in any
message or public manifest.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64e(data: bytes) -> str:
    """Base64 (standard) encoding: bytes -> ASCII str."""
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def public_key_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_from_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def private_key_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


@dataclass
class KeyPair:
    """Ed25519 key pair with signing/verification helpers."""

    public_key: bytes = field(repr=False)  # raw 32 B
    private_key: bytes = field(repr=False)  # raw 32 B

    @classmethod
    def generate(cls) -> "KeyPair":
        priv = Ed25519PrivateKey.generate()
        return cls(
            public_key=public_key_bytes(priv.public_key()),
            private_key=private_key_bytes(priv),
        )

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "KeyPair":
        priv = private_key_from_bytes(raw)
        return cls(
            public_key=public_key_bytes(priv.public_key()),
            private_key=raw,
        )

    def public_key_b64(self) -> str:
        return b64e(self.public_key)

    def private_key_b64(self) -> str:
        return b64e(self.private_key)

    def sign(self, data: bytes) -> bytes:
        """Ed25519 signature (64 B) of ``data`` with the local private key."""
        return private_key_from_bytes(self.private_key).sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        return self.verify_with(self.public_key, data, signature)

    @staticmethod
    def verify_with(raw_pub: bytes, data: bytes, signature: bytes) -> bool:
        """Verify a signature with an arbitrary public key (other agents)."""
        try:
            public_key_from_bytes(raw_pub).verify(signature, data)
            return True
        except InvalidSignature:
            return False
