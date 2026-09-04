# -*- coding: utf-8 -*-
"""Criptografía de HAAP: claves Ed25519 (primitivas).

Cada agente posee un par de claves Ed25519 (32 bytes) generado con la
biblioteca ``cryptography``. La identidad de alto nivel (dataclass
``Identity`` + persistencia) vive en ``identity.py``; aquí solo hay
primitivas de firma/verificación y codificación.

La clave privada NUNCA abandona esta máquina ni se incluye en ningún
mensaje o manifest público.
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
    """Base64 (estándar, sin padding issues) de bytes -> str ASCII."""
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
    """Par de claves Ed25519 con helpers de firma/verificación."""

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
        """Firma Ed25519 (64 B) de ``data`` con la clave privada local."""
        return private_key_from_bytes(self.private_key).sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        return self.verify_with(self.public_key, data, signature)

    @staticmethod
    def verify_with(raw_pub: bytes, data: bytes, signature: bytes) -> bool:
        """Verifica una firma con una clave pública arbitraria (otros agentes)."""
        try:
            public_key_from_bytes(raw_pub).verify(signature, data)
            return True
        except InvalidSignature:
            return False
