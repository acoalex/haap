# -*- coding: utf-8 -*-
"""Identidad de agente HAAP.

Fingerprint  = "HF-" + primeros 16 hex del SHA-256 de la clave pública
Ed25519 en bruto (32 B). Formato: ``HF-<16 hex>`` (p. ej.
``HF-3f7a9c1b2d4e5f60``). Es un identificador corto para humanos y
directorios; el emparejamiento criptográfico real usa la clave pública
completa.

La identidad completa (claves + metadatos) se persiste en
``~/.hermes/haap/identity.json`` (directorio override con env
``HAAP_DIR`` o parámetro ``directory``):

    {
      "format": "haap-identity-v1",
      "display_name": "...",
      "fingerprint": "HF-...",
      "public_key":  "<base64 raw 32B>",
      "private_key": "<base64 raw 32B>",   # secreto: chmod 600
      "created_at":  "ISO-8601 UTC",
      "endpoint":    {"transport": "https", "url": "..."}   # opcional
    }
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass, field

from .crypto import KeyPair, b64d
from .errors import HAAPError, NotInitializedError

IDENTITY_FORMAT = "haap-identity-v1"
DEFAULT_HAAP_DIR = os.path.expanduser("~/.hermes/haap")
IDENTITY_FILENAME = "identity.json"


def haap_dir() -> str:
    """Directorio de datos HAAP (override con env HAAP_DIR)."""
    return os.environ.get("HAAP_DIR", DEFAULT_HAAP_DIR)


def fingerprint_of_public_key(pub_raw: bytes) -> str:
    """SHA-256 de la clave pública -> ``HF-<16 hex>`` (8 bytes visibles)."""
    digest = hashlib.sha256(pub_raw).hexdigest()
    return "HF-" + digest[:16]


def fingerprint_matches(fp: str, pub_raw: bytes) -> bool:
    return fp == fingerprint_of_public_key(pub_raw)


@dataclass
class Identity:
    """Identidad de agente HAAP (par de claves + metadatos)."""

    keypair: KeyPair
    display_name: str = "hermes-agent"
    created_at: str = field(default_factory=lambda: time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    endpoint_transport: str = "https"
    endpoint_url: str = ""

    @property
    def fingerprint(self) -> str:
        return fingerprint_of_public_key(self.keypair.public_key)

    def public_claims(self) -> dict:
        """Información pública (sin claves) — segura para manifests."""
        claims = {
            "display_name": self.display_name,
            "fingerprint": self.fingerprint,
        }
        if self.endpoint_url:
            claims["endpoint"] = {
                "transport": self.endpoint_transport,
                "url": self.endpoint_url,
            }
        return claims

    def to_dict(self) -> dict:
        return {
            "format": IDENTITY_FORMAT,
            "display_name": self.display_name,
            "fingerprint": self.fingerprint,
            "public_key": self.keypair.public_key_b64(),
            "private_key": self.keypair.private_key_b64(),
            "created_at": self.created_at,
            "endpoint": {
                "transport": self.endpoint_transport,
                "url": self.endpoint_url,
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Identity":
        if data.get("format") != IDENTITY_FORMAT:
            raise HAAPError(
                "formato de identidad no reconocido (¿archivo de otra versión?)")
        if not isinstance(data.get("private_key"), str) or not data["private_key"]:
            raise HAAPError("identity.json sin private_key")
        kp = KeyPair.from_private_bytes(b64d(data["private_key"]))
        expected = fingerprint_of_public_key(kp.public_key)
        if data.get("fingerprint") != expected:
            raise HAAPError(
                "identity.json corrupto: fingerprint no coincide con la clave pública")
        ep = data.get("endpoint") or {}
        return cls(
            keypair=kp,
            display_name=str(data.get("display_name") or "hermes-agent"),
            created_at=str(data.get("created_at") or ""),
            endpoint_transport=str(ep.get("transport") or "https"),
            endpoint_url=str(ep.get("url") or ""),
        )


class IdentityStore:
    """Persistencia de la identidad local en ``<dir>/identity.json``."""

    def __init__(self, directory: str | None = None):
        self.directory = directory or haap_dir()
        self.path = os.path.join(self.directory, IDENTITY_FILENAME)

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def create(self, display_name: str | None = None,
               endpoint_url: str = "") -> Identity:
        os.makedirs(self.directory, exist_ok=True)
        if self.exists():
            raise HAAPError(
                f"ya existe una identidad en {self.path}; borra el archivo "
                "o usa otro HAAP_DIR para regenerar")
        try:
            host = os.uname().nodename
        except AttributeError:  # Windows
            host = os.environ.get("COMPUTERNAME", "agent")
        ident = Identity(
            keypair=KeyPair.generate(),
            display_name=display_name or f"hermes-{host}",
            endpoint_url=endpoint_url,
        )
        self.save(ident)
        return ident

    def load(self) -> Identity:
        if not self.exists():
            raise NotInitializedError(
                f"no hay identidad en {self.path}. Ejecuta primero: haap init")
        with open(self.path, "r", encoding="utf-8") as fh:
            return Identity.from_dict(json.load(fh))

    def save(self, ident: Identity) -> None:
        os.makedirs(self.directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(ident.to_dict(), fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 600: hay clave privada
        os.replace(tmp, self.path)
