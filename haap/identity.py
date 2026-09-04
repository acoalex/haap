# -*- coding: utf-8 -*-
"""HAAP agent identity.

Fingerprint = "HF-" + first 16 hex chars of the SHA-256 of the raw
Ed25519 public key (32 B). Format: ``HF-<16 hex>`` (e.g.
``HF-3f7a9c1b2d4e5f60``). It is a short, human-friendly identifier for
directories and logs; real cryptographic matching always uses the full
public key.

The full identity (including the private key) is stored at
``<HAAP_DIR>/identity.json`` with 0600 permissions.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass, field

from .crypto import KeyPair, b64d, b64e
from .errors import HAAPError, NotInitializedError

IDENTITY_FORMAT = "haap-identity-v1"
IDENTITY_FILENAME = "identity.json"
FINGERPRINT_PREFIX = "HF-"
FINGERPRINT_HEX_LEN = 16


def haap_dir() -> str:
    """HAAP home directory (``HAAP_DIR`` env var or ``~/.haap``)."""
    return os.environ.get("HAAP_DIR", os.path.expanduser("~/.haap"))


def fingerprint_of_public_key(pub_raw: bytes) -> str:
    digest = hashlib.sha256(pub_raw).hexdigest()
    return FINGERPRINT_PREFIX + digest[:FINGERPRINT_HEX_LEN]


def fingerprint_matches(fp: str, pub_raw: bytes) -> bool:
    return fingerprint_of_public_key(pub_raw) == fp


@dataclass
class Identity:
    """HAAP agent identity (key pair + metadata)."""

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
        """Public information (no keys) — safe for manifests."""
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
                "unrecognized identity format (file from another version?)")
        if not isinstance(data.get("private_key"), str) or not data["private_key"]:
            raise HAAPError("identity.json missing private_key")
        kp = KeyPair.from_private_bytes(b64d(data["private_key"]))
        expected = fingerprint_of_public_key(kp.public_key)
        if data.get("fingerprint") != expected:
            raise HAAPError(
                "corrupt identity.json: fingerprint does not match public key")
        ep = data.get("endpoint") or {}
        return cls(
            keypair=kp,
            display_name=str(data.get("display_name") or "hermes-agent"),
            created_at=str(data.get("created_at") or ""),
            endpoint_transport=str(ep.get("transport") or "https"),
            endpoint_url=str(ep.get("url") or ""),
        )


class IdentityStore:
    """Loads/creates the local identity with safe permissions (0600)."""

    def __init__(self, directory: str | None = None):
        self.directory = directory or haap_dir()
        self.path = os.path.join(self.directory, IDENTITY_FILENAME)

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def create(self, display_name: str | None = None,
               endpoint_url: str = "", overwrite: bool = False) -> Identity:
        if os.path.exists(self.path) and not overwrite:
            raise HAAPError(
                f"an identity already exists at {self.path}; delete the file "
                "or use a different HAAP_DIR to regenerate")
        ident = Identity(keypair=KeyPair.generate(),
                         display_name=display_name or "hermes-agent",
                         endpoint_url=endpoint_url)
        self.save(ident)
        return ident

    def load(self) -> Identity:
        if not os.path.exists(self.path):
            raise NotInitializedError(
                f"no identity at {self.path}. Run first: haap init")
        with open(self.path, "r", encoding="utf-8") as fh:
            return Identity.from_dict(json.load(fh))

    def save(self, ident: Identity) -> None:
        os.makedirs(self.directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(ident.to_dict(), fh, indent=2)
            fh.write("\n")
        os.replace(tmp, self.path)
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
