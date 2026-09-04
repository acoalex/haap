# -*- coding: utf-8 -*-
"""Manifiesto de capacidades de un agente HAAP.

Cada agente publica qué sabe hacer: nombre, descripción, especialidad,
herramientas/canales que expone y versiones. El manifest público
(``/.well-known/haap.json`` en el servidor HTTP y en respuestas a
``hello`` entre amigos ya aceptados) NO contiene claves ni datos
sensibles: solo identidad pública + capacidades.

El manifest completo (con introspección de skills de Hermes) se guarda
en ``<HAAP_DIR>/capabilities.json`` para inspección local y para que el
dueño decida qué publicar.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from . import __version__
from .errors import HAAPError
from .identity import haap_dir

CAPABILITIES_FILENAME = "capabilities.json"

# Rutas donde Hermes instala skills (configurables por env).
SKILLS_CANDIDATES = [
    os.path.expanduser("~/.hermes/skills"),
    os.path.expanduser("~/.hermes/profiles/default/skills"),
]

MESSAGE_TYPES_PUBLIC = [
    "hello", "challenge", "verify", "friend_request", "friend_accept",
    "capabilities", "task_request", "task_accept", "task_progress",
    "task_result", "ping", "error",
]


def _skill_name(path: Path) -> str:
    return path.name


def _read_frontmatter(skill_dir: Path) -> dict:
    """Lee el frontmatter YAML de SKILL.md de forma conservadora (solo
    las claves description y name, sin depender de un parser YAML)."""
    meta = {}
    md = skill_dir / "SKILL.md"
    if not md.exists():
        return meta
    try:
        text = md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return meta
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.S)
    if not m:
        return meta
    for line in m.group(1).splitlines():
        mm = re.match(r"^(description|name)\s*:\s*(.+)$", line.strip())
        if mm:
            meta[mm.group(1)] = mm.group(2).strip().strip("'\"")
    return meta


def scan_installed_skills(skills_dirs: list[str] | None = None) -> list[dict]:
    """Lista de skills instalados (para Hermes: <~/.hermes/skills>/**/SKILL.md)."""
    skills = []
    seen = set()
    for base in skills_dirs or SKILLS_CANDIDATES:
        base_p = Path(base)
        if not base_p.exists():
            continue
        for skill_dir in sorted(base_p.iterdir()):
            if not skill_dir.is_dir():
                continue
            if skill_dir.name in seen:
                continue
            md = skill_dir / "SKILL.md"
            if not md.exists():
                continue
            seen.add(skill_dir.name)
            meta = _read_frontmatter(skill_dir)
            skills.append({
                "name": meta.get("name") or _skill_name(skill_dir),
                "description": meta.get("description", ""),
            })
    return skills


def build_manifest(identity_public: dict, speciality: str = "",
                   skills_dirs: list[str] | None = None,
                   extra_tools: list[str] | None = None) -> dict:
    """Construye el capability manifest del agente local.

    ``identity_public``: salida de ``Identity.public_claims()``.
    """
    skills = scan_installed_skills(skills_dirs)
    manifest = {
        "format": "haap-capability-manifest-v1",
        "haap_version": __version__,
        "agent": identity_public,
        "speciality": speciality,
        "message_types": MESSAGE_TYPES_PUBLIC,
        "skills": skills,
        "tools": sorted(set(extra_tools or [])),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return manifest


def public_manifest(identity, speciality: str = "",
                    skills_dirs: list[str] | None = None,
                    messaging_url: str = "",
                    extra_tools: list[str] | None = None) -> dict:
    """Manifest PÚBLICO para ``/.well-known/haap.json`` (A2A-style).

    Solo fingerprint, nombre, especialidad, tipos de mensaje soportados,
    skills/herramientas y la URL de mensajería. NUNCA claves.
    """
    claims = identity.public_claims()
    claims.pop("display_name", None)
    return {
        "format": "haap-public-manifest-v1",
        "protocol_version": "1.0",
        "agent": {
            "fingerprint": identity.fingerprint,
            "name": identity.display_name,
            "speciality": speciality,
            "endpoint": messaging_url or identity.endpoint_url,
        },
        "message_types": MESSAGE_TYPES_PUBLIC,
        "skills": scan_installed_skills(skills_dirs),
        "tools": sorted(set(extra_tools or [])),
    }


def export_manifest(manifest: dict, directory: str | None = None,
                    filename: str = CAPABILITIES_FILENAME) -> str:
    """Persiste el manifest en <dir>/capabilities.json."""
    path = os.path.join(directory or haap_dir(), filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return path


def load_manifest(directory: str | None = None,
                  filename: str = CAPABILITIES_FILENAME) -> dict:
    path = os.path.join(directory or haap_dir(), filename)
    if not os.path.exists(path):
        raise HAAPError(f"no hay manifest en {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_manifest(data: str | bytes | dict) -> dict:
    """Parsea y valida un manifest (str JSON, bytes o dict) recibido de
    otro agente. Rechaza manifests con claves/secretos (defensa en
    profundidad: aunque venga firmado, no se procesan)."""
    if isinstance(data, (str, bytes)):
        try:
            manifest = json.loads(data)
        except ValueError as exc:
            raise HAAPError(f"manifest JSON inválido: {exc}") from exc
    else:
        manifest = data
    if not isinstance(manifest, dict):
        raise HAAPError("manifest debe ser un objeto JSON")
    agent = manifest.get("agent") or {}
    if not isinstance(agent.get("fingerprint"), str):
        raise HAAPError("manifest sin agent.fingerprint")
    for secret_key in ("private_key", "public_key", "signature"):
        if secret_key in manifest or secret_key in agent:
            raise HAAPError(
                f"manifest con campo prohibido '{secret_key}': no se procesa")
    return manifest
