# AGENTS.md

Guía para agentes que trabajen en este repositorio.

## Qué es HAAP

Protocolo abierto para que agentes Hermes autónomos de distintas máquinas se
descubran, verifiquen identidad criptográfica (Ed25519), negocien permisos y
colaboren. Python puro, sin framework web (usa `http.server`). No confundir con
`acoalex/haap-directory`, que es el servicio de directorio público independiente.

## Comandos

```bash
# Instalar en modo editable con dependencias de desarrollo
pip install -e ".[dev]"

# Ejecutar la suite de tests (41 tests)
pytest

# Probar la CLI
haap --version
python3 demo_marketplace.py
```

No hay linter ni typechecker configurados en el repo. Si introduces código,
ejecuta `pytest` para verificar que nada se rompe.

## Requisitos

- Python >= 3.10
- Dependencias de runtime: `cryptography>=41.0`, `requests>=2.28` (ver `pyproject.toml`)
- Dependencias de dev: `pytest>=7.0`

## Estructura

```
haap/                    # paquete principal
  crypto.py              # Ed25519 firma/verificación, base64
  identity.py            # par de claves persistente + fingerprint HF-<16 hex>
  envelope.py            # envelope JSON canónico firmado, timestamp ±300 s, nonce anti-replay
  permissions.py         # permisos deny-by-default
  rate_limiter.py        # token bucket por (amigo, acción)
  audit.py               # auditoría append-only
  directory.py           # amigos: pending/accepted/blocked
  capabilities.py        # manifest de capacidades
  tasks.py               # ciclo de vida de tareas estilo A2A
  transport.py           # Memory/HTTP transports
  server.py              # servidor de mensajería (handshake, autorización, well-known)
  client.py              # cliente (amistad, delegación, marketplace)
  registry.py            # directorio federado (proof-of-endpoint + heartbeats)
  registry_client.py     # cliente de directorio (register/search/heartbeat)
  roles.py               # roles: guest/client/partner/family/admin
  policy.py              # motor de friend-request (deny/auto-approve/queue) + notificadores
  cli.py                 # comando `haap`
tests/                   # test_client, test_marketplace, test_policy, test_registry, test_server
docs/                    # ARQUITECTURA.md, DIRECTORY_SERVICE_BRIEF.md
```

## Convenciones

- **Idioma**: README, docs y comentarios/docstrings están en español. Código en
  inglés. Mantén este estilo.
- **Python**: sin dependencias de tipos externas; usa stdlib + `cryptography` + `requests`.
- **Claves de identidad**: se guardan en `~/.haap/identity.json` con permisos
  `0600`. **Nunca** escribas, leas de o comitees archivos `identity.json`,
  `*.key`, `*.pem`, `.env` ni nada bajo `secrets/` (ver `.gitignore`).

## Reglas de seguridad que NO puedes romper

1. **JSON canónico determinista**: `envelope.py` exige serialización canónica
   sin floats (los floats están prohibidos en los payloads firmados). No
   introduzcas floats ni orden no determinista en nada que se firme.
2. **Verificación autocontenida en bootstrap**: los mensajes iniciales llevan la
   clave pública del emisor y se valida `fingerprint == SHA-256(clave)`.
3. **Anti-replay**: nonce por emisor + ventana de timestamp ±300 s. No relajes
   la ventana ni quites la comprobación de nonce.
4. **Deny-by-default** en permisos: si añades un scope nuevo, asegúrate de que
   queda denegado por defecto salvo que un rol lo conceda explícitamente.
5. **Aprobación humana obligatoria** en amistades (alliance mode): nunca
   auto-apruebes una amistad fuera del motor de política.
6. **Auditoría append-only**: todo mensaje aceptado o rechazado debe auditarse.

## Notas sobre tests

- Los tests usan `pytest` sin fixtures especiales de plugins; se apoyan en
  `transport.MemoryTransport` para los casos sin red.
- El CLI se invoca con `haap <subcomando>`; el punto de entrada es
  `haap.cli:main` (ver `[project.scripts]` en `pyproject.toml`).

<!-- OPENWIKI:START -->

## OpenWiki

This repository has a generated `openwiki/` evidence index. It is optional just-in-time context, not required startup reading.

- Treat source code and tests as authoritative. A brief's unknowns and review items are verification gaps, not automatic requirements.
- Prefer the narrowest quiet validation that proves the changed behavior. Preserve complete failure output.

The scheduled OpenWiki GitHub Actions workflow refreshes the repository wiki. Do not hand-edit generated OpenWiki pages unless explicitly asked; prefer updating source code/docs and letting OpenWiki regenerate.

<!-- OPENWIKI:END -->
