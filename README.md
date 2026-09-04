# HAAP — Hermes Agent Alliance Protocol

**Protocolo abierto para que agentes Hermes autónomos de distintas máquinas se descubran, verifiquen su identidad, negocien permisos y trabajen juntos.**

> 🇬🇧 This README is also available in [English](README.en.md).

## La idea

Un agente personal en tu VPS pide *"resérvame peluquería el jueves a las 17:00"*. Una peluquería del otro lado ejecuta su propio agente Hermes con acceso a su calendario de citas. Los dos agentes se descubren, verifican identidad criptográficamente, negocian el permiso de reserva y completan la cita — **sin intervención humana en ninguna de las dos puntas**.

## Componentes

| Componente | Estado | Descripción |
|---|---|---|
| `haap/crypto.py` | ✅ verificado | Ed25519 (firma/verificación), claves en bruto, base64 |
| `haap/identity.py` | ✅ verificado | Par de claves persistente + fingerprint `HF-<16 hex>` |
| `haap/envelope.py` | ✅ verificado | Envelope JSON canónico firmado, timestamp ±skew, nonce anti-replay |
| `haap/permissions.py` | ✅ base | Permisos granulares deny-by-default por agente amigo |
| `haap/rate_limiter.py` | ✅ base | Token bucket por (amigo, acción) |
| `haap/audit.py` | ✅ base | Registro de auditoría append-only |
| `haap/directory.py` | ✅ base | Registro local de amigos: pending/accepted/blocked |
| `haap/capabilities.py` | ✅ base | Manifest de capacidades del agente |
| `haap/tasks.py` | ✅ base | Ciclo de vida de tareas estilo A2A |
| `haap/transport.py` | ✅ base | Cliente/servidor HTTP sobre el envelope |
| Servidor de mensajería | 🚧 en curso | Router de mensajes con validación y desafíos |
| Directario público federado | 🚧 en curso | Registro con proof-of-endpoint + heartbeats |
| CLI `haap` | 🚧 en curso | init, whoami, friends, capabilities, task, serve |
| Tests | 🚧 en curso | Handshake completo + abuso (replay, firma inválida, flood) |

## Principios de seguridad

1. **La identidad vive en las claves, no en ningún servicio.** Fingerprint = SHA-256 de la clave pública Ed25519. Un directorio no puede suplantar a nadie.
2. **Aprobación humana obligatoria** para amistades entre agentes (alliance mode).
3. **Deny-by-default** en todos los permisos; scopes granulares (task:submit, read:calendar, booking:reserve…).
4. **Anti-replay**: nonces por emisor + ventana de timestamp ±300 s + firma sobre JSON canónico determinista (floats prohibidos).
5. **Proof-of-Endpoint** en el directorio: no se lista un agente sin demostrar control firmado del endpoint declarado.
6. **Auditoría append-only** de todo mensaje aceptado o rechazado.
7. **Denial-of-wallet acotado**: rate limits por amigo y por acción.

## Dos modos de confianza

- **Alliance** — amistad mutua verificada (challenge-response + aprobación humana). Para pares recurrentes de confianza.
- **Marketplace** — negocios que publican servicios de reserva abiertos (`service_search/quote/book/cancel`), con identidad firmada del cliente, auditoría y blacklist. Sin amistad previa.

## Quickstart (desarrollo)

```bash
git clone https://github.com/acoalex/haap.git && cd haap
pip install -r requirements.txt
python3 -c "
import sys; sys.path.insert(0, '.')
from haap.identity import IdentityStore
from haap import envelope
id_a = IdentityStore('/tmp/agent_a').create('Agente A')
id_b = IdentityStore('/tmp/agent_b').create('Agente B')
env = envelope.sign_body(id_a, 'ping', id_b.fingerprint, {'saludo': 'hola'})
envelope.verify_envelope(env, {id_a.fingerprint: id_a.keypair.public_key})
print('Envelope firmado y verificado:', id_a.fingerprint, '->', id_b.fingerprint)
"
```

## Estado

Proyecto en construcción activa (septiembre 2026). Ver [ARQUITECTURA.md](docs/ARQUITECTURA.md) para el diseño completo (threat model, diagramas de secuencia, gobernanza de directorios federados).

## Licencia

MIT
