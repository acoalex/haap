# HAAP — Arquitectura del Protocolo

**Versión del documento:** 1.0 · **Estado del protocolo:** 1.0 (core implementado)

HAAP (Hermes Agent Alliance Protocol) permite que agentes Hermes autónomos
en distintas máquinas se descubran, verifiquen identidad criptográfica,
negocien permisos y colaboren. Este documento define el diseño, el modelo
de amenazas y la gobernanza.

---

## 1. Principios

1. **La identidad vive en las claves, no en servicios.** Cada agente tiene un
   par Ed25519; su identidad pública es `HF-` + primeros 16 hex de
   `SHA-256(clave_pública)`. Ningún directorio ni intermediario puede
   suplantar a un agente.
2. **Aprobación humana para amistades.** Dos agentes nunca se hacen amigos
   solos: el dueño del receptor aprueba o rechaza cada solicitud.
3. **Deny-by-default.** Sin permiso explícito, toda acción es denegada.
4. **El directorio es guía telefónica, no notario.** Solo indexa manifests
   firmados y verifica control del endpoint. La confianza se establece
   siempre agente-a-agente.
5. **Todo queda auditado.** Cada decisión (aceptada o rechazada) deja traza
   append-only sin datos sensibles.
6. **Coste acotado.** Rate limits por (amigo, acción) impiden el
   denial-of-wallet.

## 2. Arquitectura general

```
┌─────────────────────┐                                   ┌─────────────────────┐
│  Agente A (personal)│                                   │ Agente B (negocio)  │
│  ┌───────────────┐  │                                   │  ┌───────────────┐  │
│  │ Hermes Agent  │  │                                   │  │ Hermes Agent  │  │
│  │  + haap CLI   │  │                                   │  │  + haap serve │  │
│  └───────┬───────┘  │                                   │  └───────┬───────┘  │
│  ┌───────┴───────┐  │      envelopes firmados Ed25519   │  ┌───────┴───────┐  │
│  │ HAAPServer    │◄──┼─────────── HTTPS ────────────────►│  │ HAAPServer    │  │
│  │ /haap/messages│  │                                   │  │ /haap/messages│  │
│  └───────────────┘  │                                   │  └───────┬───────┘  │
└──────────┬──────────┘                                   └──────────┼──────────┘
           │  search / register                                      │
           │                                              ┌──────────┴──────────┐
           ▼                                              │  Calendario CalDAV  │
┌─────────────────────┐                                   │  (citas del negocio)│
│ Directorio federado │                                   └─────────────────────┘
│  /search /register  │
│  proof-of-endpoint  │
└─────────────────────┘
```

Componentes:

| Módulo | Responsabilidad |
|---|---|
| `crypto.py` | Primitivas Ed25519, codificación base64 |
| `identity.py` | Par de claves persistente, fingerprint `HF-`, permisos 0600 |
| `envelope.py` | Envelope firmado, JSON canónico, anti-replay, ventana temporal |
| `directory.py` | Registro local de amigos (pending/accepted/blocked) + permisos |
| `permissions.py` | Matriz deny-by-default con scopes glob |
| `rate_limiter.py` | Token bucket por (amigo, acción) |
| `audit.py` | Auditoría append-only con redacción de secretos |
| `capabilities.py` | Manifest de capacidades (sin claves, nunca) |
| `tasks.py` | Ciclo de vida de tareas (estados A2A) |
| `transport.py` | Memory/HTTP transports |
| `server.py` | Servidor de mensajería + handshake + autorización |
| `registry.py` | Directorio federado (índice público) |
| `registry_client.py` | Cliente de directorio (register/search/heartbeat) |
| `cli.py` | Interfaz de línea de comandos |

## 3. Identidad y envelope

### 3.1 Identidad

- Par Ed25519 (32 B por clave) generado localmente.
- `fingerprint = "HF-" + SHA-256(clave_pública)[:16 hex]` — identificador
  corto para humanos y directorios; el matching criptográfico real usa la
  clave completa.
- Persistido en `$HAAP_DIR/identity.json` con permisos 0600. La clave
  privada **nunca** sale de la máquina ni viaja en mensajes.

### 3.2 Envelope (protocol_version 1.0)

```json
{
  "protocol_version":      "1.0",
  "message_type":          "task_request",
  "sender_fingerprint":    "HF-3f7a9c1b2d4e5f60",
  "recipient_fingerprint": "HF-83b91c82c444f558",
  "timestamp":             1788521676,
  "nonce":                 "<base64 16 bytes aleatorios>",
  "payload":               { ... },
  "signature":             "<base64 Ed25519 64 B>"
}
```

- La firma cubre el **JSON canónico determinista** (claves ordenadas,
  compacto, UTF-8, **floats prohibidos**) de todos los campos salvo
  `signature` → vincula emisor, receptor, timestamp, nonce y cuerpo
  (anti-sustitución de campos).
- Ventana de timestamp **±300 s** (`CLOCK_SKEW`).
- Anti-replay: `NonceManager` recuerda `(emisor, nonce)` por TTL de 660 s
  (2× ventana + margen) con poda perezosa.

### 3.3 Tipos de mensaje

Handshake y amistad: `hello`, `hello_ack`, `challenge`, `verify`,
`friend_request`, `friend_accept`.
Tareas: `task_request`, `task_accept`, `task_progress`, `task_result`.
Utilidades: `capabilities`, `ping`, `error`.

## 4. Handshake de amistad (modo *alliance*)

```
Agente A                                     Agente B
   │                                            │
   │── hello (clave pub de A en payload) ──────►│  B genera challenge
   │◄───── hello_ack {challenge} ───────────────│
   │                                            │
   │── challenge {challenge, firma_A(challenge)}►  B verifica:
   │                                            │   fingerprint==SHA256(clave)
   │                                            │   firma válida
   │◄───── verify {verified:true} ──────────────│  B registra a A (pending_in)
   │                                            │
   │── friend_request {capabilities} ──────────►│  B: pending_in + NOTIFICA AL
   │                                            │  DUEÑO (callback/webhook)
   │◄───── friend_request {received} ───────────│
   │                                            │
   │                                [APROBACIÓN HUMANA en B] │
   │                                            │
   │◄───── friend_accept {endpoint} ────────────│  B: pending_in → accepted
   │  A: pending_out → accepted                 │
   │                                            │
   │═══════ task_request/task_result ══════════►│  (con permisos + rate limit)
```

Puntos de confianza:

1. **Verificación autocontenida en bootstrap**: los mensajes `hello`,
   `challenge` y `friend_request` llevan la clave pública del emisor en el
   payload. El router comprueba `fingerprint == SHA-256(clave)` antes de
   verificar la firma. Un impostor que use su propia clave no coincide con
   el fingerprint reclamado; uno que robe el manifest no puede firmar el
   challenge (prueba de posesión de clave privada).
2. **La amistad no se establece sin humano.** El callback
   `on_friend_request` del servidor se cablea al chat del dueño
   (webhook de Hermes → Matrix/Telegram): `haap friends approve/deny`.
3. **Permisos al aprobar**: la matriz concedida queda en el registro del
   amigo (`FriendRecord.permissions`) y es deny-by-default.

## 5. Autorización de tareas

Para aceptar un `task_request`, el servidor exige, en orden:

1. Relación con el emisor en estado **accepted** (`FRIEND_NOT_FOUND` si no).
2. **Permiso** para la acción (`task:submit`, `file:read`, …) con scopes
   glob sobre el recurso (`PERMISSION_DENIED` si no).
3. **Rate limit**: token bucket por (amigo, acción) y global por amigo
   (`RATE_LIMITED`, con `retry_after`, marcado como reintentable).

Cada decisión queda en el audit log. Los códigos de error son estables
(`BAD_SIGNATURE`, `NONCE_REPLAY`, `PERMISSION_DENIED`, …) y viajan en
mensajes `error` sin información interna.

### 5.1 Ciclo de vida (nombres A2A)

```
submitted → accepted → working → completed
                │          │
                └─ rejected └─ failed
```

El path síncrono (el ejecutor responde al momento) recorre legalmente
`submitted → accepted → completed` en el registro local del servidor.

## 6. Directorio federado

### 6.1 Flujo de registro con proof-of-endpoint

```
Agente A                                      Directorio
   │                                             │
   │── POST /register {manifest_firmado, pubkey}►│  verifica firma del manifest
   │                                             │  verifica fingerprint==SHA256(clave)
   │                                             │  genera nonce (60 s TTL)
   │◄── {challenge_nonce, firma_directorio} ─────│
   │                                             │
   │── firma_A(nonce) ──────────────────────────►│  POST /register/complete
   │                                             │  verifica proof contra la clave
   │                                             │  validada en el submit
   │◄── {status: registered} ────────────────────│  A queda LISTADO
```

Garantías:

- **No se lista sin endpoint real**: el proof exige firmar el nonce con la
  clave privada desde el agente. Bots sin endpoint propio no se registran.
- **No se registran identidades ajenas**: el manifest viene firmado por la
  clave cuyo hash es el fingerprint; una clave distinta rompe la igualdad.
- **Las entradas expiran** sin heartbeat (24 h por defecto, renovación
  recomendada cada 6 h): los agentes muertos desaparecen solos.
- **Doble registro = actualización**, nunca duplicado.
- **El manifest nunca lleva claves** (`parse_manifest` rechaza payloads con
  `private_key`/`public_key`/`signature`): el directorio recuerda la clave
  validada en el submit en su estado de challenge.

### 6.2 Gobernanza: federación, no monopolio

- **Identidad descentralizada**: la identidad vive en las claves; el
  directorio no es autoridad de nada.
- **Múltiples directorios**: cada dueño configura en su cliente la lista de
  registros de confianza (`registries` en `$HAAP_DIR/config.json`). Puede
  existir un directorio por país, sector o comunidad sin coordinación.
- **La confianza se re-verifica**: tras descubrir a un agente en un
  directorio, cualquier cliente puede (y debe) consultar el
  `/.well-known/haap.json` del agente directamente y comprobar que el
  fingerprint coincide. Un directorio comprometido puede ocultar o
  envenenar resultados de búsqueda, pero no suplantar a un agente.
- **Sin verificación de negocio en v1**: la confirmación de que
  "Peluquería X" es de verdad ese negocio es la Fase 2 (verificación por
  dominio web o certificado comercial).

## 7. Modelos de confianza

### 7.1 Alliance (mutuo)

Amistad completa con aprobación humana. Permisos amplios y persistentes.
Para: agentes personales entre sí, VPS propios, familia/equipo.

### 7.2 Marketplace (abierto)

Negocios que publican servicios reservables sin amistad previa. La
apertura está acotada por scopes específicos (`booking:search`,
`booking:reserve`) que el negocio declara; todo lo demás sigue
deny-by-default. Requisitos por petición entrante: firma Ed25519 válida
(identidad real), rate limits estrictos, auditoría completa y blacklist
inmediata (`friends block`). Mensajes reservados:
`service_search`, `service_quote`, `service_book`, `service_cancel`
(namespace reservado; dispatcher en fases siguientes).

**Caso estrella**: agente personal reserva cita en peluquería cuyo agente
gestiona su calendario CalDAV de citas. Sin intervención humana en ningún
lado; auditoría completa en ambas máquinas.

## 8. Threat model

| # | Amenaza | Mitigación |
|---|---------|------------|
| T1 | **Spoofing** (hacerse pasar por otro agente) | Firma Ed25519 + binding fingerprint↔clave en cada envelope; challenge-response prueba posesión de la clave privada |
| T2 | **Replay** (reenviar mensajes capturados) | Nonce por emisor con TTL 660 s + ventana de timestamp ±300 s; reenvío fuera de ventana → `CLOCK_SKEW` |
| T3 | **MITM** (interceptar/modificar en tránsito) | Firma sobre JSON canónico de todo el envelope (anti-sustitución de campos); HTTPS recomendado; el canal HTTP plano solo es aceptable en red local confiable |
| T4 | **Amigo malicioso** (abusa de permisos concedidos) | Deny-by-default + scopes glob por recurso + rate limits por amigo + auditoría + `friends block` inmediato; el daño queda acotado a lo concedido |
| T5 | **Flooding** (agotar recursos) | Token buckets (acción + global por amigo), límite de tamaño de envelope (1 MB), tope de agentes por directorio (10 000), poda perezosa |
| T6 | **Compromiso de clave** (robo de identity.json) | Permisos 0600, clave nunca en mensajes/manifests/audit (redacción de secretos); rotación = nueva identidad + re-amistad; detección: el amigo ve un hello con nuevo fingerprint |
| T7 | **Fuga de información por errores/audit** | Códigos de error estables sin detalle interno; `AuditLog` redacta claves/firmas/payloads sensibles |
| T8 | **Denial-of-wallet** (forzar coste LLM) | Rate limits por (amigo, acción) antes de invocar al modelo; `task_request` sin permiso no consume tokens; precio por defecto conservador (5 task_request/rajada) |
| T9 | **Directorio malicioso** (envenenar descubrimiento) | El directorio no es autoridad de identidad; re-verificación directa del manifest en `/.well-known/` antes de confiar; federación: cambiar de directorio es cambiar una URL |
| T10 | **Sybil en el directorio** (registro masivo falso) | Proof-of-endpoint obligatorio (nonce firmado desde el endpoint declarado), tope de entradas, expiración por heartbeat |

## 9. Portabilidad de transporte

El envelope es agnóstico al transporte. Requisitos del transporte:
entregar bytes JSON y devolver la respuesta (o nada).

| Transporte | Estado | Notas |
|---|---|---|
| HTTPS (webhooks/servidor propio) | ✅ implementado (`HttpTransport`, `server.py`) | transporte primario |
| Matrix | documentado | los mensajes viajan como eventos en un room cerrado; el envelope firmado va en el body; ideal cuando ambos agentes ya viven en Matrix |
| Email | documentado | envelope como attachment JSON firmado; latencia alta, para colas lentas |
| Memory | ✅ implementado (`MemoryTransport`) | tests y dos agentes en el mismo proceso |

## 10. Compatibilidad con A2A

HAAP alinea conceptos con el estándar A2A (Google → Linux Foundation):

| Concepto | A2A | HAAP |
|---|---|---|
| Descubrimiento | Agent Card en `/.well-known/agent-card.json` | manifest en `/.well-known/haap.json` (mismo patrón) |
| Ciclo de vida | submitted/working/completed/failed/… | mismos nombres de estado (`tasks.py`) |
| Transporte | JSON-RPC 2.0 + SSE | envelope firmado propio (más simple) |
| Seguridad | esquemas OpenAPI (API key/OAuth) | **amistad con challenge-response + aprobación humana + permisos granulares** (diferencial de HAAP; A2A no trae capa de confianza de serie) |

Un puente futuro A2A↔HAAP es directo: exponer el manifest HAAP como Agent
Card y traducir JSON-RPC ↔ envelope. No se implementa en v1 para no
arrastrar la complejidad de JSON-RPC.

## 11. Hoja de ruta

- [x] v1.0 core: identidad, envelope, servidor, permisos, rate limits, auditoría
- [x] Directorio federado con proof-of-endpoint y heartbeats
- [x] CLI `haap` (init/whoami/friends/capabilities/task/serve/registry/audit)
- [ ] Cliente de mensajería `client.py` (task send con espera de resultado)
- [ ] Tipos marketplace (`service_search/quote/book/cancel`) en el dispatcher
- [ ] `ARQUITECTURA.md` en inglés
- [ ] Verificación de negocio (dominio web) en el directorio
- [ ] Sistema de reputación federado
- [ ] Puente a Hermes: webhook entrante → router HAAP; notificaciones al dueño
- [ ] Demo: agente personal ↔ agente de negocio (reserva CalDAV)
