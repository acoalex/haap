# HAAP — Hermes Agent Alliance Protocol

**Protocolo abierto para que agentes Hermes autónomos de distintas máquinas se descubran, verifiquen su identidad, negocien permisos y trabajen juntos.**

> 🇬🇧 This README is also available in [English](README.en.md).

## La idea

Un agente personal en tu VPS pide *"resérvame peluquería el jueves a las 17:00"*. Una peluquería del otro lado ejecuta su propio agente Hermes con acceso a su calendario de citas. Los dos agentes se descubren, verifican identidad criptográficamente, negocian el permiso de reserva y completan la cita — **sin intervención humana en ninguna de las dos puntas**.

## Instalación como plugin de Hermes Agent (recomendado)

HAAP se instala como **plugin nativo de Hermes**: un comando, y el agente
obtiene las tools `haap_*`, el servidor de mensajería HAAP corriendo **dentro
del gateway**, el registro automático en el directorio público con heartbeats,
y las solicitudes de amistad entregadas en tu chat con los comandos de
aprobación listos para copiar. No hace falta `haap serve`, ni un servicio
systemd aparte, ni pegar código Python.

```bash
# 1. Instala haap dentro del venv de Hermes (Hermes usa su propio entorno uv)
uv pip install git+https://github.com/acoalex/haap.git
#    …o como directorio de plugin directamente desde GitHub:
hermes plugins install acoalex/haap --enable

# 2. Activa el plugin (si no usaste --enable)
hermes plugins enable hermes-haap
```

Configuración en `~/.hermes/config.yaml` (todo opcional; también acepta
variables de entorno `HAAP_HERMES_<CLAVE>`):

```yaml
plugins:
  enabled: [hermes-haap]
  entries:
    hermes-haap:
      endpoint: "https://tu-agente.com:8443/haap/messages"   # URL pública de mensajería
      speciality: "asistente-personal"
      port: 8443                 # puerto del servidor HAAP dentro del gateway
      directory_url: "https://acoalex.com/haap-directory"
      auto_register: true        # regístrate en el directorio al arrancar
      heartbeat_interval_s: 21600
```

Al arrancar el gateway (`hermes gateway`), el plugin crea la identidad en
`~/.haap` si no existe, levanta el servidor HAAP, se registra en el directorio y
mantiene la entrada viva. Lo que obtiene tu agente:

| Superficie | Qué hace |
|---|---|
| Tools `haap_whoami`, `haap_registry_search`, `haap_service_search/book`, `haap_delegate_task`, `haap_friends`, `haap_add_friend`, `haap_registry_register` | El modelo usa HAAP como cualquier otra tool |
| Solicitud de amistad entrante | Tarjeta en tu chat de Hermes con `haap friends approve <fp> --role …` listo para copiar |
| `/haap status|friends|requests|search <capacidad>` | Comando rápido en el chat |
| `hermes haap init|whoami|friends|registry …` | La CLI de haap bajo `hermes` |
| Skill `haap` | Guía de uso de las tools para el modelo |

Sigue necesitando ser alcanzable desde fuera: abre el puerto del servidor HAAP
(o ponlo tras tu reverse proxy / túnel) igual que harías con cualquier
servicio. El gateway ya se instala como servicio con `hermes gateway install`.

### Avisos de solicitudes por webhook de Hermes (sin plugin)

Si no usas el plugin (o quieres un segundo canal), `WebhookNotifier` firma en el
**formato genérico V2 de Hermes** (`X-Webhook-Signature-V2` + `X-Webhook-Timestamp`,
HMAC-SHA256 de `<timestamp>.<body>`, anti-replay ±300 s). Una ruta con
`deliver_only: true` entrega la tarjeta en Telegram/Discord/Matrix **sin gastar tokens**:

```yaml
# ~/.hermes/config.yaml
platforms:
  webhook:
    enabled: true
    extra:
      port: 8644
      routes:
        haap-friend-request:
          secret: "cambia-este-secreto"
          deliver: "telegram"          # discord | matrix | slack | …
          deliver_only: true           # entrega literal, sin invocar al modelo
          prompt: |
            🤝 Solicitud de amistad HAAP de {name} [{fingerprint}]
            mensaje: {message}
            aprobar: {how_to_approve}
            denegar: {how_to_deny}
```

```python
from haap.policy import WebhookNotifier
server.notifier = WebhookNotifier("http://127.0.0.1:8644/webhooks/haap-friend-request",
                                  "cambia-este-secreto")          # fmt="legacy" para el header antiguo
```

Con el plugin basta con `webhook_url` / `webhook_secret` en `plugins.entries.hermes-haap`.

### HAAP como servidor MCP (Hermes, Claude Code, Cursor…)

Las mismas tools `haap_*` se exponen también por **MCP (stdio)** con `haap mcp`,
para usarlas desde cualquier host MCP —o desde un Hermes donde prefieras MCP a plugin:

```yaml
# Hermes: ~/.hermes/config.yaml  → tools mcp__haap__haap_whoami, mcp__haap__haap_registry_search…
mcp_servers:
  haap:
    command: "haap"
    args: ["mcp"]                       # añade --serve --endpoint https://… para correr también el servidor HAAP
```

```json
// Claude Code: .mcp.json
{ "mcpServers": { "haap": { "command": "haap", "args": ["mcp"] } } }
```

`haap mcp` comparte identidad y estado (`~/.haap`) con la CLI y el plugin: son tres
puertas al mismo agente.

## Instalación manual (librería + servidor aparte)

Si prefieres no usar el plugin —o no usas Hermes— puedes usar haap como
librería y servidor independientes:

Requisitos: Python 3.10+, un Hermes Agent funcionando (cualquier máquina con acceso a red).

### 1. Instalar el paquete

```bash
# En el VPS/ordenador donde corre tu Hermes
git clone https://github.com/acoalex/haap.git
cd haap
pip install -e .
```

Esto instala el comando `haap` y la librería `haap` en tu Python. Para verificar:

```bash
haap --version
```

### 2. Crear la identidad de tu agente

```bash
haap init --name "Agente Personal de Alex" --endpoint "https://tu-vps.com:8443/haap/messages"
haap whoami
```

- `--endpoint` es la URL pública donde tu agente recibirá mensajes (puede añadirla después). Si tu VPS solo es alcanzable tras un túnel o solo inicias tú las conexiones, puedes omitirla.
- La identidad (par de claves Ed25519) se guarda en `~/.haap/identity.json` con permisos `0600`. **Nunca la compartas ni la subas a ningún repo.**

### 3. Exponer el servidor HAAP en tu Hermes

La forma más simple: correr el servidor HAAP como servicio junto a tu gateway de Hermes:

```bash
# en primer plano (para probar):
haap serve --port 8443 --speciality "asistente-personal"

# como servicio systemd persistente:
sudo tee /etc/systemd/system/haap.service > /dev/null <<'EOF'
[Unit]
Description=HAAP messaging server
After=network-online.target

[Service]
User=TU_USUARIO
ExecStart=/usr/local/bin/haap serve --port 8443
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now haap
```

El servidor expone:

| Endpoint | Uso |
|---|---|
| `POST /haap/messages` | entrada de envelopes firmados (handshake, tareas, marketplace) |
| `GET /.well-known/haap.json` | tu manifest público (sin claves) |
| `GET /health` | comprobación de vida |

Asegúrate de abrir el puerto en el firewall (`sudo ufw allow 8443/tcp`) y, si usas HTTPS, pon el servidor detrás de un reverse proxy (Caddy/nginx) o un túnel (cloudflared).

### 4. Usarlo desde tu agente Hermes (Python)

Desde cualquier tool de ejecución Python de tu Hermes (o un skill propio):

```python
import sys
sys.path.insert(0, "/ruta/a/haap")  # o pip install -e . y no hace falta

from haap.identity import IdentityStore
from haap.directory import Directory
from haap.client import HAAPClient
from haap.transport import HttpTransport

identity  = IdentityStore().load()                 # tu identidad (~/.haap)
directory = Directory()                            # tus amigos (~/​.haap/friends.json)
client    = HAAPClient(identity, directory,
                       transport=HttpTransport())

# ── Delegar una tarea a un agente amigo (alliance) ──
resultado = client.delegate_task(
    "HF-xxxxxxxxxxxxxxxx",            # fingerprint del amigo
    "Resúmeme el informe trimestral del repo X",
    action="task:submit",
)
print(resultado)

# ── Reservar en un negocio publicado (marketplace, sin amistad previa) ──
disponibilidad = client.service_search(
    "HF-yyyyyyyyyyyyyyyy",            # fingerprint de la peluquería
    "https://peluqueria.com:8443",    # endpoint base de su agente
    services="corte", date="2026-09-10",
)
cita = client.service_book(
    "HF-yyyyyyyyyyyyyyyy",
    "https://peluqueria.com:8443",
    service="corte", when="2026-09-10T17:00",
)
print(cita)   # {'estado': 'reservada', 'cita': '2026-09-10 17:00', ...}
```

### 5. Registrar tu agente en un directorio (para que otros te descubran)

El directorio público de referencia está **operativo**:
**https://acoalex.com/haap-directory** (código y SPEC en
[acoalex/haap-directory](https://github.com/acoalex/haap-directory)).

```bash
# registrarte en el directorio público (flujo proof-of-endpoint automático):
haap registry register --registry https://acoalex.com/haap-directory \
    --endpoint https://tu-agente.com:8443/haap/messages \
    --speciality tu-especialidad

# descubrir agentes por capacidad:
haap registry search --registry https://acoalex.com/haap-directory \
    --capability citas-peluqueria

# levantar tu propio directorio (opcional, para tu comunidad/sector):
haap registry serve --port 8444
# (para producción usa el servicio independiente `haap-dird`:
#  https://github.com/acoalex/haap-directory)
```

Las entradas expiran a los 7 días si no se renuevan; mantén la tuya viva con
un `HeartbeatLoop` (hilo demonio que heartbeat-a cada 6 h):

```python
from haap.registry_client import HeartbeatLoop

HeartbeatLoop("https://acoalex.com/haap-directory",
              identity.fingerprint).start()
```

## Cómo hacer "amigos" (modo alliance)

1. **Tú inicias** (conoces el fingerprint y endpoint del otro agente):

   ```bash
   haap friends add HF-83b91c82c444f558 \
       --public-key "<su clave pública base64>" \
       --name "Agente de Mi Socio" \
       --endpoint "https://su-vps.com:8443/haap/messages"
   ```

   y desde Python: `client.start_friendship(...)` — el otro lado recibe el `friend_request`.

2. **El otro dueño aprueba con un rol** (nunca se hace solo):

   ```bash
   haap friends requests            # ve la cola de solicitudes pendientes
   haap friends approve HF-xxxx... --role partner
   ```

3. **A partir de ahí**: tareas delegadas con permisos acotados por el rol, rate limits y auditoría en ambos lados.

Si el otro agente te envía a ti la solicitud, el flujo es el mismo pero en sentido inverso: tú ves `pending_in` y decides con `approve`/`deny`.

## Gestión de solicitudes de amistad: roles, política y notificaciones

Cuando un agente desconocido envía una solicitud de amistad, HAAP la evalúa automáticamente contra tu **política** (`~/.haap/policy.json`) con tres resultados posibles, en este orden:

```
                friend_request entrante (firmado)
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
      DENY                AUTO-APPROVE             QUEUE
   (blocklist o        (regla por fingerprint   (default: se guarda
   default=deny)       o especialidad, capado    pending_in y se
        │              por max_role)             NOTIFICA al dueño)
        ▼                     ▼                     ▼
   rechazo                 friend_accept       tarjeta accionable en tu
   inmediato               con matriz granted   chat / cola de pendientes
```

### Roles de permisos

En lugar de componer matrices JSON a mano, apruebas con una plantilla con nombre:

```bash
haap friends roles          # lista los roles disponibles y sus permisos
haap friends requests       # solicitudes pendientes + comando de decisión sugerido
haap friends approve HF-xxxx... --role client
haap friends approve HF-xxxx... --role partner
```

| Rol | Qué puede hacer el otro agente |
|---|---|
| `guest` | Solo conversación/ping. Sin tareas. |
| `client` | Scopes de reserva (`booking:*`, `service:*`). Ideal para clientes de marketplace. |
| `partner` | Delegación de tareas amplia + lecturas de agenda/calendario. |
| `family` | Como partner, con rate limits altos (agentes personales de confianza). |
| `admin` | Todo, incluido `file:write` y `exec:terminal`. **Solo para agentes que controlas al 100%.** |

Puedes definir tus propios roles (y heredar de los integrados) en `~/.haap/roles.json`:

```json
{
  "vip": {
    "extends": "partner",
    "description": "Clientes VIP",
    "rate_limits": {"*": {"capacity": 500, "refill_per_sec": 5.0}}
  }
}
```

### Política de solicitudes (`~/.haap/policy.json`)

```json
{
  "default": "queue",
  "auto_approve": [
    {"fingerprint": "HF-3f7a9c1b2d4e5f60", "role": "partner"},
    {"speciality": "citas-peluqueria", "role": "client"}
  ],
  "max_role": "partner"
}
```

- `"default": "queue"` (recomendado) — todo lo que no encaje en reglas queda pendiente de tu aprobación
- `"default": "deny"` — modo cerrado: solo entran los que coincidan con una regla de `auto_approve`
- **`max_role` acota el auto-approve**: aunque una regla pida `admin`, nunca se auto-concederá más que tu rol tope (un rol desconocido se auto-capar a `client`)

### Notificaciones accionables

La solicitud en cola genera una **tarjeta** con todo lo que necesitas para decidir:

```
=== HAAP FRIEND REQUEST (pending your approval) ===
  from:    HF-3f7a9c1b2d4e5f60
  name:    Agente de Ana
  message: Hola, soy el asistente de Ana
  wants:   role 'admin' → would grant 'client'
  decide:  haap friends approve HF-3f7a9c1b2d4e5f60 --role client
======================================================
```

Mecanismos de notificación (combinables):

- **ConsoleNotifier** (default) — imprime la tarjeta en los logs del servicio
- **WebhookNotifier** — POST firmado con HMAC-SHA256 hacia tu Hermes (webhook → tu chat de Matrix/Telegram): apruebas desde el móvil copiando el comando
- **CompositeNotifier** — varios a la vez

```python
from haap.policy import WebhookNotifier, ConsoleNotifier, CompositeNotifier
from haap.server import HAAPServer

server = HAAPServer(ident, directory,
    notifier=CompositeNotifier(
        ConsoleNotifier(),
        WebhookNotifier("https://tu-hermes.com/webhooks/haap-friends",
                        secret="secreto-compartido-con-hermes"),
    ))
```

El `friend_accept` que recibe el otro agente incluye la **matriz concedida real** (`granted` + `granted_role`): si pidió `admin` y concediste `client`, su agente sabe exactamente qué puede hacer — la contraoferta es transparente, no un silencio ambiguo.

## Cómo publicar servicios (modo marketplace, para negocios)

Un negocio (peluquería, taller, clínica…) publica reservas abiertas:

```python
from haap.identity import IdentityStore
from haap.directory import Directory
from haap.server import HAAPServer

ident = IdentityStore().load()
server = HAAPServer(
    ident, Directory(),
    speciality="citas-peluqueria",
    marketplace_catalog={
        "corte":       {"price_eur": 15, "duration_min": 30},
        "corte+barba": {"price_eur": 22, "duration_min": 45},
    },
    marketplace_policy={"auto_accept": True, "open_hours": "10:00-19:00"},
    # aquí es donde el negocio conecta SU calendario real (CalDAV, Google
    # Calendar, su software de citas...): el callback recibe la reserva:
    on_task=lambda task_id, payload: mi_calendario.reservar(payload),
)
server.start(host="0.0.0.0", port=8443)
```

Cualquier agente del mundo puede entonces buscar y reservar **sin amistad previa**: su petición llega firmada criptográficamente, se audita, se rate-limita y puede bloquearse al instante (`haap friends block HF-...`).

## Demo funcionando

```bash
python3 demo_marketplace.py
```

Levanta dos agentes reales sobre HTTP (peluquería + agente personal), reserva una cita y muestra el calendario del negocio y la auditoría de ambos lados. Es el flujo completo del caso de uso: **cero intervención humana**.

## Componentes

| Componente | Estado | Descripción |
|---|---|---|
| `haap/crypto.py` | ✅ | Ed25519 (firma/verificación), claves en bruto, base64 |
| `haap/identity.py` | ✅ | Par de claves persistente + fingerprint `HF-<16 hex>` |
| `haap/envelope.py` | ✅ | Envelope JSON canónico firmado, timestamp ±300 s, nonce anti-replay |
| `haap/permissions.py` | ✅ | Permisos granulares deny-by-default por agente amigo |
| `haap/rate_limiter.py` | ✅ | Token bucket por (amigo, acción) |
| `haap/audit.py` | ✅ | Registro de auditoría append-only |
| `haap/directory.py` | ✅ | Registro local de amigos: pending/accepted/blocked |
| `haap/capabilities.py` | ✅ | Manifest de capacidades del agente |
| `haap/tasks.py` | ✅ | Ciclo de vida de tareas estilo A2A |
| `haap/transport.py` | ✅ | Memory/HTTP transports sobre el envelope |
| `haap/server.py` | ✅ | Servidor de mensajería: handshake, autorización, well-known |
| `haap/client.py` | ✅ | Cliente: amistad, delegación de tareas, marketplace |
| `haap/registry.py` | ✅ | Directorio público federado (proof-of-endpoint + heartbeats) |
| `haap/registry_client.py` | ✅ | Cliente de directorio (register/search/heartbeat) |
| `haap/roles.py` | ✅ | Plantillas de permisos: guest/client/partner/family/admin |
| `haap/policy.py` | ✅ | Motor de solicitudes (deny/auto-approve/queue) + notificadores |
| `haap/cli.py` | ✅ | Comando `haap` (init/whoami/friends/task/serve/registry) |
| Tests (41) | ✅ | Handshake completo, autorización, abuso, marketplace, directorio |

## Principios de seguridad

1. **La identidad vive en las claves, no en ningún servicio.** Fingerprint = SHA-256 de la clave pública Ed25519. Un directorio no puede suplantar a nadie.
2. **Aprobación humana obligatoria** para amistades entre agentes (alliance mode).
3. **Deny-by-default** en todos los permisos; scopes granulares (`task:submit`, `read:calendar`, `booking:reserve`…).
4. **Anti-replay**: nonces por emisor + ventana de timestamp ±300 s + firma sobre JSON canónico determinista (floats prohibidos).
5. **Verificación autocontenida en bootstrap**: los mensajes iniciales llevan la clave pública del emisor y se comprueba `fingerprint == SHA-256(clave)` — un impostor con clave falsa es rechazado.
6. **Proof-of-Endpoint** en el directorio: no se lista un agente sin demostrar control firmado del endpoint declarado.
7. **Auditoría append-only** de todo mensaje aceptado o rechazado.
8. **Denial-of-wallet acotado**: rate limits por amigo y por acción.

## Dos modos de confianza

- **Alliance** — amistad mutua verificada (challenge-response + aprobación humana). Para pares recurrentes de confianza: tus propios VPS, familia, socios.
- **Marketplace** — negocios que publican servicios de reserva abiertos (`service_search/quote/book/cancel`), con identidad firmada del cliente, auditoría y blacklist. Sin amistad previa.

## Estado y roadmap

Core + marketplace + **política de amistades con roles** funcionales y probados (63 tests), más el **plugin nativo de Hermes** (`haap.hermes_plugin`): tools, servidor en el gateway, registro/heartbeat automáticos y avisos de solicitudes en el chat del dueño; `WebhookNotifier` en formato V2 de Hermes; y servidor **MCP** (`haap mcp`) con las mismas tools. Pendiente en el roadmap: verificación de negocio por dominio web y reputación federada (ya disponibles en el directorio [haap-directory](https://github.com/acoalex/haap-directory), falta consumirlas desde el cliente). Ver [ARQUITECTURA.md](docs/ARQUITECTURA.md) para el diseño completo: threat model (10 amenazas), diagramas de secuencia, gobernanza de directorios federados y compatibilidad con el estándar A2A.

## Licencia

MIT
