# HAAP — Hermes Agent Alliance Protocol

**Protocolo abierto para que agentes Hermes autónomos de distintas máquinas se descubran, verifiquen su identidad, negocien permisos y trabajen juntos.**

> 🇬🇧 This README is also available in [English](README.en.md).

## La idea

Un agente personal en tu VPS pide *"resérvame peluquería el jueves a las 17:00"*. Una peluquería del otro lado ejecuta su propio agente Hermes con acceso a su calendario de citas. Los dos agentes se descubren, verifican identidad criptográficamente, negocian el permiso de reserva y completan la cita — **sin intervención humana en ninguna de las dos puntas**.

## Instalación en tu propio Hermes Agent

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

```bash
# levantar tu propio directorio (opcional, para tu comunidad/sector):
haap registry serve --port 8444

# o registrarte en uno existente:
haap registry register --registry https://directorio.ejemplo.com --endpoint https://tu-vps.com:8443/haap/messages
haap registry search --registry https://directorio.ejemplo.com --capability citas-peluqueria
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

2. **El otro dueño aprueba** (nunca se hace solo):

   ```bash
   haap friends list                # ve la solicitud pending_in
   haap friends approve HF-xxxx... --grant '{"task:submit": {"allow": true, "scopes": ["informes:*"]}}'
   ```

3. **A partir de ahí**: tareas delegadas con permisos acotados, rate limits y auditoría en ambos lados.

Si el otro agente te envía a ti la solicitud, el flujo es el mismo pero en sentido inverso: tú ves `pending_in` y decides con `approve`/`deny`. El callback `on_friend_request` del servidor permite además notificar esa solicitud a tu chat de Hermes (Matrix/Telegram) para aprobarla desde el móvil.

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
| `haap/cli.py` | ✅ | Comando `haap` (init/whoami/friends/task/serve/registry) |
| Tests (29) | ✅ | Handshake completo, autorización, abuso, marketplace, directorio |

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

Core + marketplace **funcionales y probados** (29 tests). Pendiente en el roadmap: puente nativo con los webhooks de Hermes (notificaciones al chat del dueño), verificación de negocio por dominio web y reputación federada. Ver [ARQUITECTURA.md](docs/ARQUITECTURA.md) para el diseño completo: threat model (10 amenazas), diagramas de secuencia, gobernanza de directorios federados y compatibilidad con el estándar A2A.

## Licencia

MIT
