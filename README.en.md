# HAAP — Hermes Agent Alliance Protocol

**An open protocol for autonomous Hermes agents on different machines to discover each other, cryptographically verify their identity, negotiate permissions, and work together.**

> 🇪🇸 Este README también está disponible en [castellano](README.md).

## The idea

A personal agent on your VPS is asked to *"book me a hairdresser appointment on Thursday at 17:00"*. On the other side, a hair salon runs its own Hermes agent with access to its appointment calendar. The two agents discover each other, verify each other's identity cryptographically, negotiate the booking permission, and complete the appointment — **with zero human intervention on either side**.

## Installing into your own Hermes Agent

Requirements: Python 3.10+, a working Hermes Agent (any network-reachable machine).

### 1. Install the package

```bash
# On the VPS/machine where your Hermes runs
git clone https://github.com/acoalex/haap.git
cd haap
pip install -e .
```

This installs the `haap` command and the `haap` library. Verify:

```bash
haap --version
```

### 2. Create your agent's identity

```bash
haap init --name "Alex Personal Agent" --endpoint "https://your-vps.com:8443/haap/messages"
haap whoami
```

- `--endpoint` is the public URL where your agent receives messages (can be added later). If your VPS is only reachable through a tunnel, or you only make outbound connections, you can omit it.
- The identity (Ed25519 key pair) is stored at `~/.haap/identity.json` with `0600` permissions. **Never share it or commit it to any repository.**

### 3. Expose the HAAP server alongside your Hermes

Simplest form: run the HAAP server as a service next to your Hermes gateway:

```bash
# foreground (for testing):
haap serve --port 8443 --speciality "personal-assistant"

# as a persistent systemd service:
sudo tee /etc/systemd/system/haap.service > /dev/null <<'EOF'
[Unit]
Description=HAAP messaging server
After=network-online.target

[Service]
User=YOUR_USER
ExecStart=/usr/local/bin/haap serve --port 8443
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now haap
```

The server exposes:

| Endpoint | Purpose |
|---|---|
| `POST /haap/messages` | signed envelope intake (handshake, tasks, marketplace) |
| `GET /.well-known/haap.json` | your public manifest (no keys) |
| `GET /health` | liveness |

Open the port in your firewall (`sudo ufw allow 8443/tcp`) and, for HTTPS, put the server behind a reverse proxy (Caddy/nginx) or a tunnel (cloudflared).

### 4. Use it from your Hermes agent (Python)

From any Python execution tool of your Hermes (or a custom skill):

```python
from haap.identity import IdentityStore
from haap.directory import Directory
from haap.client import HAAPClient
from haap.transport import HttpTransport

identity  = IdentityStore().load()                 # your identity (~/.haap)
directory = Directory()                            # your friends (~/.haap/friends.json)
client    = HAAPClient(identity, directory,
                       transport=HttpTransport())

# ── Delegate a task to a friend agent (alliance) ──
result = client.delegate_task(
    "HF-xxxxxxxxxxxxxxxx",            # friend's fingerprint
    "Summarize the Q3 report of repo X",
    action="task:submit",
)
print(result)

# ── Book at a published business (marketplace, no prior friendship) ──
availability = client.service_search(
    "HF-yyyyyyyyyyyyyyyy",            # the salon's fingerprint
    "https://salon.com:8443",         # its agent's base endpoint
    services="haircut", date="2026-09-10",
)
booking = client.service_book(
    "HF-yyyyyyyyyyyyyyyy",
    "https://salon.com:8443",
    service="haircut", when="2026-09-10T17:00",
)
print(booking)   # {'status': 'reserved', 'cita': '2026-09-10 17:00', ...}
```

### 5. Register your agent with a directory (so others can find you)

```bash
# run your own directory (optional, for your community/sector):
haap registry serve --port 8444

# or register with an existing one:
haap registry register --registry https://directory.example.com --endpoint https://your-vps.com:8443/haap/messages
haap registry search --registry https://directory.example.com --capability appointments
```

## Making friends (alliance mode)

1. **You initiate** (you know the other agent's fingerprint and endpoint):

   ```bash
   haap friends add HF-83b91c82c444f558 \
       --public-key "<their base64 public key>" \
       --name "Partner Agent" \
       --endpoint "https://their-vps.com:8443/haap/messages"
   ```

   then from Python: `client.start_friendship(...)` — the other side receives the `friend_request`.

2. **The other owner approves** (never automatic):

   ```bash
   haap friends list                # they see the pending_in request
   haap friends approve HF-xxxx... --grant '{"task:submit": {"allow": true, "scopes": ["reports:*"]}}'
   ```

3. **From then on**: delegated tasks with bounded permissions, rate limits and audit on both sides.

If the other agent sends the request to you instead, the flow is the same in reverse: you see `pending_in` and decide with `approve`/`deny`. The server's `on_friend_request` callback can also push that request to your Hermes chat (Matrix/Telegram) so you can approve it from your phone.

## Publishing services (marketplace mode, for businesses)

A business (salon, workshop, clinic…) publishes open bookings:

```python
from haap.identity import IdentityStore
from haap.directory import Directory
from haap.server import HAAPServer

ident = IdentityStore().load()
server = HAAPServer(
    ident, Directory(),
    speciality="appointments",
    marketplace_catalog={
        "haircut":        {"price_eur": 15, "duration_min": 30},
        "haircut+beard":  {"price_eur": 22, "duration_min": 45},
    },
    marketplace_policy={"auto_accept": True, "open_hours": "10:00-19:00"},
    # this is where the business connects ITS real calendar (CalDAV, Google
    # Calendar, its booking software...): the callback receives the booking:
    on_task=lambda task_id, payload: my_calendar.book(payload),
)
server.start(host="0.0.0.0", port=8443)
```

Any agent in the world can then search and book **without prior friendship**: their request arrives cryptographically signed, gets audited, rate-limited, and can be blocked instantly (`haap friends block HF-...`).

## Live demo

```bash
python3 demo_marketplace.py
```

Spins up two real agents over HTTP (salon + personal agent), books an appointment, and shows the business's calendar plus both audit trails. That is the full use-case flow: **zero human intervention**.

## Components

| Component | Status | Description |
|---|---|---|
| `haap/crypto.py` | ✅ | Ed25519 (sign/verify), raw keys, base64 |
| `haap/identity.py` | ✅ | Persistent key pair + `HF-<16 hex>` fingerprint |
| `haap/envelope.py` | ✅ | Signed canonical-JSON envelope, ±300 s timestamp, nonce anti-replay |
| `haap/permissions.py` | ✅ | Granular deny-by-default permissions per friend |
| `haap/rate_limiter.py` | ✅ | Token bucket per (friend, action) |
| `haap/audit.py` | ✅ | Append-only audit trail |
| `haap/directory.py` | ✅ | Local friends registry: pending/accepted/blocked |
| `haap/capabilities.py` | ✅ | Agent capability manifest |
| `haap/tasks.py` | ✅ | A2A-style task lifecycle |
| `haap/transport.py` | ✅ | Memory/HTTP transports over the envelope |
| `haap/server.py` | ✅ | Messaging server: handshake, authorization, well-known |
| `haap/client.py` | ✅ | Client: friendship, task delegation, marketplace |
| `haap/registry.py` | ✅ | Federated public directory (proof-of-endpoint + heartbeats) |
| `haap/registry_client.py` | ✅ | Directory client (register/search/heartbeat) |
| `haap/cli.py` | ✅ | `haap` command (init/whoami/friends/task/serve/registry) |
| Tests (29) | ✅ | Full handshake, authorization, abuse, marketplace, directory |

## Security principles

1. **Identity lives in the keys, not in any service.** Fingerprint = SHA-256 of the Ed25519 public key. A directory cannot impersonate anyone.
2. **Mandatory human approval** for agent-to-agent friendships (alliance mode).
3. **Deny-by-default** on all permissions; granular scopes (`task:submit`, `read:calendar`, `booking:reserve`…).
4. **Anti-replay**: per-sender nonces + ±300 s timestamp window + signature over deterministic canonical JSON (floats forbidden).
5. **Self-contained bootstrap verification**: initial messages carry the sender's public key and the receiver checks `fingerprint == SHA-256(key)` — an impostor with a fake key is rejected.
6. **Proof-of-Endpoint** in the directory: an agent is not listed without demonstrating signed control of its declared endpoint.
7. **Append-only audit trail** of every accepted or rejected message.
8. **Bounded denial-of-wallet**: rate limits per friend and per action.

## Two trust modes

- **Alliance** — mutual verified friendship (challenge-response + human approval). For recurring trusted pairs: your own VPSes, family, partners.
- **Marketplace** — businesses publishing open booking services (`service_search/quote/book/cancel`), with signed client identity, audit trail and blacklists. No prior friendship required.

## Status & roadmap

Core + marketplace **functional and tested** (29 tests). Roadmap items: native Hermes webhook bridge (owner chat notifications), business verification via domain web, federated reputation. See [ARQUITECTURA.md](docs/ARQUITECTURA.md) (Spanish) for the full design: threat model (10 threats), sequence diagrams, federated directory governance and compatibility with the A2A standard.

## License

MIT
