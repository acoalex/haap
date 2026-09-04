# HAAP — Hermes Agent Alliance Protocol

**An open protocol for autonomous Hermes agents on different machines to discover each other, cryptographically verify their identity, negotiate permissions, and work together.**

> 🇪🇸 Este README también está disponible en [castellano](README.md).

## The idea

A personal agent on your VPS is asked to *"book me a hairdresser appointment on Thursday at 17:00"*. On the other side, a hair salon runs its own Hermes agent with access to its appointment calendar. The two agents discover each other, verify each other's identity cryptographically, negotiate the booking permission, and complete the appointment — **with zero human intervention on either side**.

## Components

| Component | Status | Description |
|---|---|---|
| `haap/crypto.py` | ✅ verified | Ed25519 (sign/verify), raw keys, base64 |
| `haap/identity.py` | ✅ verified | Persistent key pair + `HF-<16 hex>` fingerprint |
| `haap/envelope.py` | ✅ verified | Signed canonical-JSON envelope, ±skew timestamp, nonce anti-replay |
| `haap/permissions.py` | ✅ base | Granular deny-by-default permissions per friend |
| `haap/rate_limiter.py` | ✅ base | Token bucket per (friend, action) |
| `haap/audit.py` | ✅ base | Append-only audit trail |
| `haap/directory.py` | ✅ base | Local friends registry: pending/accepted/blocked |
| `haap/capabilities.py` | ✅ base | Agent capability manifest |
| `haap/tasks.py` | ✅ base | A2A-style task lifecycle |
| `haap/transport.py` | ✅ base | HTTP client/server over the envelope |
| `haap/server.py` | ✅ tested | Messaging server: handshake, authorization, well-known |
| `haap/registry.py` | ✅ base | Federated public directory w/ proof-of-endpoint |
| CLI `haap` | 🚧 in progress | init, whoami, friends, capabilities, task, serve |
| Tests | 🚧 in progress | Full handshake + abuse (replay, bad signature, flood) |

## Security principles

1. **Identity lives in the keys, not in any service.** Fingerprint = SHA-256 of the Ed25519 public key. A directory cannot impersonate anyone.
2. **Mandatory human approval** for agent-to-agent friendships (alliance mode).
3. **Deny-by-default** on all permissions; granular scopes (task:submit, read:calendar, booking:reserve…).
4. **Anti-replay**: per-sender nonces + ±300 s timestamp window + signature over deterministic canonical JSON (floats forbidden).
5. **Self-contained bootstrap verification**: hello/friend_request messages carry the sender's public key; the receiver checks fingerprint == SHA-256(key) before verifying the signature — an impostor with a fake key is rejected.
6. **Proof-of-Endpoint** in the directory: an agent is not listed without demonstrating signed control of its declared endpoint.
7. **Append-only audit trail** of every accepted or rejected message.
8. **Bounded denial-of-wallet**: rate limits per friend and per action.

## Two trust modes

- **Alliance** — mutual verified friendship (challenge-response + human approval). For recurring trusted pairs.
- **Marketplace** — businesses publishing open booking services (`service_search/quote/book/cancel`), with signed client identity, audit trail and blacklists. No prior friendship required.

## Quickstart (development)

```bash
git clone https://github.com/acoalex/haap.git && cd haap
pip install -r requirements.txt
python3 -c "
import sys; sys.path.insert(0, '.')
from haap.identity import IdentityStore
from haap import envelope
id_a = IdentityStore('/tmp/agent_a').create('Agent A')
id_b = IdentityStore('/tmp/agent_b').create('Agent B')
env = envelope.sign_body(id_a, 'ping', id_b.fingerprint, {'greeting': 'hello'})
envelope.verify_envelope(env, {id_a.fingerprint: id_a.keypair.public_key})
print('Signed and verified envelope:', id_a.fingerprint, '->', id_b.fingerprint)
"
```

Run the test suite:

```bash
python3 -m pytest tests/ -v
```

## Status

Project under active construction (September 2026). See [ARQUITECTURA.md](docs/ARQUITECTURA.md) (Spanish) for the full design (threat model, sequence diagrams, federated directory governance).

## License

MIT
