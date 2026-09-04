# HAAP Public Directory — Agent Implementation Brief

**Document version:** 1.0 · **Date:** 2026-09-04 · **Audience:** an AI coding agent (or developer) tasked with implementing a production-grade HAAP Public Directory service.

**You are implementing the "phone book" of the HAAP ecosystem**: a public, federated service where HAAP agents register themselves so that other agents (and humans) can discover them by capability, speciality, geography or free text.

Read this document completely before writing code. It defines the context, the data contracts, the API, the security requirements, the acceptance tests and the quality bar. If anything is ambiguous, prefer the safest interpretation and document the decision in your delivery report.

---

## 1. Context: what HAAP is and where the directory fits

HAAP (Hermes Agent Alliance Protocol) is an open protocol that lets autonomous Hermes agents on different machines discover each other, verify each other's identity cryptographically, negotiate permissions and collaborate (delegate tasks, book appointments, chat).

Existing HAAP components you MUST NOT modify (they are done, tested, and versioned):

| Module | What it gives you |
|---|---|
| `haap/crypto.py` | `KeyPair` (Ed25519, raw 32-byte keys), `sign()`, `verify_with(raw_pub, data, sig)`, `b64e`, `b64d` |
| `haap/identity.py` | `Identity`, `IdentityStore`, and **`fingerprint_of_public_key(raw_pub_bytes) -> "HF-<16 hex>"`** |
| `haap/envelope.py` | `sign_body(identity, message_type, recipient_fp, payload)`, `envelope_to_bytes/from_bytes`, `verify_envelope(env, trusted_pubkeys, nonces)`, `NonceManager`, `MAX_CLOCK_SKEW = 300` |
| `haap/capabilities.py` | `public_manifest(identity, speciality, ...)` builds the agent manifest (`haap-public-manifest-v1`) |
| `haap/registry.py` | A **minimal in-memory reference implementation** of the directory (`RegistryStore`, `RegistryServer`) with proof-of-endpoint. Your job is to build the production evolution of this: persistent, hardended, observable, multi-instance-safe. Reuse its logic and data shapes — external behaviour must stay wire-compatible. |
| `haap/registry_client.py` | `register()`, `search()`, `heartbeat()`, `HeartbeatLoop` — the client side. Your service must remain compatible with this client without changes. |

Key design principle (do not violate): **the directory is a phone book, not a notary.** Identity lives in the agents' Ed25519 keys, not in the directory. The directory indexes signed manifests and verifies endpoint control; it is never an authority for identity, and its compromise must not allow impersonation.

Reference documents in this repo: `docs/ARQUITECTURA.md` (design + threat model), `README.md` (usage), `tests/test_registry.py` + `tests/test_registry_client.py` (existing behaviour you must not break).

## 2. Mission

Build a production-grade **HAAP Public Directory** service (`haap/directory_service/` package + `haap-dird` CLI entry point) that:

1. Lets agents **register** with a signed capability manifest, after proving they control the messaging endpoint they declare (**proof-of-endpoint**).
2. Lets anyone **search** registered agents by capability, speciality, geographic area, language, free text and pagination — returning everything needed to connect: fingerprint, endpoint, capabilities, supported message types, roles accepted, protocol version.
3. Keeps the index **fresh** via signed heartbeats and automatic expiry of dead entries.
4. Supports **rich agent activity information**: what the agent does, service categories, contact/booking hints, accepted roles for friendships, permission scopes it is willing to grant, operational metadata (uptime expectations, languages, pricing hints).
5. Is **hardened** against the abuse vectors in §8 and observable (logs, metrics, health).
6. Persists state (SQLite) so a restart does not lose the index, and supports concurrent access safely.

Out of scope for this brief (do not build): agent-to-agent authentication mediation, payment processing, human identity verification (KYC), a global unique directory (the design is federated — many directories, no central authority).

## 3. Data contracts (wire formats — do not change field names)

### 3.1 Agent manifest (published by agents, stored by the directory)

The manifest is the canonical JSON of the agent's public capabilities. It is produced by `haap.capabilities.public_manifest(...)` and then **extended with directory-specific metadata** before signing. Extended manifest shape (v1, `format: "haap-public-manifest-v1"`):

```json
{
  "format": "haap-public-manifest-v1",
  "protocol_version": "1.0",
  "agent": {
    "fingerprint": "HF-3f7a9c1b2d4e5f60",
    "name": "Peluqueria Euraka",
    "speciality": "citas-peluqueria",
    "endpoint": "https://euraka.example.com:8443/haap/messages",
    "description": "Peluquería unisex en Vitoria-Gasteiz. Reservas automáticas 24/7.",
    "owner_contact": "mailto:citas@euraka.example.com",
    "languages": ["es", "eu"],
    "geo": {"city": "Vitoria-Gasteiz", "country": "ES",
            "lat": 42.8467, "lon": -2.6716, "radius_km": 15},
    "availability": {"timezone": "Europe/Madrid",
                     "hours": [{"days": [1,2,3,4,5], "open": "10:00", "close": "19:00"}]},
    "trust_mode": "marketplace"
  },
  "services": [
    {"id": "corte", "name": "Corte de pelo", "category": "hairdresser",
     "price_eur": 15, "duration_min": 30,
     "booking": {"mode": "instant", "scopes": ["booking:reserve"]}}
  ],
  "message_types": ["hello", "task_request", "service_search", "service_book"],
  "roles_accepted": ["guest", "client"],
  "permission_scopes_offered": ["booking:search", "booking:reserve"],
  "capabilities_flags": {"streaming": false, "push": true, "async_tasks": true},
  "skills": [{"name": "caldav-booking", "description": "..."}],
  "tools": ["caldav"],
  "haap_version": "1.0.0",
  "generated_at": "2026-09-04T12:00:00Z"
}
```

Field rules:

- `agent.fingerprint` MUST match `^HF-[0-9a-f]{16}$` and MUST equal `fingerprint_of_public_key(public_key)`.
- `agent.endpoint` MUST be `http(s)://...` and MUST NOT contain a query string or fragment. This is where proof-of-endpoint and later agent-to-agent traffic happen.
- `services[]` entries: `id` unique within the manifest, `category` free-form lowercase, `booking.mode` one of `instant | request | manual`. `price_eur` is OPTIONAL (a business may hide prices) and when present must be a **string** like `"15.00"` or an integer — never a float (canonical JSON forbids floats).
- `roles_accepted`: which of the built-in roles (`guest, client, partner, family, admin`) the agent will honour for inbound friendship requests.
- `permission_scopes_offered`: scope strings the agent is willing to grant outbound (informational — actual grants happen agent-to-agent).
- Forbidden anywhere in the manifest: `private_key`, `signature`, `nonce`. If present, reject the registration (existing `parse_manifest` behaviour).

### 3.2 Registration flow (proof-of-endpoint, 3 round trips)

```
Agent                                        Directory
  │                                             │
  │ POST /v1/register                           │
  │  { manifest, public_key_b64,                │  1. verify manifest signature Ed25519
  │    manifest_signature }                     │  2. verify fingerprint == SHA256(pubkey)[:16hex]
  │                                             │  3. validate schema + forbidden fields
  │  ◄─ 202 { challenge_id, nonce,              │  4. store pending challenge (TTL 120 s)
  │         registry_fingerprint,               │
  │         expires_at, algorithm:"ed25519" }   │
  │                                             │
  │  signs nonce with its PRIVATE key           │
  │                                             │
  │ POST /v1/register/challenge                 │
  │  { challenge_id, fingerprint,               │  5. look up pending challenge (exact match,
  │    endpoint_proof }                         │     single-use, not expired)
  │                                             │  6. verify endpoint_proof with the pubkey
  │                                             │     bound to the challenge_id
  │  ◄─ 201 { status:"registered", agent_url,   │  7. list the agent (persist to SQLite)
  │          expires_at, directory_fingerprint }│
```

Wire-compatibility note: the reference implementation in `haap/registry.py` uses a two-call flow (`/register` → `/register/complete`). Your service MUST support both the legacy pair (`POST /register`, `POST /register/complete`) AND the versioned pair above (`/v1/...`) — the existing `registry_client.py` client uses the legacy routes and must keep working unmodified. Recommend: implement `/v1/*` as the canonical API and thin legacy aliases.

Proof verification rules (existing behaviour, keep): the endpoint proof MUST verify with `KeyPair.verify_with(raw_pub, nonce_bytes, proof)`; a proof signed by any other key MUST be rejected and the agent NOT listed; a mismatched `public_key_b64` between register and challenge MUST be rejected (see `tests/test_registry.py::test_failed_endpoint_proof_not_listed`).

### 3.3 Heartbeat

```
POST /v1/heartbeat  { fingerprint, timestamp, signature }
  → signature covers "heartbeat:{fingerprint}:{timestamp}" (ASCII)
  → timestamp within ±300 s of server time
  → 200 {status:"ok", expires_at}   |   404 {error:"unknown_or_expired"}
```

Default entry TTL: 24 h without heartbeat (configurable). Heartbeats may also be sent over the legacy `POST /heartbeat {fingerprint}` form.

### 3.4 Search

```
GET /v1/search?capability=citas&geo=42.85,-2.67,25&q=peluqueria&limit=20&offset=0
  → 200 { "results": [manifest...], "total": N, "limit": 20, "offset": 0 }
```

- `capability`: substring match (case-insensitive) against `speciality`, `services[].id`, `services[].category`, `tools[]`, `skills[].name`.
- `q`: free text, case-insensitive, over the full manifest JSON; multiple words = AND.
- `geo=lat,lon,radius_km`: haversine distance against `agent.geo.lat/lon` when present; entries without geo are excluded from geo-filtered searches.
- `limit` default 20, max 100 (higher → clamp, do not error). `offset` for pagination. Response includes `total` (count of all matches ignoring pagination).

### 3.5 Agent profile

```
GET /v1/agents/{fingerprint}   → 200 manifest | 404 {error}
GET /health                    → 200 {status, agents, version, uptime_s}
```

## 4. Architecture requirements

**Package layout** (create under the existing repo, follow its conventions — English docstrings, type hints, small focused modules):

```
haap/directory_service/
  __init__.py          # version + public exports
  store.py             # SQLite persistence layer (all SQL lives here)
  models.py            # dataclasses / TypedDicts for AgentRecord, Challenge, SearchQuery
  service.py           # business logic: registration state machine, search, expiry (no HTTP)
  http_api.py          # stdlib http.server ThreadingHTTPServer wiring (same style as registry.py)
  rate_limit.py        # per-IP token buckets for anonymous endpoints
  notifiers.py         # optional ops notifications (e.g. registration flood alerts)
haap_dird.py or CLI hook   # `haap-dird` entry point: --db, --host, --port, --ttl, --backup
tests/test_directory_service.py
docs/DIRECTORY_SERVICE.md   # operator guide: run, configure, backup, monitor
```

**Storage (SQLite, file-backed):**

- Tables: `agents(fingerprint PK, public_key_b64, manifest_json, registered_at, last_heartbeat, expires_at, listed INTEGER)`, `challenges(challenge_id PK, fingerprint, nonce, public_key_b64, endpoint, created_at, expires_at, used INTEGER)`, `audit_log(id PK AUTOINCREMENT, ts, event, fingerprint, result, detail_json)` — plus indexes you deem necessary.
- WAL mode; all access through a single module with proper transactions; safe under threads (use a connection per thread or a serialized writer — measure, choose, document).
- On startup, prune expired entries; prune lazily on reads too (same semantics as the reference: an entry is "listed" iff `now <= expires_at`).
- Re-registration of a live fingerprint = **update** (bump fields, keep `registered_at`); registration of an expired fingerprint = fresh insert.

**Backwards compatibility (hard requirement):** all existing tests must keep passing (`python3 -m pytest tests/` → 41 passed). `haap/registry.py` and `haap/registry_client.py` stay untouched unless a bug forces a change (then: separate `fix:` commit, documented).

## 5. Security requirements (non-negotiable)

1. **All cryptographic verification server-side**: manifest signature, fingerprint↔key binding, endpoint proof. Never trust client-supplied fingerprint without recomputing `fingerprint_of_public_key(public_key)`.
2. **Proof-of-endpoint is mandatory and single-use**: one challenge, one use, 120 s TTL, bound to the exact `public_key_b64` validated at submit time. Failed proof → NOT listed (test exists: `test_failed_endpoint_proof_not_listed`).
3. **Manifests never contain keys**: reject on `private_key`, `signature`, `nonce` at any depth (mirror `capabilities.parse_manifest`).
4. **No floats in signed data**: prices etc. as strings/integers; reject floats in the signed manifest with a clear error.
5. **Anti-flooding**: per-IP token buckets on anonymous endpoints (register: e.g. 5/hour burst 2; search: 60/min; heartbeat: tied to the agent fingerprint rather than IP). Cap total listed agents (configurable, default 10 000) with a clear error when full. Challenge table capped (e.g. 5 000 pending) — evict oldest.
6. **Canonical JSON for signatures**: exactly `json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()` — same as the reference and client. Any deviation breaks verification; do not "improve" it.
7. **Reject oversized payloads** (manifest > 256 KiB → 413) and malformed JSON with 400 + stable error codes (uppercase snake case, e.g. `INVALID_SCHEMA`, `SIGNATURE_MISMATCH`, `CHALLENGE_EXPIRED`, `CHALLENGE_USED`, `RATE_LIMITED`, `DIRECTORY_FULL`, `FORBIDDEN_FIELD`).
8. **Errors never leak internals**: stable code + short message only; log details server-side with the secret-redaction approach used by `haap/audit.py`.
9. **Audit everything** (registration accepted/rejected + reason, heartbeats, expirations, search abuse) into the `audit_log` table — append-only, no secrets.
10. **Rate-limit headers** on 429: `Retry-After` (seconds).

## 6. Operational requirements

- **CLI**: `haap-dird --db /var/lib/haap/dird.db --host 0.0.0.0 --port 8444 --ttl-hours 24 --max-agents 10000`. Also `--backup-every-hours N` writing a consistent SQLite backup copy; `haap-dird --prune` for offline pruning; graceful shutdown on SIGTERM/SIGINT (finish in-flight request, flush, close DB).
- **Observability**: `/health` (status, listed count, pending challenges, version, uptime); structured logs (JSON lines) for registrations, rejections with reason, expiry prunes, flood alerts; count of registrations/queries exposed in `/health` (or `/metrics` if you prefer, plain text).
- **Config file** optional: `~/.haap/dird.json` (host, port, db path, ttl, limits) — CLI flags override it. Document precedence.

## 7. Testing requirements (acceptance bar)

All in `tests/test_directory_service.py` (plus any files you need). Use pytest, tmp_path fixtures, real HTTP on ephemeral ports (127.0.0.1, port 0) like the existing tests. Minimum coverage of scenarios:

1. **Happy path**: register (3-round-trip proof-of-endpoint) → listed → search finds by capability, speciality and q → profile fetch → heartbeat renews → profile still listed.
2. **Rejection cases** (each with its stable error code): bad manifest signature; fingerprint↔key mismatch; forbidden field present; float price; malformed JSON; oversized manifest; endpoint without http(s); challenge expired; challenge reused; proof signed by wrong key; public_key mismatch between register and challenge; directory full.
3. **Update vs duplicate**: re-register same fingerprint (live) → update, count stable; register after expiry → fresh entry.
4. **Expiry**: entry disappears after TTL (inject a clock — the service must accept a `clock` callable like `RateLimiter` does; do not sleep real TTLs).
5. **Search semantics**: multi-word AND; geo radius include/exclude; pagination (`limit`/`offset`/`total`); clamping of oversized `limit`; empty results shape.
6. **Concurrency**: parallel registrations of distinct fingerprints all succeed; parallel heartbeats on one fingerprint all renew (no lost update).
7. **Persistence**: restart the service against the same DB file → entries survive, expired ones are pruned.
8. **Backwards compatibility**: the *unmodified* `tests/test_registry.py` and `tests/test_registry_client.py` still pass; `registry_client.register/search/heartbeat` work against your service unmodified.
9. **Abuse**: IP rate limiting produces 429 + Retry-After; audit rows exist for each rejection.

Run the full suite (`python3 -m pytest tests/ -v`) and include the exact tail output in your report. All tests must pass; no skipped tests without justification.

## 8. Threat model for the directory (address each in your report)

| # | Threat | Required mitigation |
|---|---|---|
| T1 | Impersonation (register someone else's fingerprint) | Manifest must be signed by the key whose hash is the fingerprint; proof-of-endpoint bound to that key |
| T2 | Fake endpoint / honeypot listing | Proof-of-endpoint proves control at registration; heartbeats keep proving liveness (signed) |
| T3 | Replay of registration/heartbeat | Nonce single-use + TTL (challenges); heartbeat timestamp ±300 s |
| T4 | Index poisoning (garbage manifests) | Schema validation, size caps, forbidden fields, audit trail |
| T5 | Flooding / resource exhaustion | IP rate limits, caps on agents and challenges, payload limits |
| T6 | Enumeration of all agents | Accepted by design (it is a public directory); mitigate abuse with rate limits, not secrecy |
| T7 | Directory operator tampers with manifests | Out of scope for the wire protocol by design; clients MUST re-verify `/.well-known/haap.json` against the agent before trusting (document this in DIRECTOR Y_SERVICE.md §"Trust boundaries") |
| T8 | SQL injection / request smuggling | Parameterized SQL only; strict Content-Length handling; no string-built queries |
| T9 | Denial of wallet (for the directory operator) | Rate limits + caps + optional registration cost hook (documented stub, off by default) |
| T10 | Stale/dead entries | TTL + signed heartbeats + prune on read and on startup |

## 9. Quality bar and working conventions

- Python 3.10+ stdlib first (http.server like the reference). SQLite via stdlib `sqlite3`. Third-party deps only if unavoidable — `cryptography`, `requests` already allowed; anything else needs justification in the report.
- **All code in English** (docstrings, comments, errors). Type hints everywhere. No floats in signed data. Immutable dataclasses where practical.
- Follow the repo's commit style: small, frequent, conventional (`feat:`, `fix:`, `docs:`, `test:`), push after each coherent unit. Sign-off style: `git -c user.name="Alex Acosta" -c user.email="acoalex@gmail.com"`.
- Do NOT touch `haap/registry.py`, `haap/registry_client.py`, or existing tests except for genuine bugs (separate `fix:` commits with a clear message).
- Docs: `docs/DIRECTORY_SERVICE.md` (operator guide, English) covering architecture of your service, config, endpoints, backup/restore, monitoring, trust boundaries, and the deliberate deviations from this brief (if any).

## 10. Delivery report (return this structure)

1. Tree of created/modified files.
2. Design decisions and any deviations from this brief, with rationale.
3. Exact tail of the full pytest run (all suites, not just yours).
4. cURL transcript: one full registration with proof-of-endpoint against your running service + one search hit + one heartbeat.
5. Threat-model table filled with "how it is addressed" for each row.
6. Known limitations / future work.
