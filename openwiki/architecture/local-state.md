---
type: "Reference"
title: "Local State, Persistent Files and Data Entities"
openwiki_generated: true
verified:
  - by: openwiki/0.5.0
    at: 2026-09-05T09:02:08.883Z
sources:
  - id: openwiki-source-ea70eb6c045047448e446296
    resource: repo://.gitignore
  - id: openwiki-source-7592e1af420e65cc4a7cffee
    resource: repo://docs/DIRECTORY_SERVICE_BRIEF.md
  - id: openwiki-source-3891b016079c97e361524496
    resource: repo://haap/audit.py
  - id: openwiki-source-26aebf275d6f9be62c86d1a8
    resource: repo://haap/capabilities.py
  - id: openwiki-source-24adab58d3948e62a2292d51
    resource: repo://haap/cli.py
  - id: openwiki-source-035f85b3635abc9c77778ad7
    resource: repo://haap/client.py
  - id: openwiki-source-21604f9a956537b0c5c85892
    resource: repo://haap/crypto.py
  - id: openwiki-source-b70b0666af2653478c0a1cad
    resource: repo://haap/directory.py
  - id: openwiki-source-b358d1998165f4ed7fcb72c0
    resource: repo://haap/envelope.py
  - id: openwiki-source-c2dda71c01c0c3308f3e408d
    resource: repo://haap/identity.py
  - id: openwiki-source-88f21a0ad8695cc87203a86b
    resource: repo://haap/permissions.py
  - id: openwiki-source-aee5914f59c2fa73b1d3a884
    resource: repo://haap/policy.py
  - id: openwiki-source-57d7710b9339ab42912a55e1
    resource: repo://haap/rate_limiter.py
  - id: openwiki-source-1ad4db07f7e18c9ecc6c66cd
    resource: repo://haap/registry_client.py
  - id: openwiki-source-58440913f3ebe9f94657b458
    resource: repo://haap/registry.py
  - id: openwiki-source-b80cf839f4531575b216e5ec
    resource: repo://haap/roles.py
  - id: openwiki-source-f90b976a5addf17457a8a5be
    resource: repo://haap/server.py
  - id: openwiki-source-3f40c2d336660173700ea7f3
    resource: repo://haap/tasks.py
  - id: openwiki-source-2474212d3cebf96cd7d1f586
    resource: repo://tests/test_server.py
generated: { by: "openwiki/0.5.0", at: "2026-09-05T09:02:08.883Z" }
---


# Local State, Persistent Files and Data Entities

Every HAAP agent owns one directory of local state that records who it is
(`identity.json`), who it trusts and what they may do (`friends.json`),
the tasks it delegated or executed (`tasks.json`), an audit trail
(`audit.log`), and optional operator overrides (`roles.json`,
`policy.json`, `capabilities.json`). Runtime traffic state — token
buckets, anti-replay nonces, handshake challenges, and the federated
public directory — is deliberately **not** persisted. This page documents
that split, the schema and lifecycle of each stored entity, and the rules
(permissions, atomicity, secrecy) that keep the files safe.

## State root and how it is chosen

The default root is `$HAAP_DIR`, falling back to `~/.haap`:

```python
def haap_dir() -> str:
    return os.environ.get("HAAP_DIR", os.path.expanduser("~/.haap"))
```

Every store class (`IdentityStore`, `Directory`, `TaskRegistry`,
`AuditLog`) and the configuration loaders (`load_roles`, `load_policy`,
manifest export) accept an optional `directory` argument and fall back to
`haap_dir()` when it is `None`. The CLI exposes the same override as
`--dir` ("HAAP data directory (default $HAAP_DIR or ~/.haap)"), which is
resolved per command invocation. One directory holds exactly one agent's
state: creating a second identity in the same place is refused unless the
existing file is deleted or `overwrite=True`, so multi-agent hosts give
each agent its own subdirectory (the test suite does exactly this with
`tmp_path / "a"`, `tmp_path / "b"`, ...).

```mermaid
flowchart TD
    subgraph PERSIST["Persistent files under HAAP_DIR - survive restart"]
        direction TB
        ID["identity.json - Ed25519 keypair and metadata, mode 0600"]
        FR["friends.json - FriendRecord map with statuses and permission matrices"]
        TS["tasks.json - TaskRecord list with lifecycle state"]
        AU["audit.log - append-only JSON lines with rotation"]
        RO["roles.json - optional role overrides"]
        PO["policy.json - optional friend-request policy"]
        CA["capabilities.json - optional full manifest export"]
    end
    subgraph MEM["In-memory only - rebuilt on restart"]
        direction TB
        RD["RegistryStore - federated directory index and challenges"]
        RL["RateLimiter - per-friend token buckets"]
        NM["NonceManager - anti-replay cache"]
        CH["Pending handshake challenges"]
        AM["AuditLog and TaskRegistry when constructed with memory=True"]
    end
    PERSIST
    MEM
```

Caption: Durable per-agent files under `$HAAP_DIR` versus process-local stores that lose their contents on restart.

| File | Owner class | Content | Written when |
|---|---|---|---|
| `identity.json` | `IdentityStore` | Ed25519 keypair + metadata | `haap init`, explicit save |
| `friends.json` | `Directory` | `fingerprint -> FriendRecord` | every relationship mutation |
| `tasks.json` | `TaskRegistry` | list of `TaskRecord` | task create/update/progress (file mode only) |
| `audit.log` | `AuditLog` | one JSON event per line | every security-relevant decision |
| `roles.json` | `roles.load_roles` | role overrides over built-ins | optional, read at approval time |
| `policy.json` | `RequestPolicy` | deny/auto-approve rules | optional, read at server start |
| `capabilities.json` | `capabilities.export_manifest` | full manifest incl. skill introspection | optional, embedder export |

## identity.json

`IdentityStore` persists the agent's identity under
`<HAAP_DIR>/identity.json` in the versioned `haap-identity-v1` format: the
base64 Ed25519 key pair, `display_name`, `fingerprint`, `created_at` and
the public `endpoint` (`transport` + `url`). Writes are atomic
(`.tmp` file + `os.replace`) and the final file is `chmod`-ed to `0600`
(owner read/write only). `create()` generates a fresh `KeyPair` and
refuses to overwrite an existing identity unless `overwrite=True`;
`load()` raises `NotInitializedError` with a "Run first: haap init"
message when no file exists.

Loading validates the file defensively: an unknown `format` value and a
missing `private_key` raise `HAAPError`, and the stored `fingerprint`
must equal the fingerprint derived from the private key — a corrupt or
tampered file is rejected rather than silently accepted. The public
fingerprint itself is `"HF-"` plus the first 16 hex chars of
SHA-256(public key); cryptographic matching always uses the full key.

## friends.json — the friendship directory

`Directory` is the local friends registry and is **always file-backed** —
it has no in-memory mode. Construction loads `friends.json` (a JSON
object keyed by fingerprint) if present; if the file is absent the
registry starts empty. Every mutation (`upsert`, `remove`,
`register_known`, `add_pending_out`, `mark_outbound_accepted`, `approve`,
`deny`, `block`) saves the whole map back immediately via atomic
`.tmp` + `os.replace`, serialized by a per-instance `RLock`. In-process
locks are the only concurrency control; there is no cross-process locking
or file watching, so two agents must never share one directory.

Each `FriendRecord` stores the friend's fingerprint, display name,
relationship `status`, the friend's **public** key (needed to verify
signatures), messaging endpoints, `declared_capabilities`, the permission
matrix granted to that friend, per-action rate limits, timestamps and
notes. The status field follows the friendship state machine:

| Status | Meaning | Entered by |
|---|---|---|
| `pending_out` | I sent a request; awaiting `friend_accept` | `add_pending_out` |
| `pending_in` | I received a request; awaiting human approval | challenge completion (`register_known`) or `friend_request` |
| `accepted` | friendship established both ways | `approve` (human) or `mark_outbound_accepted` (peer accepted) or policy auto-approve |
| `blocked` | absolute deny-by-default | `block` |

`register_known` records a sender whose signature was already verified and
creates an implicit `pending_in` record if none existed, without changing
the status of an existing relationship. `approve` is the HUMAN decision on
`pending_in` and stamps the granted matrix; `deny` deletes the record;
`block` forces `status=blocked` and clears `permissions` to `{}` so a
blocked fingerprint can never act — the server rejects blocked senders
even on the friendship-less marketplace path.

### Permission matrices and rate limits live in the friend record

The authority for "what may friend X do against me" is
`FriendRecord.permissions`, an action-keyed map of
`{action: {"allow": bool, "scopes": [...]}}` persisted inside
`friends.json`. Semantics are deny-by-default: an absent action or
`allow: false` denies; scopes are glob patterns matched against the
requested `resource` (empty scopes or `["*"]` allow any resource).
Deliberately, an **explicit empty matrix** (`{}`) means "deny everything",
whereas a missing matrix (`None`) at `add_pending_out` time installs the
conservative `DEFAULT_GRANT_TEMPLATE` (chat:converse, task:delegate,
task:submit — never file/exec). Per-action `rate_limits` (token-bucket
capacity and refill) are stored on the record too; the shipped
`DEFAULT_RATE_LIMITS` catalog applies when a friend configures none.
`PermissionMatrix` is stateless evaluation logic — the matrix it checks
is always the serialized friend record.

`Directory.public_keys()` deliberately includes pending and blocked
records: any *known* sender can be verified (and then rejected with the
proper error), and the server augments the map with the agent's own key.
A signature from an entirely unknown fingerprint is a
`SignatureError`/`UNKNOWN_SENDER`.

## tasks.json — the task registry

`TaskRegistry` persists a JSON list of `TaskRecord`s to `tasks.json`
when constructed with a directory (`memory=False`, the default), and
stays purely in memory when constructed with `memory=True` (load and
save are skipped). A `TaskRecord` is keyed by `task_id` (`"T"` + short
uuid4 hex) and records `role`, the peer `friend_fingerprint`, `prompt`,
`action`/`resource` (for scope checks), lifecycle `state`, a free-form
`detail` dict and a `progress_log`. Only the last 20 progress entries are
serialized per record. Writes are atomic `.tmp` + `os.replace`, under a
reentrant lock, and every `create`/`update`/`progress` persists
immediately in file mode.

Records carry the side that owns them: HAAPClient mirrors tasks this
agent delegated with `role="delegate"`, while HAAPServer records tasks
this agent received and executes with `role="server"` — so one agent's
registry holds both halves of its task activity. State follows the A2A
lifecycle `submitted -> accepted -> working -> completed` with
`rejected`/`failed` as additional outcomes; `transition()` enforces the
valid-transition table (`completed`, `failed`, `rejected` are terminal)
and raises `TaskStateError` on illegal moves, so the persisted `state`
field is always authoritative.

## audit.log

`AuditLog` writes one JSON entry per line to `<HAAP_DIR>/audit.log`:
`{ts, event, friend, action, result, detail}`. Every security decision
(handshake, permission checks, rate-limit hits, tasks, marketplace)
leaves a trace. The module hard-redacts secrets before writing:
`challenge_token`, `private_key`, `signature` and `task_payload` are
always replaced with `"<redacted>"`, so log contents stay safe to share.
Appends are serialized under a lock; when the file reaches 5 MB it
rotates `audit.log -> audit.log.1 -> audit.log.2` and drops anything
older (rotation failures are swallowed — logging never breaks the
protocol). `recent()` re-reads the file per call, skips malformed lines,
and filters/sorts by timestamp. `memory=True` gives an in-memory variant
used by tests and as the server's fallback.

## Operator overrides: roles.json, policy.json, capabilities.json

**`roles.json`** optionally overrides the five built-in named roles
(`guest`, `client`, `partner`, `family`, `admin`), each a bundle of a
permission matrix + rate limits + optional TTL that the human owner
approves with one word instead of a hand-made matrix. A user role may
`extends` a built-in; invalid entries and a missing/corrupt file fall
back to the built-ins. `resolve_role` re-reads the file on every call, so
`roles.json` edits take effect at the next approval without a restart.

**`policy.json`** drives `RequestPolicy.evaluate`, applied to every
inbound `friend_request` in order: **deny** (policy default is deny and
no auto-rule matches), **auto-approve** (first rule matching fingerprint
or speciality — the granted role is capped by `max_role` on the ladder
guest < client < partner < family < admin; unknown/custom roles
auto-approve capped at `client`), else **queue** for a human decision
with an actionable notification card. Missing or corrupt `policy.json`
defaults to `{"default": "queue", "auto_approve": [], "max_role":
"partner"}`. Unlike roles, the policy is snapshotted when the server
constructs its `RequestPolicy` at startup, so editing `policy.json`
requires a restart of a running server to take effect.

**`capabilities.json`** holds an optional *full* manifest export
(`haap-capability-manifest-v1`, produced by `build_manifest` with
Hermes skill introspection that reads the `description`/`name`
frontmatter of SKILL.md files under `~/.hermes/skills` candidates). It is
written only when an embedder calls `export_manifest`; neither `haap
serve` nor `haap capabilities` writes it. The manifest actually served
to other agents (`GET /.well-known/haap.json`) is generated live by
`public_manifest` and contains only public identity + capabilities — no
keys. `parse_manifest` additionally refuses any inbound manifest that
carries `private_key`, `public_key` or `signature` fields (defense in
depth).

## Deliberately ephemeral state

Four kinds of state are process-local by design and vanish on restart:

- **`RegistryStore` (federated public directory)** — the agent directory
  keeps registered manifests, endpoint-proof challenges and last-seen
  timestamps **in memory only** (`dict`s plus a lock); it has no file
  store or persistence hook. Entries expire after `ENTRY_TTL_S` (24 h)
  without a heartbeat (lazy pruning on read), the index caps at
  `MAX_AGENTS` (10 000), and re-registration of the same fingerprint is
  an update. The repository's `RegistryServer` is the minimal reference
  implementation; the production-grade persistent (SQLite) directory
  service is developed separately and wire-compatible per
  `docs/DIRECTORY_SERVICE_BRIEF.md`.
- **`RateLimiter`** — per-`(friend, action)` token buckets live in
  process memory and are pruned lazily; rate-limit state never survives a
  restart (limits themselves come from the persisted friend records).
- **`NonceManager`** — the anti-replay set of seen `(sender, nonce)`
  pairs, TTL 660 s with a 100 000-entry cap.
- **Handshake challenges** — the server keeps pending
  hello→challenge-response state (`challenge`, issue time) in memory and
  rejects responses older than 120 s.

Relatedly, the server and client defaults push two otherwise-persistent
stores into memory: `HAAPServer` falls back to `AuditLog(memory=True)`
and `TaskRegistry(memory=True)` when none is injected, and `HAAPClient`
defaults to an in-memory task registry with no audit log. The shipped
`haap serve` CLI injects a file-backed `Directory` and file-backed
`AuditLog` but **not** a task registry, so tasks handled by a default
`haap serve` process are not written to `tasks.json`; `haap task list`
opens a file-backed registry from the same directory and therefore shows
records only when a caller actually injected and used a file-backed
`TaskRegistry`. Embedders that want durable task history must construct
`TaskRegistry(<dir>)` and pass it to `HAAPServer`/`HAAPClient`.

## Invariants, failure semantics and expiry

- **Atomic writes.** `identity.json`, `friends.json` and `tasks.json`
  are all written via `.tmp` + `os.replace`, so a crash mid-write cannot
  truncate a live store.
- **Corrupt-file behavior differs per store.** `IdentityStore.load`
  raises on a corrupt or inconsistent file (never silently accepts);
  `Directory` lets a `JSONDecodeError` propagate from a corrupt
  `friends.json`; `TaskRegistry` swallows unreadable/corrupt files and
  starts empty; `AuditLog` skips malformed lines; `roles.json`/
  `policy.json` fall back to built-ins/defaults. Operator expectations
  should match: friends data is fail-loud, caches and config are
  fail-soft.
- **What expires automatically.** The only TTL-driven pruning in shipped
  code is the registry entry TTL (24 h, renewed by heartbeat — the
  client's `HeartbeatLoop` default interval is 6 h), the 120 s handshake
  challenge window, and the 660 s nonce replay window. Pending friend
  requests and task records are stored indefinitely (policy.py declares
  `PENDING_TTL_DAYS = 7` but nothing enforces pruning of `pending_in`
  entries).
- **Secrecy.** The private key never leaves the machine: it never
  travels in envelopes, capability manifests, directory registrations or
  audit entries (redaction), inbound manifests carrying keys are
  rejected, `identity.json` is the only store chmod-0600, and the
  repository's `.gitignore` bans `identity.json`, `*.key`, `*.pem`,
  `.env`, `secrets/`, `friends.json` and `audit/` from ever being
  committed. Friends/audit files contain no private material (public keys
  and redacted logs only), but identity files are treated as secrets
  outright. Compromise of `identity.json` is handled as full key
  compromise: rotate = new identity + re-friendship (threat model T6 in
  `docs/ARQUITECTURA.md`).

## Related pages

- /openwiki/architecture/security-model.md
- /openwiki/concepts/identity.md
- /openwiki/concepts/permissions-and-roles.md
- /openwiki/concepts/rate-limiting-and-audit.md
- /openwiki/operations/cli-and-config.md
- /openwiki/operations/federated-directory.md
- /openwiki/workflows/task-delegation.md
