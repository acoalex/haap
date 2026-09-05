---
type: "Overview"
title: "HAAP Code Wiki — Orientation and Routing Map"
description: "Entry point and routing map of the HAAP code wiki: what HAAP is (open pure-Python agent protocol, Python 3.10+, stdlib http.server, no web framework, Ed25519 identity), the alliance and marketplace trust modes, quick-start commands for identity, server, friends, directory and tests, and a goal-oriented map to every wiki page for architecture, protocol concepts, workflows, operations, integrations and testing."
tags: [HAAP, orientation, routing-map, quickstart, wiki-index, agent-protocol, hermes]
verified:
  - by: openwiki/0.5.0
    at: 2026-09-05T09:02:08.883Z
sources:
  - id: openwiki-source-8037e2358a2c4f9b2c722a11
    resource: repo://AGENTS.md
  - id: openwiki-source-7ec6126ec0a4381fcbae630d
    resource: repo://demo_marketplace.py
  - id: openwiki-source-a822c209c4991386625e995d
    resource: repo://docs/ARQUITECTURA.md
  - id: openwiki-source-7592e1af420e65cc4a7cffee
    resource: repo://docs/DIRECTORY_SERVICE_BRIEF.md
  - id: openwiki-source-c2dda71c01c0c3308f3e408d
    resource: repo://haap/identity.py
  - id: openwiki-source-f90b976a5addf17457a8a5be
    resource: repo://haap/server.py
  - id: openwiki-source-05ccef8d4cf1698187f20464
    resource: repo://pyproject.toml
  - id: openwiki-source-23775c3de52f3ab95a13cb8b
    resource: repo://README.md
generated: { by: "openwiki/0.5.0", at: "2026-09-05T09:02:08.883Z" }
---

# HAAP Code Wiki — Orientation and Routing Map

## What HAAP is

HAAP (Hermes Agent Alliance Protocol) is an open protocol and pure-Python
library that lets autonomous Hermes agents on different machines discover
each other, verify cryptographic identity, negotiate permissions, and
collaborate. It is packaged as the `haap` PyPI project (version 1.0.0, MIT):
it requires **Python >= 3.10**, its only runtime dependencies are
`cryptography>=41.0` and `requests>=2.28`, and it uses **no web framework** —
its HTTP surface is stdlib `http.server`. Installing the package provides the
`haap` console command (entry point `haap.cli:main`) and the importable `haap`
package whose modules mirror the components below.

Four sentences anchor the whole wiki:

- **Identity lives in keys.** Each agent is an Ed25519 key pair persisted at
  `$HAAP_DIR/identity.json` (default `~/.haap`, mode `0600`); the public
  identifier is the fingerprint `HF-` + first 16 hex characters of
  `SHA-256(public key)`, and the private key never leaves the machine — it
  never travels in envelopes, manifests or audit records.
  → [Agent Identity](concepts/identity.md)
- **Every interaction is a signed envelope.** Canonical JSON (sorted keys,
  compact, floats forbidden), a ±300 s clock window, per-sender nonces
  (anti-replay), and a signature over every field except itself, with stable
  error codes traveling in signed `error` envelopes.
  → [Signed Envelope Protocol and Anti-Replay](concepts/envelope-protocol.md)
- **Trust is deny-by-default.** Friends hold permission matrices with glob
  scopes (inbound and outbound), rate-limited per (friend, action), with an
  append-only audit of every accepted or rejected decision.
  → [Permissions Matrix, Scopes and Named Roles](concepts/permissions-and-roles.md)
  and [Abuse Controls: Token Buckets and Append-Only Audit](concepts/rate-limiting-and-audit.md)
- **The directory is a phone book, not a notary.** Agents register in a
  federated directory by proving endpoint control; trust is always re-verified
  agent-to-agent afterwards.
  → [Directory Registration and Discovery Workflow](workflows/directory-registration.md)

### Two trust modes

| Mode | Who | How trust starts | Where documented |
|---|---|---|---|
| **Alliance** | recurring peers (your VPSs, family, partners) | mutual friendship: challenge-response handshake plus the receiving owner's **human approval**, which grants a concrete permission matrix / role | [Alliance Friendship Handshake](workflows/friendship-handshake.md) |
| **Marketplace** | businesses publishing open bookable services | no prior friendship: any agent with a valid Ed25519 signature can `service_search` / `service_quote` / `service_book` / `service_cancel`, scoped by the business's own policy, audited, rate-limited, instantly blockable | [Marketplace Booking Workflow](workflows/marketplace-booking.md) |

## Quick start in five commands

```bash
pip install -e ".[dev]"                 # editable install; dev extra is pytest>=7.0
haap init --name "Agente Personal de Alex" --endpoint "https://tu-vps.com:8443/haap/messages"
haap whoami                             # shows fingerprint, name, endpoint
haap serve --port 8443 --speciality "asistente-personal"
pytest                                  # full offline suite (see testing/overview)
python3 demo_marketplace.py             # canonical working demo: two real agents over HTTP
```

The `haap serve` HTTP surface is three endpoints: `POST /haap/messages`
(signed envelopes in), `GET /.well-known/haap.json` (public manifest, no
keys), and `GET /health` (liveness). `demo_marketplace.py` boots a business
agent with a published `marketplace_catalog` and an `on_task` calendar backend
plus a personal agent, and completes the search-and-book flow end to end with
zero human intervention — the reference for the marketplace mode.

- All subcommands (`init`, `whoami`, `friends list/requests/approve/deny/remove/block/roles`,
  `capabilities`, `task`, `serve`, `registry serve/register/search`, `audit`),
  the `--dir` / `HAAP_DIR` overrides, and the systemd service example live on
  [CLI Commands and Runtime Configuration](operations/cli-and-config.md).
- Every file an agent persists — `identity.json`, `friends.json`, `tasks.json`,
  `audit.log`, `roles.json`, `policy.json`, `capabilities.json` — is documented
  on [Local State, Persistent Files and Data Entities](architecture/local-state.md).

## How this wiki is organized

| Domain | What it covers | Pages |
|---|---|---|
<!-- openwiki: broken internal link [architecture/overview.md] file "architecture/overview.md" does not exist. Fix the href or restore the target, then delete this comment. -->
| **Architecture** | component map of the whole system, threat model and hard invariants, persisted local state | [System Architecture and Component Map](architecture/overview.md), [Security Model, Threat Model and Hard Invariants](architecture/security-model.md), [Local State](architecture/local-state.md) |
| **Concepts** | the protocol primitives and their enforcement points | [Identity](concepts/identity.md), [Envelope Protocol](concepts/envelope-protocol.md), [Capability Manifests](concepts/manifests.md), [Permissions and Roles](concepts/permissions-and-roles.md), [Rate Limiting and Audit](concepts/rate-limiting-and-audit.md) |
| **Operations** | running and operating agents, the server, the client, and a directory | [CLI and Config](operations/cli-and-config.md), [Messaging Server](operations/messaging-server.md), [Client and Transports](operations/client-and-transports.md), [Federated Directory](operations/federated-directory.md) |
| **Workflows** | end-to-end flows between agents | [Friendship Handshake](workflows/friendship-handshake.md), [Task Delegation](workflows/task-delegation.md), [Marketplace Booking](workflows/marketplace-booking.md), [Directory Registration](workflows/directory-registration.md) |
| **Integrations** | wiring HAAP into a Hermes agent, well-known discovery, the A2A mapping, transport portability | [Hermes and A2A](integrations/hermes-and-a2a.md) |
| **Testing** | the 41-test pytest suite mapped to behaviors, fixtures, how to extend it | [Test Suite Map](testing/overview.md) |

## Route by goal

- **I want to understand the architecture in one read.** Start at
<!-- openwiki: broken internal link [architecture/overview.md] file "architecture/overview.md" does not exist. Fix the href or restore the target, then delete this comment. -->
  [System Architecture and Component Map](architecture/overview.md), then read
  [Security Model, Threat Model and Hard Invariants](architecture/security-model.md)
  (the T1–T10 threat table with its code mitigations) before touching code.
- **I must not break a security invariant while changing code.** The rules that
  can never be relaxed — canonical JSON without floats, ±300 s window +
  per-sender nonce, self-contained fingerprint↔key verification in bootstrap,
  deny-by-default scopes, mandatory human approval for friendships, append-only
  audit — are collected in [Security Model](architecture/security-model.md) and
  pinned down per-mechanism on the [Envelope Protocol](concepts/envelope-protocol.md)
  and [Permissions and Roles](concepts/permissions-and-roles.md) pages.
- **I want to add a new friend-flow message type.** See the message-type catalog
  on [Envelope Protocol](concepts/envelope-protocol.md), then the router
  dispatch, bootstrap sender-key resolution (`BOOTSTRAP_TYPES`) and per-type
  handlers on [Messaging Server](operations/messaging-server.md), and the state
  transitions you must keep consistent on [Friendship Handshake](workflows/friendship-handshake.md).
- **I want to change what an agent persists (or add a store).** Read
  [Local State](architecture/local-state.md) first: which entities are JSON
  files with which schemas and permissions, which state is deliberately
  in-memory, and the `HAAP_DIR` / `--dir` resolution rules.
- **I want to run an agent 24/7 or operate one.** [CLI and Runtime Configuration](operations/cli-and-config.md)
  for commands and human-editable `roles.json` / `policy.json` / `friends.json`,
  plus [Messaging Server](operations/messaging-server.md) for what the runtime
  actually does per message and [Local State](architecture/local-state.md) for
  what it writes.
- **I write code that talks outbound.** [Client Operations and Transport Layers](operations/client-and-transports.md):
  `HAAPClient` construction, the local permission/rate-limit guards that run
  before anything leaves the machine, and the `MemoryTransport` vs
  `HttpTransport` contract.
- **I need to approve or manage friendships.** CLI decision commands on
  [CLI and Runtime Configuration](operations/cli-and-config.md); the full
  handshake, request policy engine (deny / auto-approve capped by `max_role` /
  queue) and notifier cards on [Friendship Handshake](workflows/friendship-handshake.md).
- **I want to delegate or receive tasks.** [Task Delegation Workflow](workflows/task-delegation.md):
  authorization order (accepted friendship → action+scope permission → rate
  limit), the sync vs async execution paths, the `on_task` executor contract,
  and the A2A-style `TaskRegistry` state machine.
- **I want to publish a bookable service.** [Marketplace Booking Workflow](workflows/marketplace-booking.md),
  with `demo_marketplace.py` as the canonical running example.
- **I want to register an agent in (or run) a directory.** The agent side:
  [Directory Registration and Discovery Workflow](workflows/directory-registration.md)
  (challenge proof-of-endpoint, heartbeats, search). The operator side:
  [Federated Directory System](operations/federated-directory.md). The repo's
  registry is the reference implementation; the production public directory is
  the separate `acoalex/haap-directory` service the README points to.
- **I want to wire HAAP into my Hermes agent or follow A2A.** [Hermes and A2A](integrations/hermes-and-a2a.md):
  `HAAPServer` callbacks in a Hermes agent, HMAC-signed webhook notifications,
  skill introspection for manifests, the `/.well-known/haap.json` discovery
  pattern, and documented vs implemented transports.
- **I want to add or extend tests.** [Test Suite Map](testing/overview.md):
  the six pytest files, the two-agent fixture patterns (`handle_message`
  direct calls vs `MemoryTransport` client wiring vs loopback HTTP), and how to
  extend the suite for a new flow.

## Source of truth behind the wiki

The wiki is generated from the repository itself; when prose and code disagree,
code and tests win. The seed files each page derives from:

| Repo file | Role | Feeds |
|---|---|---|
| `AGENTS.md` | repo conventions for agents: what HAAP is, command summary, module map, the security rules that cannot be broken, key-handling prohibitions | [Security Model](architecture/security-model.md), [Local State](architecture/local-state.md), [Testing](testing/overview.md) |
| `README.md` / `README.en.md` | operator-facing usage: install, identity, friendship, policy/roles, marketplace, demo, component table (Spanish original; English translation) | [CLI and Config](operations/cli-and-config.md), all [Workflows](workflows/friendship-handshake.md) |
<!-- openwiki: broken internal link [architecture/overview.md] file "architecture/overview.md" does not exist. Fix the href or restore the target, then delete this comment. -->
| `docs/ARQUITECTURA.md` | protocol design document: principles, envelope format, handshake and task-authorization sequences, federated-directory governance, the T1–T10 threat model, A2A compatibility | [Architecture](architecture/overview.md), [Security Model](architecture/security-model.md), [Concepts](concepts/envelope-protocol.md) |
| `docs/DIRECTORY_SERVICE_BRIEF.md` | implementation brief for the production public directory (wire-compatible evolution of `haap/registry.py`) | [Federated Directory](operations/federated-directory.md) |
| `pyproject.toml` | package metadata, Python 3.10+ requirement, runtime/dev dependencies, `haap = haap.cli:main` console script | [CLI and Config](operations/cli-and-config.md), [Testing](testing/overview.md) |
| `haap/*.py` | the 19 modules implementing everything above | every page |
| `tests/` | six pytest files, the executable contract | [Testing](testing/overview.md) |
| `demo_marketplace.py` | canonical marketplace demo | [Marketplace Booking](workflows/marketplace-booking.md) |

Two conventions to keep in mind while reading: the repository's own docs,
README and docstrings are written in Spanish while code identifiers are in
English (this wiki is in English and keeps identifiers, file paths, commands
and error codes unchanged); and `identity.json` / `*.key` / `*.pem` / `.env`
material is **never** committed or shared — treat it as untouchable in every
page of this wiki.
