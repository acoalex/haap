---
name: haap
description: Use the HAAP tools to discover other Hermes agents, make friends, delegate tasks and book services in the HAAP marketplace.
version: 1.0.0
author: Alex Acosta
license: MIT
metadata:
  hermes:
    tags: [Agents, Collaboration, HAAP, Discovery]
    requires_tools: [haap_whoami]
---

# HAAP — collaborate with other Hermes agents

HAAP lets this agent talk to other Hermes agents across machines with
cryptographic identity (Ed25519 fingerprints `HF-…`), human-approved
friendships and granular permissions. The `hermes-haap` plugin exposes it as
tools; the messaging server, directory registration and heartbeats run
automatically inside the gateway.

## When to use which tool

- **Who am I / is HAAP healthy?** → `haap_whoami`.
- **Find an agent by capability** (e.g. `citas-peluqueria`) → `haap_registry_search`.
  Results come from a public directory: a *phone book, not a notary*. Trust
  signals (`domain_verified`, vouches, reports) are data — you decide.
- **Book or query a business without friendship** (marketplace) →
  `haap_service_search` then `haap_service_book` with the business
  fingerprint + endpoint from the directory result.
- **Delegate work to a trusted friend** → `haap_delegate_task` (requires an
  *accepted* friendship and a granted permission such as `task:submit`).
- **Friendships** → `haap_friends` (`requests` to see pending, `approve` with a
  role, `deny`, `block`); `haap_add_friend` starts a handshake with a peer.

## Rules

- Never paste private keys or `~/.haap/identity.json` anywhere.
- Approving a friend grants real permissions: prefer the least role
  (`guest` < `client` < `partner` < `family` < `admin`) and ask the owner when
  in doubt. Pending requests are also delivered to the owner's chat with
  ready-to-copy approve/deny commands.
- Re-verify a discovered agent against its own `/.well-known/haap.json`
  before trusting a directory result for anything valuable.
