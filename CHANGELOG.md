# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/). This project uses
semantic versioning once it reaches 1.0. Until then, minor versions may break.

> **Note on history.** The git log was squashed to a single commit for a clean
> public record. This file is the record of what that history contained; the
> commit log no longer is.

## [Unreleased]

First public release. Everything below is new.

### Second implementation

- **Node gateway** (`core/gateway-ts/`) written against the specification rather
  than ported from Python. **Passes the conformance suite 15/15**, which is the
  first evidence that the spec is implementable from the document and that the
  suite is a specification instrument rather than a regression test. CI runs it
  on every push.

### Delegation chains

- Sealed credentials can now be passed onward up to a budget the **originator**
  sets and no hop can raise. The chain is bound into the AAD, so a hop cannot
  rewrite the recorded path; loops are refused; and a recipient applies its own
  policy to which hops it accepts.
- Stated rather than overclaimed: re-sealing requires the intermediate hop to
  hold plaintext momentarily. The chain adds **accountability**, not secrecy
  from intermediaries. For secrecy from a hop, seal directly to the recipient.

### Security audit

Self-audit of the published tree before release: six findings, two critical, all
fixed with attack-reproducing tests. See [SECURITY-AUDIT.md](SECURITY-AUDIT.md).

- **Administrative authentication.** `/admin/revoke` previously had none — one
  unauthenticated request revoked any session. Now requires `XCP_ADMIN_TOKEN`,
  compared in constant time, and is **disabled** when unset rather than open.
- **Signed revocation.** The gossip endpoint took the originating peer's domain
  from the request body. With the peer list also public, anyone could name a real
  peer and revoke any node. Revocations now carry an EIP-712 signature from the
  issuing node's key and expire after an hour so one cannot be replayed.
- **Egress control** (`security/xcpsec/egress.py`). The peer-record fetch
  accepted a caller-supplied URL with TLS verification disabled — server-side
  request forgery reaching internal services, with the error echoed back as an
  oracle. Validation now happens on the **resolved address**, redirects are
  refused, responses are capped, and errors are generic.
- **Topology redacted** behind the admin token, consistent with a privacy design
  that already keeps counterparties out of what it publishes.
- **Federation gets its own rate budget.** Metering it under the anonymous
  bucket — sized for hostile traffic at roughly four calls a minute — would have
  made a real federation throttle itself, since peering is unauthenticated by
  necessity.

### Core protocol

- **Clients** in Python, Go, Java and the browser, sharing one interface, so any
  client works against any gateway.
- **Gateway** — the trust boundary. Verifies the caller, gates every action
  against a signed mandate, and routes to upstream MCP servers. Holds no keys and
  no funds: a verifier and router, never a custodian.
- **MCP server** — an XCP-aware reference server that trusts only
  gateway-verified identity.
- **Verifier** — real Merkle inclusion, EIP-712 recovery and scope coverage,
  running either in memory or against an on-chain registry.
- **ERC-8004x Session Registry** — Solidity contract plus an in-process EVM test
  for the read path.
- **A2T / A2A / T2T** gRPC contract for agent→tool, agent↔agent and tool↔tool
  streams.

### Stateless identity (MCP 2026-07-28)

- Targets the MCP revision that removed protocol sessions. Identity is a
  **per-request credential** bound to one method, one tool, one argument digest,
  one certificate footprint and a seconds-long expiry — replacing a session id
  with something worth far less to steal.
- Authorization is decided from the mandatory `Mcp-Method` and `Mcp-Name`
  headers **without parsing the body**, so it runs at edge speed.
- MRTR flows link multi-round-trip calls into one logical call. Stale headers and
  deprecated methods surface as warnings, not failures.

### Trust Firewall

- **Graded corpus reachability**: caller tier × server trust class
  (`unknown` → `probed` → `attested` → `contracted`) yields an effect, a
  settlement mode, and inherited obligations (sandbox, quarantine, receipt).
- Unvetted servers stay **reachable in observe mode** rather than blocked;
  nothing binding happens against them, and money never moves toward an
  unattested counterparty.

### Trust lattice

- Agent tier × human tier resolves to one **mandate template**: scopes, payment
  rails, session TTL and spend cap.
- Entitlements from an enterprise IdP **narrow and never widen**. The ceiling is
  the weaker leg, with one deliberate exception where a company-backed autonomous
  agent has the company as its principal.

### Receipts and settlement

- **Proof-of-delivery**: a task commitment, a tamper-evident call chain, and an
  EIP-712 signed receipt.
- An escrow state machine that releases only on verified evidence or an arbiter
  ruling. Auto-accept is off by default.
- `xcp receipt <bundle>` verifies an evidence bundle offline.

### Federation

- A web of independently-operated nodes with **no central authority**. A node
  proves itself with a domain and a TLS certificate published at
  `/.well-known/xcp-node.json`; peers verify it locally, consulting no third
  party.
- Transitive trust **decays per hop and is capped**, so a compromised node cannot
  launder full trust.
- Revocation spreads by gossip from trusted peers only, backstopped by
  seconds-long credential TTLs. Chain anchoring is optional and off by default.
  Nodes may disagree; no consensus is required.

### Open extension points

- Two ungated registries: any **MCP connection** and any **foundational
  inference model**. No allowlist, no vendor keys, no approval step — validation
  is the only gate, and provider additions are explicitly exempt from maintainer
  review.
- Six tool-call styles normalise to one `(tool, arguments)` shape, so adding a
  model requires no core change.

### Discovery

- Generates an ARD `ai-catalog.json` and an MCP Registry manifest from one
  config, with representative queries derived from the live tool surface.

### Security

- Optional `xcpsec` library: hardened mTLS with certificate pinning, an argument
  firewall, an execution sandbox with resource limits and network isolation,
  supply-chain manifest pinning, and prompt-injection content boundaries.

### Self-serve

- `xcp` CLI: `init`, `doctor`, `tier`, `certs`, `up`, `publish`, `verify`,
  `receipt`.
- Docker Compose and a Helm chart with safe defaults; docs site published to
  GitHub Pages.

### Notes

- XCP and the ERC-8004x Session Registry are **draft proposals originated in this
  project**. MCP, A2A, ERC-8004, ARD and the OWASP taxonomies are independent
  work by others.
- ARD support targets a draft specification and will change when it stabilises.
- This code has **not** had an independent security audit.
