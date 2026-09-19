---
title: XCP
---

# XCP

**A trust layer for agents that call tools and agents they don't own.**

Agents can find each other now. They still can't trust each other. Discovery
standards tell an agent *where* a capability lives and verify a domain once,
when a catalog is published. XCP verifies **the call happening right now** — who
the agent is, whose authority it carries, what it may reach, and what it may spend.

```bash
git clone https://github.com/AGI-Gateway/XCP && cd XCP
make install && make demo
```

!!! tip "Open infrastructure — extend it freely"
    Every software organisation can plug in their own **MCP connection** or
    **foundational inference model** with no allowlist, no vendor keys and no
    approval step. MIT licensed, including the specification. Maintained
    anonymously so no single vendor controls it.
    See [Providers](providers.md).

!!! note "Built for stateless MCP"
    Targets the **MCP 2026-07-28** specification, which removed protocol
    sessions. XCP replaces the session with a per-request, call-bound credential
    and decides authorization from the mandatory `Mcp-Method` / `Mcp-Name`
    headers — no body parsing, no sticky routing.
    See [Trust Firewall](trust-firewall.md).

## Start here

<div class="grid cards" markdown>

- :material-rocket-launch: **[Self-serve guide](self-serve.md)** — run it, position it, publish it. No sales call.
- :material-shield-lock: **[Trust lattice](trust-lattice.md)** — agent tier × human tier → one mandate template.
- :material-firewall: **[Trust Firewall](trust-firewall.md)** — consume 20k+ MCP servers on graded terms.
- :material-receipt: **[Receipts](receipts.md)** — settlement conditioned on verifiable delivery.

</div>

## What it does

| | |
|---|---|
| **Stateless identity** | A per-request credential bound to one method, one tool, one argument digest, one short expiry. Worth less to steal than a session id. |
| **Header-speed decisions** | Authorization from `Mcp-Method` + `Mcp-Name`, without opening the body. |
| **Graded reachability** | The whole corpus stays reachable; the terms vary by what backs the caller and what backs the server. |
| **Per-call governance** | Merkle proof + EIP-712 + scope coverage. Revocable in about one block. |
| **Proof-of-delivery** | Escrow releases on evidence a third party can re-check offline. |
| **Defence in depth** | Optional `xcpsec`: hardened mTLS, argument firewall, execution sandbox, supply-chain pinning, prompt-injection boundaries. |

<div class="xcp-footprint">0x<b>7b3f9a2c1e8d4f60</b>a5b2e1c9d8f7a6b504e19c7d2a8b3f10<i>9d4a2d9c</i>feedface00112233<s>445566</s>778899aabbccddeeff0011223344556677</div>

## Status

!!! warning "Read this before you build on it"
    **XCP and the ERC-8004x Session Registry are draft proposals originated in
    this project.** MCP, A2A, ERC-8004 and the OWASP taxonomies are independent
    work by others, and we don't claim otherwise.

    - The code works and is tested; the enforcement path has no stubs.
    - It has **not** had an independent security audit.
    - ARD support targets a draft whose industry adoption was near zero at the
      time of writing.
    - The optional security library **reduces and contains** its threat classes;
      it does not eliminate them.

MIT — including the specification.
