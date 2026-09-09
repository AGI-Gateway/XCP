# XCP

**A trust layer for agents that call tools and agents they don't own.**

Agents can find each other now. They still can't trust each other. Discovery
standards tell an agent *where* a capability lives and verify a domain once, when
a catalog is published. XCP verifies **the session connecting right now** — who
the agent is, whose authority it carries, and what it may spend.

**Open infrastructure, MIT licensed.** Every software organisation can plug in
their own MCP connection or foundational inference model, freely — no allowlist,
no vendor keys, no approval step, no commercial relationship. Run it yourself,
fork it, embed it in closed software. Maintained anonymously so no single vendor
controls it.

```bash
git clone https://github.com/AGI-Gateway/XCP && cd XCP
make install && make demo
```

```
session opened   agent=42001 footprint=0xd3832e3d18dbb6… rails=3
A2T echo         OK  served_for=42001 verified_by=gw-local
A2T sum          DENIED (out of scope) ✓
A2A delegate     OK  accepted=True peer=did:8004:8453:0xPEER
T2T chain        OK  research.fetch -> summarize.run
```

The denials are the product working.

---

## What you get

| | |
|---|---|
| **Stateless identity** | Targets **MCP 2026-07-28**, which removed protocol sessions. A per-request credential bound to one method, one tool, one argument digest and a seconds-long expiry replaces `Mcp-Session-Id` — worth less to steal than a session id. |
| **Trust Firewall** | Authorization decided from the mandatory `Mcp-Method` / `Mcp-Name` headers, without parsing the body. The whole 20k+ corpus stays reachable; the *terms* vary by what backs the caller and what backs the server. |
| **Proof-of-delivery** | Escrow releases on evidence — task commitment, tamper-evident call chain, signed receipt — that a third party can re-verify offline. |
| **A trust lattice** | Agent tier × human tier → one mandate template. Free agents enter at the bottom and climb; enterprises land at the top. |
| **Per-call governance** | Every action gated by a signed mandate: Merkle proof + EIP-712 + scope coverage. Revocable in about one block. |
| **Discovery on-ramp** | One command generates your ARD catalog *and* MCP Registry manifest, with representative queries derived from your real tool surface. |
| **Defence in depth** | Optional `xcpsec`: hardened mTLS, argument firewall, execution sandbox, supply-chain pinning, prompt-injection boundaries. |
| **Wraps, never replaces** | Point it at MCP servers you already run. They don't change. |

---

## Run a node — the Agentic Internet

A single gateway is useful. A **web of independently-operated gateways that
verify each other directly** is an agentic internet: anyone can join without
permission, and nobody can be de-listed.

```python
from federation import Federation, build_node_record, verify_node_record

rec = build_node_record(domain="node.example.org", cert_pem=cert,
                        gateway_url="https://node.example.org")
# serve at /.well-known/xcp-node.json — that plus your TLS cert IS your identity
```

A peer verifies you with three local checks and **no third party**: the record is
well-formed, it was served from the domain it claims, and its `node_id` matches
the certificate the TLS handshake presented. Trust then travels transitively,
**decaying by hop and capped at 3**, so one compromised node can't launder trust.
Revocation spreads by gossip, backstopped by seconds-long credential TTLs.

**No registry, no chain, no vendor, no consensus.** Chain anchoring is optional
and off by default. What you *do* still depend on — DNS and certificate
authorities — is stated plainly in
[docs/agentic-internet.md](docs/agentic-internet.md), along with the honest
limits: the network doesn't exist yet, and bootstrap is a real unsolved problem.

## The catalog — 7,048 MCP servers, classified

```bash
xcp catalog --categories                          # every category, with counts
xcp catalog --category dev-tools --kind routable  # only what you can reach today
xcp catalog --search stripe
```

Navigate on **two axes**, and you need both:

| axis | values | why it matters |
|---|---|---|
| **kind** | `routable` (158) · `installable` (6,890) | Most MCP servers are local packages, not endpoints. You cannot route traffic to something nobody is running. |
| **verification** | `confirmed` · `community` · `unconfirmed` · `self_hosted` | Caps how far an entry can be promoted. Harvested entries land at `unconfirmed`/`unknown` — observe-only, sandboxed, nothing binding. |

Twenty categories derived from the corpus itself, largest first:

| | | | |
|---|---|---|---|
| `dev-tools` 1,025 | `finance-payments` 560 | `security` 364 | `ai-agents` 339 |
| `data-stores` 289 | `cloud-infra` 249 | `observability` 179 | `browsing-scraping` 166 |
| `knowledge-memory` 148 | `media-design` 128 | `search-web` 120 | `communication` 109 |
| `location-weather` 105 | `productivity` 102 | `crm-sales` 59 | `science-research` 42 |
| `gaming` 33 | `iot-hardware` 28 | `ecommerce` 13 | `other` 590 |

**Category tells you what a server claims to do. Only verification tells you
whether to believe it.** Full breakdown: [`connectors/README.md`](connectors/README.md).

## Extend it — this is the part you're meant to change

Two open registries. No gatekeeper, no allowlist, validation is the only gate.

```python
from providers import MCPConnection, register_connection, ModelProvider, ToolCallStyle, register_model

# any MCP server, anywhere
register_connection(MCPConnection(
    id="acme-research", name="Acme Research Tools",
    endpoint="https://mcp.acme.example/mcp"))

# any foundational inference model
register_model(ModelProvider(
    id="acme-llm-1", name="Acme LLM 1",
    tool_call_style=ToolCallStyle.OPENAI_TOOLS,
    self_hostable=True, open_weights=True))
```

New servers start at `unknown` — **reachable, not blocked**. XCP never calls your
model; it only needs to know how the model *expresses* a tool call, which is why
adding one changes nothing in the core. `NATIVE_MCP`, `OPENAI_TOOLS`,
`ANTHROPIC`, `JSON_SCHEMA`, `TEXT_DSL` and `CUSTOM` all normalise to the same
shape. **"Multi-Model" is a commitment, not branding** — the reference entries
are vendor-neutral and one is a self-hosted, open-weights path. XCP never phones
home.

See [`providers/README.md`](providers/README.md).

## The trust lattice

Authority is a function of what backs the **agent** and what backs the **human**
behind it — not a single flag.

| | H0 Public | H1 General SSO | H2 Enterprise SSO |
|---|---|---|---|
| **A2 Company** | Service agent | Professional | **Full settlement** |
| **A1 Registry** | Open marketplace | Consumer commerce | Delegated corporate |
| **A0 Free** | Sandbox | Metered | Shadowed |

```bash
./xcp tier --table                              # see all nine cells
./xcp tier --agent company --human enterprise   # what that grants
```

The ceiling is the weaker leg — a corporate human can't lift an unbacked agent.
One deliberate exception: `A2×H0` isn't capped by the missing human, because a
company-backed autonomous agent has the company as its principal.

Entitlement attributes from an enterprise IdP **narrow** the envelope further and
can never widen it. That invariant is enforced and tested.

---

## Self-serve in three commands

```bash
./xcp init --domain acme.example --org "Acme Corp"   # scaffold xcp.toml
./xcp doctor                                          # check env, config, tier
./xcp publish --introspect                            # become discoverable
```

Full walkthrough: **[docs/self-serve.md](docs/self-serve.md)**

Other commands: `xcp up` (run the stack), `xcp certs` (local dev PKI),
`xcp verify <url>` (probe someone else's endpoint before trusting it).

---

## Repository layout

```
xcp/
├── xcp                     the self-serve CLI entry point
├── cli/xcp/                CLI implementation
├── trust/                  the trust lattice — tiers → mandate templates
├── federation/             peer-to-peer node trust — the agentic internet
├── connectors/             one MCP endpoint definition per external SaaS
├── vault/                  secret *references* + SSO identity providers
├── providers/              open registries: add an MCP connection or a model
├── trustfirewall/          stateless MCP credentials + graded corpus reachability
├── receipts/               proof-of-delivery and evidence-conditioned escrow
├── discovery/              ARD catalog + MCP Registry manifest generation
├── core/
│   ├── client/             Python · Go · Java · browser
│   ├── gateway/            verify session → gate mandate → route
│   ├── server/             XCP-aware MCP server
│   ├── verifier/           Merkle + EIP-712 + scope, in-memory or on-chain
│   ├── contracts/          ERC-8004x SessionRegistry.sol
│   └── proto/              A2T / A2A / T2T gRPC contract
├── security/xcpsec/        optional defence-in-depth library
├── deploy/                 certs, docker-compose, helm
├── examples/ tests/ docs/
```

---

## How a request flows

```
 client ──① open session (mTLS)──▶ gateway ──binds footprint──▶ Session Registry
        ──② call + mandate proof──▶ gateway
                                     │ ③ verifySession(footprint)
                                     │ ④ mandate gate (Merkle + EIP-712 + scope)
                                     ▼
                              upstream MCP server  ◀── verified identity forwarded
```

The gateway holds no keys and no funds. It is a verifier and a router, not a
custodian — and we intend to keep that property.

---

## Testing

```bash
make test     # core protocol · self-serve layer · security library · sandbox
make lint
```

CI runs all of it plus a proto compile, a Go vet, and the on-chain verifier path
against an in-process EVM.

---

## Documentation

- **Docs site**: https://agi-gateway.github.io/XCP/
- [SaaS connectors](docs/connectors.md) — one MCP endpoint per service
- [Vault & authentication](docs/vault.md) — OAuth, OIDC, SAML, JWT, mTLS; SSO providers
- [Run a node](docs/agentic-internet.md) — federate without central dependencies
- [Self-serve guide](docs/self-serve.md) — run, position, publish
- [Trust Firewall](docs/trust-firewall.md) — stateless MCP, graded corpus reachability
- [Receipts & settlement](docs/receipts.md) — proof-of-delivery
- [Architecture](docs/architecture.md) — planes, session model, trust boundaries
- [Protocol](docs/protocol.md) — headers, scopes, session + mandate flow
- [Security](docs/security.md) — threat model, and what XCP does *not* solve
- [`xcpsec`](security/README.md) — the optional hardening library

---

## Contributing

Maintained **anonymously** — contributions default to anonymous attribution and
you're welcome to leave them that way. Adding a provider needs no approval at
all; it's validated, not judged.

- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup and PR checklist
- [GOVERNANCE.md](GOVERNANCE.md) — how decisions get made; protocol changes need
  an RFC issue, a 7-day comment period, and maintainer consensus
- [ROADMAP.md](ROADMAP.md) — items two or more adopters need get pulled forward
- [SECURITY.md](SECURITY.md) — report vulnerabilities to GitHub private security advisories, not
  as public issues

---

## Status — read this before you build on it

**XCP and the ERC-8004x Session Registry are draft proposals originated in this
project.** MCP, A2A, ERC-8004 and the OWASP taxonomies are independent, real work
by others, and we don't claim otherwise.

- The code works and is tested; the enforcement path has no stubs.
- It has **not** had an independent security audit.
- ARD support targets a **v0.9 draft** whose industry adoption was near zero at
  the time of writing. Publishing a catalog is a cheap option on a well-backed
  spec — not a proven traffic channel.
- The optional security library **reduces and contains** its threat classes; it
  does not eliminate them. [docs/security.md](docs/security.md) is explicit about
  where the limits are.

If that honesty is inconvenient, it's still better than finding out later.

## License

MIT — and it covers the protocol specification, message formats and data schemas
as well as the code. Implement, extend or embed them freely, in open or closed
software, with no royalty and no obligation to contribute back. See
[NOTICE.md](NOTICE.md) for scope and for the independent work referenced here. Copyright is held by "Anonymous
Contributors"; see [GOVERNANCE.md](GOVERNANCE.md#anonymous-by-design) for what
anonymity trades away.