# Self-Serve Guide

Everything here you can do yourself, without contacting anyone. That's the point:
a trust layer that requires a sales call isn't infrastructure.

Three stages, each independently useful:

1. **Run it** — stand up a verified gateway in front of your tools.
2. **Position it** — pick your trust tier and understand what it grants.
3. **Publish it** — become discoverable to agents that have never heard of you.

---

## 1. Run it

```bash
git clone https://github.com/AGI-Gateway/XCP && cd XCP
make install
make demo          # no config needed — spins up the whole stack and drives it
```

The demo prints a session opening, a granted call succeeding, and out-of-scope
calls being **denied**. Those denials are the product working.

Point it at your own MCP server:

```bash
./xcp init --name my-tools --domain acme.example --org "Acme Corp"
# edit xcp.toml → [gateway].upstreams = { research = "http://localhost:9001/mcp" }
./xcp doctor       # checks environment, config and your tier
./xcp up           # or: make up   (docker compose)
```

Your agents now reach tools through a gateway that verifies the session and gates
every call against a mandate. The tools themselves are unchanged.

### Real certificates

```bash
./xcp certs --agent-id 42001     # local dev PKI — NEVER use in production
```

For production, issue certificates from your own CA and set `cert_path`,
`key_path` and `ca_path` on the client. The certificate footprint
`keccak256(DER(cert))` is what binds the session to an identity.

---

## 2. Position it — the trust lattice

Your authority is a function of **what backs the agent** and **what backs the
human behind it**. Nine cells, one deterministic envelope each.

```bash
./xcp tier --table                                  # the whole lattice
./xcp tier                                          # your envelope, from xcp.toml
./xcp tier --agent company --human enterprise       # explore a cell
./xcp tier --agent company --human enterprise --limit 50000   # with an entitlement
```

| | H0 Public | H1 General SSO | H2 Enterprise SSO |
|---|---|---|---|
| **A2 Company** | Service agent | Professional | **Full settlement** |
| **A1 Registry** | Open marketplace | Consumer commerce | Delegated corporate |
| **A0 Free** | Sandbox | Metered | Shadowed |

**The rule:** the ceiling is the weaker leg. A corporate human can't lift an
unbacked agent — `A0×H2` ("Shadowed") is observe-mode and audit-only.

**One exception:** `A2×H0` is *not* capped by the missing human, because a
company-backed autonomous agent has the company as its principal. Without that,
the lattice would forbid unattended service agents, which is the most common
enterprise case.

### Climbing

```bash
./xcp tier            # prints the concrete next step for your position
```

- **A0 → A1**: register the agent in the ERC-8004 identity registry and publish
  an ARD catalog entry.
- **A1 → A2**: have a legal entity sign the agent's mandate root.
- **H0 → H1**: add a consumer SSO login so a verified human principal exists.
- **H1 → H2**: connect your enterprise IdP and map entitlement attributes.

### Entitlements narrow, never widen

When the human tier is `ENTERPRISE`, attributes from your IdP (groups, cost
centre, approval limit) further restrict the envelope. This is enforced, not
advisory: an entitlement **cannot** grant a scope the tier doesn't already have.

```python
from trust.tiers import AgentTier, HumanTier, Entitlements, resolve

tpl = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE,
              Entitlements(approval_limit_minor=50_000, denied_scopes=["pay:*"]))
```

### Wiring it into the gateway

```python
from trust.tiers import session_binding, AgentTier, HumanTier

binding = session_binding(AgentTier.REGISTRY, HumanTier.ENTERPRISE,
                          footprint="0x…", agent_id=42001)
# → agentId, certFootprint, railsBitmap, ttlSeconds, posture, scopes, spendCapMinor
```

Those are exactly the fields an XCP Session Registry binding carries, so the tier
system plugs into the existing gateway without protocol changes.

---

## 3. Publish it — become discoverable

Agents can't call what they can't find. Publishing feeds two pipes at once:

- **`/.well-known/ai-catalog.json`** → the ARD crawl path (registries index it)
- **`server-<name>.json`** → the MCP Registry install path

```bash
./xcp publish --introspect        # --introspect calls tools/list to enrich the catalog
```

Output lands in `dist/`. Host the catalog at
`https://<your-domain>/.well-known/ai-catalog.json` and submit the manifest to
the MCP Registry.

### Why `--introspect` matters

Most publishers write thin descriptions and rank badly. `--introspect` reads your
actual tool surface and derives natural-language **representative queries** — the
signal registries match against:

```
tools: echo, sum, now
→ "echo the provided text back", "sum by numbers", "return the current server time"
```

### The XCP difference in the catalog

Entries carry trust metadata alongside the endpoint:

```json
"trust": {
  "auth": "xcp-mtls",
  "xcpTrustTier": "A2xH2",
  "xcpGateway": "https://gw.acme.example",
  "verifiedAtConnect": true
}
```

ARD anchors identity to **domain ownership at publish time**. That's a real
signal, but it says nothing about the session connecting right now. `xcpGateway`
tells a discovering agent this endpoint is fronted by live session verification —
found *and* verifiable.

### Before you trust someone else's endpoint

```bash
./xcp verify https://someone-elses-gateway.example
```

Probes health, checks whether anonymous calls are refused, and reports whether
they publish an ARD catalog.

---

## Hardening for production

- Run `enforce` posture. `observe` is for onboarding an endpoint you haven't
  vetted, not a steady state.
- `XCP_SECURITY=1` enables the argument firewall (command injection, SSRF).
- Use `xcpsec.sandbox` for any tool that executes untrusted input.
- Keep TTLs short — the protocol caps session bindings at 7 days.
- Serve `/.well-known/*` unauthenticated (RFC 8615); gate everything else.
- Watch `mandate_denials_total` and `session_verifications_total{result}`.

See [security.md](security.md) for the threat model, including what XCP does
**not** address.

---

## Honest status

- **XCP and ERC-8004x are draft proposals originated in this project.** MCP, A2A,
  ERC-8004 and the OWASP taxonomies are independent work by others.
- **ARD support targets the v0.9 draft.** Adoption of ARD across the industry was
  near zero at the time of writing — publishing a catalog is a cheap option on a
  well-backed spec, not a proven traffic channel. Validate against the published
  schema before relying on it.
- **This code has not been independently audited.**
