# Trust Firewall

Stateless identity and graded corpus reachability for **MCP 2026-07-28**.

```python
from trustfirewall import TrustFirewall, ServerClass, mint

fw = TrustFirewall(posture="enforce"); fw.load_lattice()
fw.classify("partner.acme.example", ServerClass.CONTRACTED)

cred = mint(key, agent_id=42001, chain_id=8453, footprint=fp, tier="A2xH2",
            mcp_method="tools/call", mcp_name="search", body=body, ttl_seconds=60)

d = fw.decide(headers, body, server_host="partner.acme.example")
d.allowed, d.binding, d.settlement, d.obligations.to_dict()
```

## What changed and why it matters

MCP 2026-07-28 removed protocol sessions — no `initialize`, no
`Mcp-Session-Id`. XCP replaces the session with a **per-request credential
bound to the call**:

```
session id  →  a pointer to server-side state       (needs stickiness)
credential  →  the state, signed and self-verifying (needs nothing)
```

A stolen session id was a bearer token for everything that session could do. A
stolen credential is bound to one method, one tool, one argument digest and a
seconds-long expiry — replay it against a different tool and the binding fails.

The same release made `Mcp-Method` and `Mcp-Name` mandatory, which map directly
onto XCP's scope grammar, so authorization is decided **from headers, without
parsing the body**.

## Graded reachability

| caller | unknown | probed | attested | contracted |
|---|---|---|---|---|
| **A2 company** | observe (read) | allow · escrow | allow · metered | allow · full |
| **A1 registry** | observe (read) | allow · escrow | allow · metered | allow · metered |
| **A0 free** | observe (read) | read only | read only | read only |

Unvetted servers are **reachable, not blocked** — observe mode, read-only,
sandboxed, output quarantined. Nothing binding happens against a server nobody
has vetted, and money never moves toward an unattested counterparty.

`corpus_matrix()` returns the full 3 × 4 × 2 table for operator review.

## Not competing with your WAF

Any API gateway can now route and meter per tool from those two headers. That is
commodity. This adds what a WAF structurally cannot: binding the call to a
verified agent identity, checking it against a signed mandate, grading it by the
counterparty's trust class, and carrying a spend ceiling and receipt obligation
into settlement.

Full docs: [docs/trust-firewall.md](../docs/trust-firewall.md) ·
demo: `python examples/trust_firewall.py`
