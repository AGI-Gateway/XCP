# Trust Lattice

Agent identity tier × human identity tier → one mandate template.

```python
from trust.tiers import AgentTier, HumanTier, Entitlements, resolve, session_binding

tpl = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE)
tpl.cell            # "A2xH2"
tpl.scopes          # granted scope patterns
tpl.rails_list()    # ["X402", "AP2", "MPP", "ACP"]
tpl.ttl_seconds     # 604800 (7d — the protocol cap)

# entitlements from an enterprise IdP can only NARROW
resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE,
        Entitlements(approval_limit_minor=50_000, denied_scopes=["pay:*"]))

# render straight into an XCP session binding
session_binding(AgentTier.REGISTRY, HumanTier.ENTERPRISE, footprint="0x…", agent_id=42001)
```

## The tiers

**Agent** — what stands behind the agent:
`FREE` self-asserted keypair · `REGISTRY` ERC-8004 identity + reputation ·
`COMPANY` a legal entity signs the mandate root.

**Human** — what stands behind the person:
`PUBLIC` anonymous · `GENERAL_SSO` consumer IdP · `ENTERPRISE` employer IdP with
entitlement attributes.

## Invariants (tested)

- The ceiling is the **weaker leg** — `A0×H2` is observe-mode, audit-only.
- **Exception:** `A2×H0` isn't capped, because the company is the principal.
- Entitlements **narrow only**; they can never grant a scope the tier lacks.
- No cell exceeds the 7-day protocol cap on session bindings.
- An approval limit of 0 disables settlement entirely.

`./xcp tier --table` prints the whole lattice.
