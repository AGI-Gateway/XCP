# Second gateway — Node

An independent XCP gateway written against `docs/protocol.md` and the
conformance clauses, **not** by porting the Python source.

```bash
XCP_UPSTREAMS='{"research":"https://your-mcp/mcp"}' node core/gateway-ts/gateway.mjs
xcp conform http://127.0.0.1:8080
```

## Why it exists

The conformance suite was built to certify independent implementations and had
never faced one. A suite that only ever runs against the implementation it was
written alongside is not a specification instrument — it is a regression test
with ambitions.

**Result: 15/15, conformant on core, stateless and security profiles.** The
specification is implementable from the document.

Dependency-free (`node:http` only), so it runs anywhere Node does and can be
audited in one sitting.

## What it implements

Session binding with seven-day expiry, identity parsing and verification,
mandate scope coverage including glob suffixes, expiry checks, version
negotiation (a caller that advertises nothing gets the **oldest** version),
lattice-keyed abuse controls with a bounded LRU, pre-auth metering, admin
authentication in constant time and **disabled when unset**, and body caps per
tier.

## What it does not

Federation, receipts, settlement, telemetry, policy, sealed credentials. Those
are reference-implementation features, and their absence is the point: a second
implementation should be free to implement a subset and still be conformant for
the profiles it claims.
