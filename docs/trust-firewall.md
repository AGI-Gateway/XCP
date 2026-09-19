# Trust Firewall

**Consume the whole MCP corpus, on graded terms, without sessions.**

A firewall decides whether a packet may pass. A *trust* firewall decides whether
a **call** may pass — using identity and authority rather than IP and port, and
deciding it from headers at the speed your edge already runs.

## What MCP 2026-07-28 changed

The fifth MCP specification removed protocol sessions. The `initialize`
handshake and the `Mcp-Session-Id` header are gone; every request is
self-describing, so any request can land on any instance behind a plain load
balancer — including serverless and edge deployments.

That was a direct challenge to how XCP originally worked:

| | before | after |
|---|---|---|
| MCP | stateful, session id, sticky routing | stateless request/response |
| XCP | verify once per session, reuse | **verify per request, bound to the call** |

The resolution is not to fight statelessness but to adopt it. Replace session
state with a credential that **is** the state — minted per request, signed, and
cryptographically bound to the specific call being made.

```
session id  →  a pointer to server-side state       (needs stickiness)
credential  →  the state, signed and self-verifying (needs nothing)
```

!!! tip "This is stronger than what it replaces"
    A stolen session id was a bearer token for everything that session could do.
    A stolen request credential is bound to one method, one tool, one argument
    digest and a seconds-long expiry. Replay it against a different tool and the
    binding check fails.

## The headers do the work

MCP 2026-07-28 made two headers mandatory on Streamable HTTP so infrastructure
can route and meter without opening the body:

```http
POST /mcp HTTP/1.1
Mcp-Method: tools/call
Mcp-Name: search
XCP-Request-Credential: eyJhZ2VudF9pZCI6NDIwMDEs…
```

Those map one-to-one onto XCP's scope grammar, which already had the same shape:

| `Mcp-Method` | `Mcp-Name` | XCP scope |
|---|---|---|
| `tools/call` | `search` | `mcp:tools/search` |
| `tools/list` | — | `mcp:tools/list` |
| `resources/read` | `file://x` | `mcp:resources/read` |
| `prompts/get` | `greet` | `mcp:prompts/greet` |

So authorization is decided **without parsing the body**. Deep argument
inspection stays a separate, optional stage
([`xcpsec.argfirewall`](https://github.com/AGI-Gateway/XCP/tree/main/security)).

## Graded reachability

There are tens of thousands of reachable MCP servers and a large share are
unauthenticated. The instinct is to allowlist a handful and ignore the rest.
That is safe and useless.

The Trust Firewall takes the other route: **the whole corpus is reachable, and
the terms of engagement vary.** Two axes decide those terms.

**What backs the caller** — the [trust lattice](trust-lattice.md) cell (`A0`–`A2` × `H0`–`H2`).

**What backs the server** — its trust class:

| class | meaning |
|---|---|
| `unknown` | discovered in the corpus; never probed |
| `probed` | passed the safety gate: auth required, no SSRF, clean tool metadata |
| `attested` | publisher-signed, digest-pinned manifest |
| `contracted` | a legal entity stands behind it |

Their intersection yields the terms:

| caller | unknown | probed | attested | contracted |
|---|---|---|---|---|
| **A2 company** | observe (read only) | allow · escrow | allow · metered | **allow · full** |
| **A1 registry** | observe (read only) | allow · escrow | allow · metered | allow · metered |
| **A0 free** | observe (read only) | read only | read only | read only |

### The rules, stated so they can be argued with

- An **unknown server is never blocked outright** — it is reachable in observe
  mode, read-only, sandboxed, with output quarantined. Blocking the unvetted
  majority is what makes people bypass the gateway.
- **Nothing binding happens against an unknown server**, at any caller tier.
  Reachability is not endorsement.
- **Writes require** the server to be at least `probed` *and* the caller to be at
  least `A1`. A free agent may read the world; it may not change it.
- **Settlement requires** `attested` or better *and* a caller who can be held to
  account. Money never moves toward an anonymous counterparty.
- **Output below `contracted` is treated as untrusted content**, because a
  well-behaved server can still return a prompt injection.

## Obligations travel with the decision

A decision isn't just allow/deny. It carries what the caller must do *because of
who they are talking to*:

```python
{
  "sandboxExecution": True,    # run under xcpsec.sandbox
  "quarantineOutput": True,    # wrap in an untrusted-content boundary
  "requireReceipt": False,     # settlement needs proof-of-delivery
  "scanArguments": True,       # argument firewall before forwarding
  "maxScope": "read"
}
```

## Usage

```python
from trustfirewall import TrustFirewall, ServerClass, mint

fw = TrustFirewall(posture="enforce")
fw.load_lattice()                       # tier → scopes from the trust lattice
fw.classify_many({
    "partner.acme.example": ServerClass.CONTRACTED,
    "scraped.example":      ServerClass.UNKNOWN,
})

cred = mint(agent_key, agent_id=42001, chain_id=8453, footprint=fp,
            tier="A2xH2", mcp_method="tools/call", mcp_name="search",
            body=body, ttl_seconds=60, spend_cap_minor=25_000)

d = fw.decide(request.headers, body, server_host="partner.acme.example")
if not d.allowed:
    reject(d.reason)
if d.obligations.quarantine_output:
    result = content_firewall.wrap(result, origin=d.scope)
```

Run the demo:

```bash
python examples/trust_firewall.py
```

## MRTR — one logical call, several round trips

MCP 2026-07-28 replaced server-pushed elicitation with **Multi Round-Trip
Requests**: the server returns `input_required`, the client collects the answer
and retries. One logical call can now span several HTTP requests, each needing
its own credential. A `flow` id links them, so audit and
[receipts](receipts.md) record one logical call with N round trips rather than N
unrelated calls.

## What this is *not*

!!! warning "Don't compete where it's commodity"
    Since MCP 2026-07-28, **any** WAF or API gateway can route, throttle and
    meter per tool from those same two headers. That part is commodity and
    getting more so.

    The Trust Firewall is not competing there. What it adds is the part a WAF
    structurally cannot do: bind the call to a verified agent identity, check it
    against a signed mandate, grade it against the counterparty's trust class,
    and carry a spend ceiling and receipt obligation into settlement.

## Migration notes

- **Legacy clients**: an `Mcp-Session-Id` header surfaces as a *warning*, not a
  failure — stale clients keep working while you migrate.
- **Deprecated methods**: `roots/list`, `sampling/createMessage`,
  `logging/setLevel` are flagged. They have a 12-month removal window.
- **Auth**: MCP tightened authorization alongside — Dynamic Client Registration
  deprecated, RFC 9207 issuer identification, RFC 8707 resource indicators so
  tokens are accepted only by their audience. Those stack *underneath* XCP:
  OAuth answers "is this token for this server", XCP answers "which agent, under
  whose authority, for what scope, with what spend cap".
- **Enterprise Managed Auth**: the new EMA extension provides IdP-based org-wide
  provisioning — a natural source for the `H2` entitlement attributes the
  lattice consumes.
