# XCP Architecture

XCP — the Multi-Model Secure Context Protocol — is a control plane that rides
alongside MCP, A2A, and payment rails rather than replacing them. This document
describes the moving parts and why they're arranged this way.

## The problem it solves

Agent protocols move data and trigger actions, but they carry no portable answer
to three questions:

1. **Identity** — who is actually on this connection?
2. **Authorization** — are they allowed to perform *this specific* action?
3. **Accountability** — what happened, provably, and who did it?

Each protocol solves fragments (MCP has OAuth options; A2A has Agent Cards), but
nothing binds them together across trust domains, and nothing lets a third party
verify a session without adopting the other party's identity system. XCP adds
that missing layer.

## Three planes over one session

Every XCP connection carries three parallel planes, multiplexed over a single
mTLS session:

```
        ┌───────────────────────── one mTLS session ─────────────────────────┐
        │  Identity plane      Governance plane        Payments plane          │
        │  verifySession()     mandate proofs          railsBitmap + settle    │
        └────────────────────────────────────────────────────────────────────┘
```

- **Identity** resolves *who*: the certificate footprint is looked up in the
  Session Registry, returning the bound agent id, its mandate root, and its
  allowed rails.
- **Governance** resolves *whether*: each action carries a mandate proof that
  must Merkle-verify against the on-chain root, carry a valid sponsor signature,
  and cover the requested scope.
- **Payments** resolves *settlement*: a session may only use the rails its
  binding allows, and a payment additionally requires a mandate covering the
  `pay:<rail>` scope — a double gate.

## The certificate footprint

The load-bearing primitive is the **certificate footprint**:

```
footprint = keccak256(DER(client_certificate))
```

The relying party recomputes it from the certificate observed on the *live* TLS
connection (RFC 9266 channel binding) and looks it up in the Session Registry.
Two properties follow:

- **Replay resistance.** A token or mandate captured from one connection cannot
  be used on another, because the attacker's connection has a different
  footprint. A header assertion of the footprint is never trusted on its own.
- **On-chain verifiability.** Any party can confirm — against a public registry
  no single domain operates — that this certificate is currently bound to this
  agent, carries this mandate root, and has not been revoked.

## Trust boundaries

```
   agent process          gateway (trust boundary)         upstream MCP server
   ┌───────────┐          ┌────────────────────┐           ┌────────────────┐
   │ holds key │──mTLS───▶│ verify + gate + route│──verified─▶│ trusts gateway │
   │ + mandate │          │ holds no keys/funds │  identity  │  identity only │
   └───────────┘          └────────────────────┘           └────────────────┘
                                    │
                                    ▼
                        Session Registry (on-chain)
                        no single party operates it
```

- The **agent** holds its own certificate private key and its sponsor-signed
  mandates. It never hands these to the gateway.
- The **gateway** is a verifier and router. It checks the session and the
  mandate, then forwards the *verified* identity upstream. It is deliberately
  not a custodian: compromising a gateway does not yield agent keys or funds.
- The **upstream server** trusts only the gateway-attested identity
  (`XCP-Verified-By`), so it doesn't need to re-implement verification.
- The **Session Registry** is the shared trust root. Because it's on a public
  chain, relying parties in different domains can verify each other without a
  central authority that could forge or suppress bindings.

## The three interaction types

XCP defines three streams, each with its own scope namespace, so authorization
is specific to the shape of the interaction:

| Stream | Direction | Scope | Notes |
|--------|-----------|-------|-------|
| A2T | Agent → Tool | `mcp:tools/<tool>` | the common case: calling MCP tools |
| A2A | Agent ↔ Agent | `a2a:delegate/<peer>` | **both** sessions verified; no trust-by-default |
| T2T | Tool ↔ Tool | `t2t:chain/<src>→<dst>` | output→input with no agent round-trip; mandate on every hop |

The A2A "both sessions verified" rule is what defeats agent session smuggling:
neither agent extends implicit trust to the other. The T2T "mandate on every
hop" rule is what keeps authorization intact when tools chain directly, instead
of dropping it or forcing a round-trip that invites injection.

## Why on-chain

The registry could be a centralized service. It's on-chain because the goal is
*cross-domain* trust: two organizations' agents should be able to verify each
other without either adopting the other's PKI or trusting a shared operator. The
chain provides integrity and availability of the binding records and a
tamper-evident revocation log — nothing more. Confidentiality of mandate
contents and business data stays off-chain (mandate leaves are hashed into the
root; only the root is public).

## What XCP is not

XCP is a trust, identity, session, and governance layer. It is **not** a
sandbox, a dependency scanner, or a prompt-injection filter. It reduces the blast
radius of those problems (scoped authorization, attribution, kill switch) but
does not replace input validation, supply-chain signing, or model-level
defenses. See [security.md](security.md) for the honest boundary.
