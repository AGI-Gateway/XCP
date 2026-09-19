# XCP Security Model

This document states plainly what XCP defends against, what it only partially
mitigates, and what it does not address. Overclaiming would be its own risk: XCP
is a trust, identity, session, and governance layer, and those are the wrong
tools for some classes of problem.

The threat taxonomies referenced here are real: the OWASP Top 10 for MCP, the
OWASP Top 10 for Agentic Applications (ASI), and published 2025–2026 research on
A2A session smuggling and agent-memory poisoning. XCP and ERC-8004x are draft
proposals.

## What XCP defends well

### Authentication — who is on the connection
*Addresses OWASP MCP07 (Insufficient Auth), ASI03 (Agent Identity Abuse).*

XCP replaces "trust the caller's assertion" with an on-chain, channel-bound
check: the certificate footprint `keccak256(DER(cert))` is recomputed from the
live connection and looked up in the Session Registry, which returns the bound
agent, mandate root, and rails. A header assertion alone is never trusted, and a
session is authenticated only if the footprint is bound, unrevoked, and within
its ≤7-day window. Each agent is a distinct on-chain identity, so actions are
attributable and identities can't be silently reused.

### Authorization — may they do this action
*Addresses OWASP MCP02 (Scope Creep), MCP01 (Token Mismanagement).*

Authorization is a mandate: a signed, scoped, time-bounded grant. Every action
presents a Merkle proof against the on-chain mandate root, a sponsor EIP-712
signature, and a scope that must cover the request. Scope can't creep because
it's fixed at issuance and checked on every call, and mandates carry explicit
expiry. Sessions are authenticated by channel-bound certificates, not bearer
tokens — there's nothing in a request to lift and replay, which is exactly
OWASP's prescription for MCP01.

### Accounting — what happened, provably
*Addresses OWASP MCP08 (Lack of Audit/Telemetry).*

Every action is attributable to a session and an on-chain identity, producing a
non-repudiable audit trail plus Prometheus metrics (`requests_total{decision}`,
`mandate_denials_total`, session verification outcomes). The emission is
standardized; retention and monitoring remain operational responsibilities.

### Secured A2A — trust between agents
*Addresses Agent Session Smuggling (Unit 42, 2025), ASI07 (Insecure Inter-Agent
Comms), Agent Card spoofing / Agent-in-the-Middle.*

The A2A stream requires **both** sessions verified before delegation — removing
the trust-by-default that session smuggling depends on. Channel binding blocks
cross-origin instruction injection, and identity bound on-chain plus to the mTLS
certificate means a spoofed Agent Card can't wear another agent's identity.
Mutual TLS closes the Agent-in-the-Middle position.

### Shared context — memory isolation
*Addresses OWASP MCP10 (Context Injection & Over-Sharing).*

Context access is a mandate-scoped action, and sessions are isolated by
footprint, so one agent can't silently read another's working memory.
Over-sharing becomes an explicit, authorized, audited transfer rather than an
ambient default.

### Native MCP↔MCP integration
*Addresses OWASP MCP09 (Shadow MCP Servers), and T2T chain authorization.*

Discovered servers can be brought under one governed wrapper, defaulting to an
observe posture until they meet a bar, converting shadow servers from
invisible-and-ungoverned to discovered-and-gated. The T2T stream preserves
authorization end-to-end across a tool chain by carrying the mandate on every
hop.

## What XCP only partially mitigates

| Threat | What XCP does | What it doesn't do |
|--------|---------------|--------------------|
| **ASI09/10 — Rogue agents / contagion** | Kill switch ends live sessions in ~1 block; per-hop mandates cap a compromised agent | Can't certify that individually-safe agents compose safely — multi-agent security is non-compositional |
| **ASI06 — Memory/context poisoning** | Attributes and scopes memory *writes*; makes the injection point discoverable | Doesn't inspect the semantic *content* an authorized agent writes — needs provenance + memory-integrity defenses |
| **MCP03 — Tool poisoning** | Wrapper can scan tool metadata/results for known patterns; promotion is gated and revocable | Signature scanning won't catch a sufficiently novel/obfuscated payload |
| **MCP06 — Prompt injection** | Reduces blast radius: scoped tools, per-hop mandates, attribution, audit | Can't stop a model from being persuaded by natural-language instructions in its context |

## Addressed by the optional security library (`xcpsec`)

The core protocol leaves three classes to the application, because they concern
the *content and effects* of an already-authorized call rather than identity or
authorization. The optional [`xcpsec`](https://github.com/AGI-Gateway/XCP/blob/main/security/README.md) library adds
enforcement for them at the two points XCP touches (the gateway, and the
result-return boundary), on a hardened mTLS transport. Coverage is real but
bounded — see the library README for the precise honest statement.

- **MCP05 — Command Injection & Execution — defense-in-depth (filter +
  containment).** Two complementary layers. The argument firewall
  (`xcpsec.argfirewall`) blocks the injection surface (shell metacharacters,
  SSRF targets, path traversal, unexpected arguments) before a call is routed,
  and `safe_run` executes with no shell (the reference gateway enables this with
  `XCP_SECURITY=1`). The sandbox (`xcpsec.sandbox`) then contains execution, so
  a payload that evades the filter still hits a wall: CPU/memory/file/process
  limits, a wall-clock kill, `no_new_privs`, a scrubbed environment, and — where
  the kernel supports it — network and mount-namespace isolation. `safe_eval`
  closes the `eval()` footgun. The reference server's `calc` and `run` tools use
  these. Capabilities are detected and reported (`Result.applied`), so the
  sandbox never overstates isolation; for fully untrusted code, run inside a
  container/microVM as the outer boundary too.
- **MCP04 — Supply Chain & Dependency Tampering — tool-surface tampering
  addressed.** Signed, pinned tool manifests (`xcpsec.supplychain`) turn rug
  pulls, schema poisoning, tool shadowing, and unapproved servers into
  cryptographic digest mismatches, and the digest can be anchored in the on-chain
  mandate root. This does not scan your dependency tree — pair with SBOM /
  dependency scanning for the code-level supply chain.
- **MCP06 — Prompt Injection — materially mitigated, not eliminated.** Provenance
  tainting and quarantine boundaries (`xcpsec.contentfirewall`) neutralize the
  common mechanisms and keep untrusted content structurally separated from
  instructions, while the confused-deputy guard plus XCP's scoped authorization
  ensure an injected instruction still can't invoke a tool the mandate doesn't
  grant. A novel phrasing can still evade a signature scan — this reduces
  probability and blast radius rather than guaranteeing prevention.

### Transport hardening

`xcpsec.mtls` provides the secured transport all of the above sits on: TLS 1.3
only, required client certificates, certificate pinning by footprint,
AgentBinding-OID extraction, and RFC 9266 channel binding so session tokens bind
to the exact connection. This closes transport-level attack surface (MITM,
downgrade, anonymous callers, cross-connection token replay).

## Operational security notes

- **Key custody.** Agents hold their own certificate private keys. XCP shrinks
  the exposure window (≤7-day bindings, on-chain revocation) and removes
  bearer-token replay, but a stolen live private key is usable until revoked.
  Protect keys in a proper key store or HSM.
- **The gateway is not a custodian.** It holds no agent keys and no funds.
  Compromising a gateway lets an attacker deny or misroute traffic, but does not
  yield agent credentials or the ability to forge on-chain bindings.
- **On-chain confidentiality.** Only mandate *roots* and binding metadata are
  public. Mandate contents and business data stay off-chain (leaves are hashed
  into the root). Don't put secrets in fields that reach the chain.
- **This is draft, unaudited code.** It demonstrates the protocol and passes its
  own tests. It has not had an independent security audit. Pin to a released spec
  and get a review before production.

## Reporting

Please report security issues privately to the maintainers rather than opening a
public issue, and allow time for a fix before disclosure.
