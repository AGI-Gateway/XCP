# XCP Protocol Reference

This document specifies the wire-level contract of the reference implementation:
the headers, the session and mandate flow, and the scope grammar. It follows
`draft-xcp-core-00`; where the draft and this code differ, the code is
the source of truth for this repository.

> XCP and the ERC-8004x Session Registry are draft proposals. Field names and
> shapes may change before a released spec.

## Transport

The canonical transport is gRPC over one mTLS (TLS 1.3) connection, with three
bidirectional streams multiplexed as HTTP/2 streams — defined in
[`proto/xcp_streams.proto`](https://github.com/AGI-Gateway/XCP/blob/main/proto/xcp_streams.proto). For ease of testing and
integration, the reference gateway also exposes the same operations over
HTTP/JSON, which is what the four clients and the examples use. The semantics are
identical; only the framing differs.

## Headers

Two headers carry the XCP envelope on every governed request.

### `XCP-Agent-Identity`

```
XCP-Agent-Identity: <agentId>;<chainId>;<footprint>
```

- `agentId` — decimal ERC-8004 Identity Registry token id
- `chainId` — decimal chain id of the settlement chain (e.g. `8453` for Base)
- `footprint` — `0x`-prefixed `keccak256(DER(cert))` of the session certificate

The gateway recomputes/verifies the footprint against the live connection and the
Session Registry. The header is an assertion; verification is what makes it true.

### `XCP-Mandate`

A JSON object (compact) proving authorization for the specific action:

```json
{
  "mandateId": "m-tools",
  "delegator": "0xSPONSOR…",
  "mandateScope": ["mcp:tools/research.*"],
  "notAfter": 1767225600,
  "leaf": "0x…",
  "proof": ["0x…", "0x…"],
  "signature": "0x…"
}
```

- `mandateScope` — the granted scopes (see grammar below)
- `notAfter` — unix seconds; the gateway rejects expired mandates
- `leaf` — keccak of the canonical mandate fields
- `proof` — Merkle inclusion path to the session's `mandateRoot`
- `signature` — sponsor EIP-712 signature over the mandate

When the gateway uses an external verifier, the full proof is checked (Merkle +
EIP-712 + scope). In local/dev mode the gateway checks scope coverage and expiry
from the header.

### `XCP-Verified-By` (gateway → upstream)

When the gateway forwards a verified call upstream, it strips any client-supplied
trust markers and sets:

```
XCP-Agent-Identity: <verified identity>
XCP-Verified-By: <gateway id>
```

Upstream servers trust the identity only when `XCP-Verified-By` is present, so an
agent cannot forge a "verified" identity by setting the header itself.

## Session lifecycle

```
POST /v1/session/open
  → { agentId, chainId, footprint }
  ← { sessionId, mandateRoot, rails, notAfter }
```

The gateway records the footprint binding. With an external verifier the binding
must already exist on-chain (created by the agent's controller calling
`setBinding` on the Session Registry); the gateway reads it. In local mode the
gateway's in-memory registry records it directly.

```
POST /v1/session/close        → ends the session
POST /admin/revoke            → kill switch (local registry); on-chain uses revokeSession
```

A binding's `notAfter` is capped at 7 days from issuance. Revocation is intended
to terminate live connections within about one block on-chain.

## Action requests

All three take the two XCP headers plus a small JSON body.

### A2T — Agent → Tool

```
POST /v1/a2t/call
  { "server": "research", "tool": "fetch", "arguments": { … } }
```

Scope required: `mcp:tools/<tool>`. On success the gateway forwards a JSON-RPC
`tools/call` to the upstream MCP server named by `server` (resolved through
`XCP_UPSTREAMS`) and returns its result.

### A2A — Agent ↔ Agent

```
POST /v1/a2a/delegate
  { "peerDid": "did:8004:8453:0x…", "task": { … } }
```

Scope required: `a2a:delegate/<peerDid>`. **Both** the caller's and the peer's
sessions must be verified before a delegation is bridged — neither side extends
implicit trust.

### T2T — Tool ↔ Tool

```
POST /v1/t2t/pipe
  { "src": "research.fetch", "dst": "summarize.run", "payload": { … } }
```

Scope required: `t2t:chain/<src>-><dst>`. The mandate is carried on the hop, so
the chain is authorized without a round-trip back through the agent, and each hop
is independently attributable.

## Scope grammar

Scopes are colon/slash-delimited strings. A granted scope **covers** a requested
scope by exact match or a single trailing-wildcard prefix:

```
granted  mcp:tools/research.*     covers   mcp:tools/research.fetch      ✓
granted  mcp:tools/research.*     covers   mcp:tools/research.summarize  ✓
granted  mcp:tools/research.*     covers   mcp:tools/payments.transfer   ✗
granted  a2a:delegate/did:8004:…  covers   a2a:delegate/did:8004:…       ✓ (exact)
granted  pay:x402/*               covers   pay:x402/transfer             ✓
```

Namespaces in use:

| Namespace | Example | Guards |
|-----------|---------|--------|
| `mcp:tools/` | `mcp:tools/research.fetch` | A2T tool calls |
| `a2a:delegate/` | `a2a:delegate/<peerDid>` | A2A delegations |
| `t2t:chain/` | `t2t:chain/<src>-><dst>` | T2T chains |
| `pay:<rail>/` | `pay:x402/transfer` | settlement (double-gated with railsBitmap) |

## Rails bitmap

The session binding carries a bitmap of allowed payment rails:

```
bit 0  x402
bit 1  AP2
bit 2  MPP
bit 3  ACP
```

A payment is allowed only if (a) the rail's bit is set in the session binding and
(b) a mandate covers the `pay:<rail>` scope. Either failing denies the payment.

## Error responses

| Status | Meaning |
|--------|---------|
| `401` | session not verified (unbound, expired, revoked, or agentId mismatch) |
| `403` | mandate gate failed (missing proof, expired, or scope not covered) |
| `404` | unknown upstream server (A2T) |
| `502` | upstream MCP server unreachable |

Bodies are `{ "error": "XCP: <reason>" }`.
