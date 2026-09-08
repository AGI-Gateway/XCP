# XCP Gateway

The trust boundary. The gateway verifies sessions, gates mandates, and routes
A2T / A2A / T2T to upstream MCP servers or peers — attaching the **verified**
agent identity, never a client-asserted one. It holds no user keys and no funds:
it is a verifier and router, not a custodian.

```bash
pip install -r requirements.txt
XCP_UPSTREAMS='{"research":"http://localhost:9001/mcp"}' \
  uvicorn xcp_gateway:app --host 0.0.0.0 --port 8080
```

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `XCP_VERIFY_URL` | (empty) | external verifier URL; empty = built-in in-memory registry |
| `XCP_UPSTREAMS` | `{}` | JSON map `{server_name: mcp_url}` for A2T routing |
| `XCP_POSTURE` | `enforce` | `enforce` (reject unverified) or `observe` (allow + log) |
| `XCP_GATEWAY_ID` | `gw-local` | id stamped into audit + `XCP-Verified-By` |

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/session/open` | bind a certificate footprint to an agent |
| POST | `/v1/session/close` | end a session |
| POST | `/v1/a2t/call` | Agent → Tool (verify + mandate + route to MCP) |
| POST | `/v1/a2a/delegate` | Agent ↔ Agent (both sessions verified) |
| POST | `/v1/t2t/pipe` | Tool ↔ Tool (mandate carried on the hop) |
| POST | `/admin/revoke` | kill switch (local registry) |
| GET | `/metrics` | Prometheus metrics |
| GET | `/health` | posture, verifier mode, upstreams |

## Verification

With `XCP_VERIFY_URL` set, session and mandate checks are delegated to the
[verifier](../verifier/README.md), which does real Merkle inclusion + EIP-712 +
scope coverage against an on-chain (or in-memory) Session Registry. Without it,
the gateway uses a built-in in-memory registry so it runs standalone for
development.

## Enforcement posture

- **enforce** — unverified sessions get 401; out-of-scope actions get 403.
- **observe** — everything is allowed but the audit log records that it was
  unverified/unauthorized. Use this to onboard a server before its properties
  are established, then promote to enforce.

## Metrics

`xcp_gateway_requests_total{stream,decision}`,
`xcp_gateway_sessions_total{result}`,
`xcp_gateway_mandate_denials_total{scope}`,
`xcp_gateway_upstream_seconds{server}` (needs `prometheus-client`).
