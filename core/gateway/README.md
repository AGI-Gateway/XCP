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

## Abuse controls

A gateway published in a discovery catalog, routing for callers it has never met,
with **no rate limit, is an open relay**. Enabled by default.

Capacity follows authority — the lattice already says how much a caller is
trusted, so it also says how much of the node's budget they may consume:

| tier | rate/min | burst | concurrent | max body |
|---|---:|---:|---:|---:|
| anonymous / unverified | 20 | 10 | 1 | 32 KB |
| `A0xH0` sandbox | 60 | 30 | 2 | 64 KB |
| `A1xH1` consumer | 3,000 | 1,000 | 16 | 4 MB |
| `A2xH2` full settlement | 30,000 | 10,000 | 64 | 16 MB |

Four limits, because the failure modes differ: **rate** stops flooding, **burst**
absorbs legitimate spikes, **concurrency** stops slow-loris (which a
requests/second limit does not touch at all), and **body size** stops one request
consuming the node. A **global ceiling** binds regardless of tier, because a node
that dies serving trusted traffic is just as down as one killed by an attacker.

Charges are **cost-weighted**: a `t2t:chain` across three hops costs 12 units
where a `tools/list` costs 1.

| env var | default | |
|---|---|---|
| `XCP_RATE_LIMIT` | `1` | set `0` to disable (private deployments only) |
| `XCP_GLOBAL_RATE` | `120000` | node-wide cost units/min |
| `XCP_GLOBAL_CONCURRENCY` | `256` | node-wide in-flight cap |
| `XCP_LIMIT_FAIL_OPEN` | `0` | fail closed by default — failing open turns a limiter bug into an abuse bypass |

The tracked-caller table is bounded (LRU): a limiter keyed on an
attacker-supplied identifier is otherwise a memory-exhaustion vector itself.

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
