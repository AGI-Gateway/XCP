# XCP MCP Server

A reference MCP server that sits behind an XCP gateway. It speaks ordinary MCP
(JSON-RPC: `initialize` / `tools/list` / `tools/call`) so unmodified clients and
the gateway can talk to it, and it trusts the **verified** identity the gateway
forwards in `XCP-Agent-Identity` (validated by the presence of `XCP-Verified-By`).

```bash
pip install -r requirements.txt
REQUIRE_VERIFIED=1 uvicorn xcp_server:app --host 0.0.0.0 --port 9001
```

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `REQUIRE_VERIFIED` | `0` | `1` = reject `tools/call` that didn't arrive gateway-verified |
| `XCP_SERVER_NAME` | `reference-mcp` | name reported in `initialize` |

## Tools

The bundled tools are illustrative — `echo`, `sum`, `now`, and (when the
optional `xcpsec` library is importable) `calc` and `run`. `calc` evaluates a
user expression with `xcpsec.sandbox.safe_eval` (no `eval()` footgun); `run`
executes a Python snippet inside the containment sandbox (resource limits,
network isolation, wall-clock kill). They demonstrate handling untrusted input
safely. Replace the `TOOLS` registry in `xcp_server.py` with your own. Each tool is
`(description, params, handler)`; the handler takes the arguments dict and
returns a JSON-serializable result.

## Modes

- **Behind a gateway (recommended):** the gateway verifies the session and
  mandate, then forwards the verified identity. With `REQUIRE_VERIFIED=1` the
  server refuses any `tools/call` that didn't come through a gateway.
- **Standalone (dev):** accepts anonymous calls for local testing.

The server echoes `_xcp.servedFor` / `_xcp.verifiedBy` in results so you can see
which verified agent a call was served for.
