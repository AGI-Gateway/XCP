"""
xcp_server — reference XCP-aware MCP server (Multi-Model Secure Context Protocol).

An MCP server that sits behind an XCP gateway. It speaks ordinary MCP
(JSON-RPC: initialize / tools/list / tools/call) so unmodified MCP clients
and the gateway can talk to it, and it trusts the *verified* agent identity
the gateway forwards in the XCP-Agent-Identity header (attaching XCP-Verified-By).

Two deployment modes:
  - Behind a gateway (recommended): the gateway verifies the session and
    mandate, then forwards the verified identity. This server enforces that
    calls arrive verified when REQUIRE_VERIFIED=1.
  - Standalone (dev): accepts anonymous calls for local testing.

Run:
    pip install fastapi "uvicorn[standard]"
    REQUIRE_VERIFIED=1 uvicorn xcp_server:app --host 0.0.0.0 --port 9001

Tools exposed are illustrative (echo, fetch-metadata, sum). Replace `TOOLS`
with your own. Status: XCP / ERC-8004x are draft proposals.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

REQUIRE_VERIFIED = os.getenv("REQUIRE_VERIFIED", "0") == "1"
SERVER_NAME = os.getenv("XCP_SERVER_NAME", "reference-mcp")

app = FastAPI(title="XCP MCP Server", version="0.1.0-draft")


# ── tool registry ──────────────────────────────────────────────────────────
# Each tool: (description, json-schema-ish params, handler(args)->result)

def _echo(args: dict) -> dict:
    return {"echo": args.get("text", "")}


def _sum(args: dict) -> dict:
    xs = args.get("numbers", [])
    return {"sum": sum(float(x) for x in xs)}


def _now(args: dict) -> dict:
    return {"unix": int(time.time()), "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ")}


# Optional: tools that must handle untrusted input safely use xcpsec.sandbox.
# `calc` evaluates a user expression with safe_eval (no eval() footgun); `run`
# executes a short Python snippet inside the containment sandbox. Both are only
# registered when the security library is importable, so the base server has no
# hard dependency on it.
def _load_sandboxed_tools() -> dict:
    try:
        import os as _os, sys as _sys
        _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "..", "security"))
        from xcpsec.sandbox import (safe_eval, run_python_sandboxed,
                                    SandboxPolicy, UnsafeExpression)
    except Exception:
        return {}

    def _calc(args: dict) -> dict:
        expr = str(args.get("expr", ""))
        try:
            return {"result": safe_eval(expr, args.get("vars", {}))}
        except UnsafeExpression as e:
            return {"error": f"rejected unsafe expression: {e}"}

    def _run(args: dict) -> dict:
        code = str(args.get("code", ""))
        r = run_python_sandboxed(code, SandboxPolicy(
            cpu_seconds=2, wall_seconds=5, memory_mb=128, allow_network=False))
        return {"stdout": r.stdout[:4000], "stderr": r.stderr[:2000],
                "timed_out": r.timed_out, "returncode": r.returncode,
                "contained_by": sorted(r.applied)}

    return {
        "calc": ("Evaluate an arithmetic expression safely (no code execution).",
                 {"expr": {"type": "string"}}, _calc),
        "run":  ("Run a short Python snippet inside a resource-limited, "
                 "network-isolated sandbox.",
                 {"code": {"type": "string"}}, _run),
    }


TOOLS: dict[str, tuple[str, dict, Callable[[dict], dict]]] = {
    "echo": ("Echo the provided text back.",
             {"text": {"type": "string"}}, _echo),
    "sum":  ("Sum a list of numbers.",
             {"numbers": {"type": "array", "items": {"type": "number"}}}, _sum),
    "now":  ("Return the current server time.", {}, _now),
}

# Add the sandboxed tools if the security library is available.
TOOLS.update(_load_sandboxed_tools())


def _tool_list() -> list[dict]:
    return [{"name": name, "description": desc,
             "inputSchema": {"type": "object", "properties": params}}
            for name, (desc, params, _) in TOOLS.items()]


# ── identity forwarded by the gateway ──────────────────────────────────────

def _identity(request: Request) -> dict:
    hdr = request.headers.get("xcp-agent-identity", "")
    verified_by = request.headers.get("xcp-verified-by", "")
    parts = hdr.split(";")
    if len(parts) == 3 and verified_by:
        return {"agentId": parts[0], "chainId": parts[1],
                "footprint": parts[2], "verifiedBy": verified_by}
    return {}


# ── JSON-RPC handling (MCP) ────────────────────────────────────────────────

@app.post("/mcp")
async def mcp(request: Request) -> JSONResponse:
    try:
        msg = await request.json()
    except Exception:
        return JSONResponse(_err(None, -32700, "parse error"))
    method = msg.get("method", "")
    mid = msg.get("id")
    ident = _identity(request)

    # Handshake is always allowed so a client can discover requirements.
    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": SERVER_NAME, "version": "0.1.0"},
            "capabilities": {"tools": {}},
            "xcp": {"requiresVerified": REQUIRE_VERIFIED}}})

    if method in ("ping", "notifications/initialized"):
        return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": {}})

    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": mid,
                            "result": {"tools": _tool_list()}})

    if method == "tools/call":
        # Enforce that the gateway verified the caller, if configured.
        if REQUIRE_VERIFIED and not ident:
            return JSONResponse(_err(mid, -32001,
                "XCP: unverified call. Route through an XCP gateway."), 401)
        params = msg.get("params", {})
        name = params.get("name", "")
        if name not in TOOLS:
            return JSONResponse(_err(mid, -32602, f"unknown tool '{name}'"))
        _, _, handler = TOOLS[name]
        try:
            result = handler(params.get("arguments", {}))
        except Exception as e:
            return JSONResponse(_err(mid, -32603, f"tool error: {e}"))
        # Echo who the gateway said this was, for demonstration/audit.
        return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text",
                         "text": json.dumps(result)}],
            "_xcp": {"servedFor": ident.get("agentId"),
                     "verifiedBy": ident.get("verifiedBy")}}})

    return JSONResponse(_err(mid, -32601, f"method not found: {method}"))


def _err(mid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "server": SERVER_NAME,
            "requiresVerified": REQUIRE_VERIFIED,
            "tools": list(TOOLS.keys())}
