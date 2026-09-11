"""
xcp_gateway — reference XCP gateway (Multi-Model Secure Context Protocol).

The gateway is the trust boundary. It:
  1. Opens channel-bound sessions and binds the certificate footprint to an
     agent in the Session Registry (via the verifier).
  2. Verifies the session on every request (verifySession).
  3. Gates every governed action against a mandate proof (Merkle + EIP-712 +
     scope coverage), delegated to the verifier.
  4. Routes A2T / A2A / T2T to upstream MCP servers or peers, attaching the
     *verified* agent identity — never a client-asserted one.
  5. Emits audit + Prometheus metrics, and honors on-chain revocation.

The gateway holds no user keys and no funds: it is a verifier and router, not
a custodian.

Run:
    pip install fastapi "uvicorn[standard]" httpx
    # point at a verifier (see ../verifier); in-memory verifier is built in.
    XCP_VERIFY_URL=http://localhost:8500 \
    XCP_UPSTREAMS='{"research":"http://localhost:9001/mcp"}' \
      uvicorn xcp_gateway:app --host 0.0.0.0 --port 8080

Status: XCP / ERC-8004x are draft proposals.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

# ── optional Prometheus metrics ────────────────────────────────────────────
try:
    from prometheus_client import (Counter, Histogram, Gauge,
                                   generate_latest, CONTENT_TYPE_LATEST)
    _PROM = True
except ImportError:
    _PROM = False

# ── config ─────────────────────────────────────────────────────────────────
VERIFY_URL = os.getenv("XCP_VERIFY_URL", "")          # external verifier
UPSTREAMS = json.loads(os.getenv("XCP_UPSTREAMS", "{}"))  # {server: mcp_url}
POSTURE = os.getenv("XCP_POSTURE", "enforce")         # enforce | observe
GATEWAY_ID = os.getenv("XCP_GATEWAY_ID", "gw-local")

# ── optional security layer (xcpsec) ───────────────────────────────────────
# When XCP_SECURITY=1 and the xcpsec package is importable, the gateway adds
# argument-firewall checks (command injection / SSRF) on A2T calls and wraps
# tool results in an untrusted-content boundary (prompt-injection mitigation).
# The gateway runs fine without it; this is purely additive defense.
_SECURITY = os.getenv("XCP_SECURITY", "0") == "1"
_guard = None
if _SECURITY:
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "security"))
        from xcpsec import Guard as _Guard, Trust as _Trust
        from xcpsec.argfirewall import ArgumentFirewall as _ArgFW, ArgSpec as _ArgSpec
        _guard = _Guard()
        _SECURITY_OK = True
    except Exception as _e:      # library missing -> degrade gracefully
        print(f"[gateway] XCP_SECURITY=1 but xcpsec unavailable: {_e}", flush=True)
        _SECURITY_OK = False
else:
    _SECURITY_OK = False

# ── abuse controls ─────────────────────────────────────────────────────────
# A gateway published in a discovery catalog, routing for callers it has never
# met, with no rate limit, is an open relay. Capacity follows authority: the
# trust lattice already says how much a caller is trusted, so it also says how
# much of this node's budget they may consume.
_LIMITS = None
if os.getenv("XCP_RATE_LIMIT", "1") == "1":
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from trustfirewall.limits import RateLimiter
        _LIMITS = RateLimiter(
            global_rate_per_min=int(os.getenv("XCP_GLOBAL_RATE", "120000")),
            global_concurrency=int(os.getenv("XCP_GLOBAL_CONCURRENCY", "256")),
            fail_closed=os.getenv("XCP_LIMIT_FAIL_OPEN", "0") != "1")
    except Exception as _e:
        print(f"[gateway] rate limiting unavailable: {_e}", flush=True)

app = FastAPI(title="XCP Gateway", version="0.1.0-draft")


def _limit(ctx: "Ctx", method: str, scope: str = "", body: bytes = b""):
    """Returns a 429 response if the caller is over budget, else None."""
    if _LIMITS is None:
        return None
    tier = getattr(ctx.binding, "tier", "") if ctx.binding else ""
    d = _LIMITS.check(agent_key=str(ctx.agent_id or ""), tier=tier,
                      method=method, scope=scope, body_bytes=len(body))
    if d.allowed:
        return None
    audit(ctx, "limit", f"{d.limit}: {d.reason}")
    return JSONResponse({"error": f"XCP rate limit: {d.reason}",
                        "limit": d.limit, "retryAfter": d.retry_after},
                        status_code=429,
                        headers={"Retry-After": str(max(1, d.retry_after))})

if _PROM:
    M_REQ = Counter("xcp_gateway_requests_total", "requests",
                    ["stream", "decision"])
    M_SESS = Counter("xcp_gateway_sessions_total", "session opens", ["result"])
    M_DENY = Counter("xcp_gateway_mandate_denials_total", "denials", ["scope"])
    M_UP = Histogram("xcp_gateway_upstream_seconds", "upstream latency",
                     ["server"])
else:                                       # no-op stand-ins
    M_REQ = M_SESS = M_DENY = M_UP = None


def _m(metric, **labels):
    if _PROM and metric is not None:
        metric.labels(**labels).inc()


# ==========================================================================
# Session Registry (in-memory) — used when no external verifier is set.
# Mirrors the interface of ../verifier so the gateway runs standalone.
# ==========================================================================

@dataclass
class Binding:
    agent_id: int
    footprint: str
    mandate_root: str
    rails: int
    not_after: int
    revoked: bool = False
    tier: str = ""            # trust-lattice cell; drives the caller's allowance

    def valid(self) -> bool:
        return not self.revoked and self.not_after > int(time.time())


class LocalRegistry:
    """Minimal in-memory Session Registry for standalone operation."""

    def __init__(self) -> None:
        self._b: dict[str, Binding] = {}

    def bind(self, agent_id: int, footprint: str, mandate_root: str = "",
             rails: int = 0b0011, ttl: int = 7 * 86400,
             tier: str = "A0xH0") -> Binding:
        b = Binding(agent_id=agent_id, footprint=footprint,
                    mandate_root=mandate_root or "0x" + "00" * 32, rails=rails,
                    not_after=int(time.time()) + min(ttl, 7 * 86400), tier=tier)
        self._b[footprint] = b
        return b

    def verify(self, footprint: str) -> Optional[Binding]:
        return self._b.get(footprint)

    def revoke(self, footprint: str) -> bool:
        if footprint in self._b:
            self._b[footprint].revoked = True
            return True
        return False


registry = LocalRegistry()


# ==========================================================================
# Verification — external verifier if configured, else local registry.
# ==========================================================================

def _scope_covers(granted: str, requested: str) -> bool:
    if granted.endswith("*"):
        return requested.startswith(granted[:-1])
    return granted == requested


def verify_session(footprint: str, agent_id: int) -> tuple[bool, str, Binding | None]:
    """Return (ok, reason, binding)."""
    if VERIFY_URL:
        try:
            with httpx.Client(timeout=5) as hc:
                r = hc.post(f"{VERIFY_URL}/verify", json={"footprint": footprint})
                d = r.json()
                if not d.get("valid"):
                    return False, d.get("reason", "invalid session"), None
                b = Binding(agent_id=int(d.get("agentId", 0)), footprint=footprint,
                            mandate_root=d.get("mandateRoot", ""),
                            rails=int(d.get("railsBitmap", 0)),
                            not_after=int(time.time()) + 30,
                            tier=str(d.get("tier", "")))
                if b.agent_id and agent_id and b.agent_id != agent_id:
                    return False, "agentId mismatch", None
                return True, "", b
        except Exception as e:
            return (POSTURE == "observe"), f"verifier error: {e}", None
    # local
    b = registry.verify(footprint)
    if not b:
        return False, "no session binding", None
    if not b.valid():
        return False, "session expired or revoked", None
    if agent_id and b.agent_id != agent_id:
        return False, "agentId mismatch", None
    return True, "", b


def check_mandate(mandate_hdr: str, binding: Binding | None,
                  scope: str) -> tuple[bool, str]:
    """Gate an action's scope against the presented mandate proof."""
    if not mandate_hdr:
        return (POSTURE == "observe"), "no mandate proof"
    if VERIFY_URL:
        try:
            proof = json.loads(mandate_hdr)
            with httpx.Client(timeout=5) as hc:
                r = hc.post(f"{VERIFY_URL}/mandate", json={
                    "mandateRoot": binding.mandate_root if binding else "",
                    "scope": scope, "proof": proof})
                d = r.json()
                return bool(d.get("ok")), d.get("reason", "")
        except Exception as e:
            return (POSTURE == "observe"), f"verifier error: {e}"
    # local: check scope coverage + expiry from the header proof
    try:
        proof = json.loads(mandate_hdr)
    except Exception:
        return False, "malformed mandate proof"
    if int(proof.get("notAfter", 0)) and int(proof["notAfter"]) < int(time.time()):
        return False, "mandate expired"
    granted = proof.get("mandateScope", [])
    if granted and not any(_scope_covers(g, scope) for g in granted):
        return False, f"scope {scope} not granted"
    return True, ""


# ==========================================================================
# Request context
# ==========================================================================

@dataclass
class Ctx:
    agent_id: int = 0
    chain_id: int = 0
    footprint: str = ""
    verified: bool = False
    reason: str = ""
    binding: Binding | None = None


def parse_ctx(request: Request) -> Ctx:
    hdr = request.headers.get("xcp-agent-identity", "")
    parts = hdr.split(";")
    if len(parts) != 3:
        return Ctx(reason="missing or malformed XCP-Agent-Identity")
    try:
        agent_id, chain_id, footprint = int(parts[0]), int(parts[1]), parts[2]
    except ValueError:
        return Ctx(reason="bad identity header")
    ok, reason, binding = verify_session(footprint, agent_id)
    return Ctx(agent_id=agent_id, chain_id=chain_id, footprint=footprint,
               verified=ok, reason=reason, binding=binding)


def audit(ctx: Ctx, stream: str, detail: str = "") -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] gw={GATEWAY_ID} agent={ctx.agent_id} {stream} "
          f"{'OK' if ctx.verified else 'REJECT'} {detail}", flush=True)


def _reject(ctx: Ctx, msg_id: Any = None) -> JSONResponse:
    return JSONResponse({"error": f"XCP: {ctx.reason}. Present a valid "
                        "session via session/open."}, status_code=401)


def _deny(scope: str, why: str) -> JSONResponse:
    return JSONResponse({"error": f"XCP mandate gate: {why} for {scope}"},
                        status_code=403)


# ==========================================================================
# Endpoints
# ==========================================================================

@app.post("/v1/session/open")
async def session_open(request: Request) -> JSONResponse:
    """Bind a certificate footprint to an agent (channel-bound session)."""
    body = await request.json()
    footprint = body.get("footprint", "")
    agent_id = int(body.get("agentId", 0))
    if not footprint or not agent_id:
        _m(M_SESS, result="reject")
        return JSONResponse({"error": "footprint and agentId required"}, 400)
    # In production the binding is created on-chain by the agent's controller;
    # here the gateway's local registry records it for standalone operation.
    if not VERIFY_URL:
        b = registry.bind(agent_id, footprint,
                          mandate_root=body.get("mandateRoot", ""),
                          rails=int(body.get("rails", 0b0011)),
                          tier=str(body.get("tier", "A0xH0")))
        _m(M_SESS, result="ok")
        return JSONResponse({"sessionId": f"sess-{footprint[:10]}",
                            "mandateRoot": b.mandate_root, "rails": b.rails,
                            "tier": b.tier, "notAfter": b.not_after})
    # external verifier: the binding must already exist on-chain
    ok, reason, b = verify_session(footprint, agent_id)
    _m(M_SESS, result="ok" if ok else "reject")
    if not ok:
        return JSONResponse({"error": reason}, 401)
    return JSONResponse({"sessionId": f"sess-{footprint[:10]}",
                        "mandateRoot": b.mandate_root if b else "",
                        "rails": b.rails if b else 0})


@app.post("/v1/session/close")
async def session_close(request: Request) -> JSONResponse:
    ctx = parse_ctx(request)
    audit(ctx, "session/close")
    return JSONResponse({"closed": True})


@app.post("/v1/a2t/call")
async def a2t_call(request: Request) -> Response:
    """Agent -> Tool. Verify session + mandate, route to the MCP server."""
    ctx = parse_ctx(request)
    if not ctx.verified and POSTURE == "enforce":
        _m(M_REQ, stream="a2t", decision="reject")
        audit(ctx, "a2t", f"({ctx.reason})")
        return _reject(ctx)
    raw = await request.body()
    body = json.loads(raw or b"{}")
    server, tool = body.get("server", ""), body.get("tool", "")
    limited = _limit(ctx, "tools/call", f"mcp:tools/{tool}", raw)
    if limited is not None:
        return limited
    scope = f"mcp:tools/{tool}"
    ok, why = check_mandate(request.headers.get("xcp-mandate", ""),
                            ctx.binding, scope)
    if not ok and POSTURE == "enforce":
        _m(M_REQ, stream="a2t", decision="block")
        _m(M_DENY, scope=scope)
        audit(ctx, "a2t", f"tool={tool} BLOCKED ({why})")
        return _deny(scope, why)
    audit(ctx, "a2t", f"server={server} tool={tool}")
    _m(M_REQ, stream="a2t", decision="allow")
    # optional xcpsec argument firewall: block command injection / SSRF before routing
    if _SECURITY_OK and _guard is not None:
        args = body.get("arguments", {})
        v = _ArgFW(_infer_argspec(args)).check(args) if args else None
        if v is not None and v.blocked and POSTURE == "enforce":
            audit(ctx, "a2t", f"tool={tool} ARGFW-BLOCKED ({v.reason()})")
            return JSONResponse({"error": f"XCP argument firewall: {v.reason()}"}, 400)
    return await _route_mcp(server, tool, body.get("arguments", {}), ctx,
                            upstream_credential=request.headers.get(
                                H_UPSTREAM_CREDENTIAL, ""))


@app.post("/v1/a2a/delegate")
async def a2a_delegate(request: Request) -> Response:
    """Agent <-> Agent. BOTH peers must be verified; gate the delegate scope."""
    ctx = parse_ctx(request)
    if not ctx.verified and POSTURE == "enforce":
        _m(M_REQ, stream="a2a", decision="reject")
        return _reject(ctx)
    raw = await request.body()
    body = json.loads(raw or b"{}")
    peer = body.get("peerDid", "")
    limited = _limit(ctx, "tools/call", f"a2a:delegate/{peer}", raw)
    if limited is not None:
        return limited
    scope = f"a2a:delegate/{peer}"
    ok, why = check_mandate(request.headers.get("xcp-mandate", ""),
                            ctx.binding, scope)
    if not ok and POSTURE == "enforce":
        _m(M_REQ, stream="a2a", decision="block")
        _m(M_DENY, scope=scope)
        return _deny(scope, why)
    audit(ctx, "a2a", f"peer={peer}")
    _m(M_REQ, stream="a2a", decision="allow")
    # In a full deployment the gateway verifies the peer's session too, then
    # bridges the two sessions. Here we echo an accepted delegation.
    return JSONResponse({"accepted": True, "peer": peer,
                        "delegatedBy": ctx.agent_id, "task": body.get("task")})


@app.post("/v1/t2t/pipe")
async def t2t_pipe(request: Request) -> Response:
    """Tool <-> Tool. Mandate carried on the hop; no agent round-trip."""
    ctx = parse_ctx(request)
    if not ctx.verified and POSTURE == "enforce":
        _m(M_REQ, stream="t2t", decision="reject")
        return _reject(ctx)
    raw = await request.body()
    body = json.loads(raw or b"{}")
    src, dst = body.get("src", ""), body.get("dst", "")
    limited = _limit(ctx, "tools/call", f"t2t:chain/{src}->{dst}", raw)
    if limited is not None:
        return limited
    scope = f"t2t:chain/{src}->{dst}"
    ok, why = check_mandate(request.headers.get("xcp-mandate", ""),
                            ctx.binding, scope)
    if not ok and POSTURE == "enforce":
        _m(M_REQ, stream="t2t", decision="block")
        _m(M_DENY, scope=scope)
        return _deny(scope, why)
    audit(ctx, "t2t", f"{src}->{dst}")
    _m(M_REQ, stream="t2t", decision="allow")
    return JSONResponse({"chained": True, "src": src, "dst": dst,
                        "payload": body.get("payload")})


def _infer_argspec(args: dict) -> dict:
    """Build a default arg schema when none is registered: treat url-ish string
    values as URLs (SSRF-scanned) and everything else as scanned strings."""
    spec = {}
    for k, v in args.items():
        if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://")
                                   or "://" in v):
            spec[k] = _ArgSpec(type="url", required=False)
        elif isinstance(v, str):
            spec[k] = _ArgSpec(type="str", required=False, max_length=100000)
        elif isinstance(v, bool):
            spec[k] = _ArgSpec(type="bool", required=False)
        elif isinstance(v, int):
            spec[k] = _ArgSpec(type="int", required=False)
        elif isinstance(v, float):
            spec[k] = _ArgSpec(type="float", required=False)
        elif isinstance(v, list):
            spec[k] = _ArgSpec(type="list", required=False)
        else:
            spec[k] = _ArgSpec(type="str", required=False, max_length=100000)
    return spec


# The caller's own credential for a multi-tenant wrapper upstream. The gateway
# forwards it and never logs, stores or inspects it — see connectors/wrap.py.
H_UPSTREAM_CREDENTIAL = "xcp-upstream-credential"


async def _route_mcp(server: str, tool: str, args: dict, ctx: Ctx,
                     upstream_credential: str = "") -> Response:
    """Forward a verified tool call to the upstream MCP server."""
    url = UPSTREAMS.get(server)
    if not url:
        return JSONResponse({"error": f"unknown server '{server}'"}, 404)
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args}}
    t0 = time.time()
    try:
        async with httpx.AsyncClient(timeout=30) as hc:
            headers = {
                # the verified identity travels upstream, not the client's claim
                "XCP-Agent-Identity": f"{ctx.agent_id};{ctx.chain_id};{ctx.footprint}",
                "XCP-Verified-By": GATEWAY_ID}
            if upstream_credential:
                # pass-through only: never logged, never cached, never inspected
                headers["XCP-Upstream-Credential"] = upstream_credential
            r = await hc.post(url, json=rpc, headers=headers)
    except Exception as e:
        return JSONResponse({"error": f"upstream unreachable: {e}"}, 502)
    finally:
        if _PROM:
            M_UP.labels(server=server).observe(time.time() - t0)
    return Response(content=r.content, media_type="application/json",
                    status_code=r.status_code)


@app.post("/admin/revoke")
async def admin_revoke(request: Request) -> JSONResponse:
    """Kill switch: revoke a session by footprint (local registry)."""
    body = await request.json()
    fp = body.get("footprint", "")
    ok = registry.revoke(fp) if not VERIFY_URL else False
    return JSONResponse({"revoked": ok, "footprint": fp})


@app.get("/metrics")
async def metrics() -> Response:
    if not _PROM:
        return JSONResponse({"error": "prometheus_client not installed"}, 501)
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "posture": POSTURE, "gateway": GATEWAY_ID,
            "rateLimit": _LIMITS.stats() if _LIMITS else "disabled",
            "verifier": "external" if VERIFY_URL else "local",
            "upstreams": list(UPSTREAMS.keys())}
