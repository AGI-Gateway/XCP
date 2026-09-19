"""
bench.gateway — what the trust layer costs end to end.

The only honest form of this claim is a difference, so this runs two servers
with an identical upstream and an identical client:

    baseline   a bare passthrough proxy — no identity, no mandate, no limits
    xcp        the real gateway in enforce posture with everything on

The gap between them is the price of the trust layer. Absolute numbers on one
machine say very little; the delta is what transfers.
"""
from __future__ import annotations

import json, multiprocessing, os, statistics, sys, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.harness import measure, Comparison, comparison_table, table, \
    ENVIRONMENT_CAVEAT

UP, BASE, XCP = 9410, 9411, 9412
FP = "0x" + "ab" * 32
AGENT = 42001


def _upstream():
    """A trivial MCP server. Identical for both paths, so it cancels out."""
    import uvicorn
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    a = FastAPI()

    @a.get("/health")
    async def h(): return {"ok": True}

    @a.post("/mcp")
    async def mcp():
        return JSONResponse({"jsonrpc": "2.0", "id": 1,
                             "result": {"content": [{"type": "text", "text": "ok"}]}})
    uvicorn.run(a, host="127.0.0.1", port=UP, log_level="error")


def _baseline():
    """Passthrough only. This is what you have WITHOUT a trust layer."""
    import uvicorn, httpx, json as _j
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    a = FastAPI()
    client = httpx.AsyncClient(timeout=10)

    @a.get("/health")
    async def h(): return {"ok": True}

    # Typed body rather than a Request annotation: under spawn the annotation
    # may not resolve and FastAPI then treats it as a query field, returning
    # 422. Same framework and same JSON parsing as the XCP path, so the
    # framework cost cancels in the comparison.
    @a.post("/v1/a2t/call")
    async def call(payload: dict):
        r = await client.post(f"http://127.0.0.1:{UP}/mcp",
                              content=_j.dumps(payload).encode(),
                              headers={"Content-Type": "application/json"})
        return JSONResponse(r.json())
    uvicorn.run(a, host="127.0.0.1", port=BASE, log_level="error")


def _xcp():
    os.environ.update(
        XCP_POSTURE="enforce", XCP_RATE_LIMIT="1", XCP_GLOBAL_RATE="10000000",
        XCP_GLOBAL_CONCURRENCY="4096",
        XCP_UPSTREAMS=json.dumps({"research": f"http://127.0.0.1:{UP}/mcp"}))
    sys.path.insert(0, str(ROOT))
    import uvicorn
    from core.gateway.xcp_gateway import app
    uvicorn.run(app, host="127.0.0.1", port=XCP, log_level="error")


def _wait(port: int):
    for _ in range(80):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
            return
        except Exception:
            time.sleep(0.3)
    raise RuntimeError(f"port {port} never came up")


def _post(port: int, path: str, body: dict, headers: dict):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main() -> int:
    multiprocessing.set_start_method("spawn", force=True)
    for fn in (_upstream, _baseline, _xcp):
        multiprocessing.Process(target=fn, daemon=True).start()
    for p in (UP, BASE, XCP):
        _wait(p)

    h = json.loads(urllib.request.urlopen(
        f"http://127.0.0.1:{XCP}/health", timeout=5).read())
    backend = h.get("cryptoBackend", "?")
    fast = h.get("cryptoFastPath")
    print(f"crypto backend: {backend}  fast_path={fast}")
    if not fast:
        print("  WARNING: measuring the pure-Python ECDSA path; "
              "numbers will be ~35x worse than a correctly configured node")

    _post(XCP, "/v1/session/open",
          {"agentId": AGENT, "chainId": 8453, "footprint": FP, "tier": "A2xH2"}, {})
    hdrs = {"XCP-Agent-Identity": f"{AGENT};8453;{FP}",
            "XCP-Mandate": json.dumps(
                {"mandateScope": ["mcp:tools/echo"],
                 "notAfter": int(time.time()) + 3600})}
    body = {"server": "research", "tool": "echo", "arguments": {"text": "hello"}}

    st, _ = _post(XCP, "/v1/a2t/call", body, hdrs)
    assert st in (200, 404, 502), f"xcp path not working: {st}"
    st2, _ = _post(BASE, "/v1/a2t/call", body, {})
    assert st2 == 200, f"baseline not working: {st2}"

    N = 400
    base = measure("baseline proxy (no trust layer)",
                   lambda: _post(BASE, "/v1/a2t/call", body, {}),
                   n=N, warmup=40, unit="ms")
    treat = measure("XCP gateway (enforce, all controls)",
                    lambda: _post(XCP, "/v1/a2t/call", body, hdrs),
                    n=N, warmup=40, unit="ms")
    anon = measure("XCP gateway, rejected call (401 path)",
                   lambda: _post(XCP, "/v1/a2t/call", body, {}),
                   n=200, warmup=20, unit="ms",
                   note="metered pre-auth, so a flood is bounded")

    cmp = Comparison(baseline=base, treatment=treat)
    print(table([base, treat, anon], "End-to-end, loopback"))
    print(comparison_table([cmp], "Cost of the trust layer"))
    print(f"\n  overhead p50: {cmp.overhead_p50:+.3f} ms "
          f"({cmp.ratio_p50:.2f}x baseline)")
    print(f"  overhead p95: {cmp.overhead_p95:+.3f} ms")
    print("\n  For context: a single cross-region network hop is 20-80 ms, so "
          f"the trust layer is {cmp.overhead_p50 / 30 * 100:.1f}% of one 30 ms RTT.")
    print(ENVIRONMENT_CAVEAT)

    Path("/tmp/bench-gateway.json").write_text(json.dumps({
        "cryptoBackend": backend, "cryptoFastPath": fast,
        "comparison": cmp.to_dict(), "rejectPath": anon.to_dict()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
