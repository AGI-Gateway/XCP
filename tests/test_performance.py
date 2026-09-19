"""
test_performance.py — guard the two regressions that measurement found.

Neither was visible in unit tests. Both cost roughly two orders of magnitude on
the hot path, and both would have shipped silently.

    python tests/test_performance.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_upstream_client_is_pooled():
    """
    Creating an AsyncClient per request pays a fresh TCP connect every call:
    measured at ~24 ms of added latency, more than 100x the gateway's own
    verification work.
    """
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    assert "_upstream_client()" in src
    routing = src[src.index("async def a2t_call"):]
    assert "AsyncClient(timeout=30)" not in routing, \
        "the routing path must not construct a client per request"
    assert "max_keepalive_connections" in src, "the pool must keep connections"


def test_native_ecdsa_backend_is_required_and_surfaced():
    """
    eth-keys calls its PURE PYTHON implementation 'NativeECCBackend', which is
    easy to misread. It is ~35x slower on signature verification, and
    verification runs on every call.
    """
    reqs = (ROOT / "requirements.txt").read_text()
    assert "coincurve" in reqs
    assert "35x" in reqs, "pin the dependency with the reason, or it gets dropped"
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    assert "_CRYPTO_FAST" in src and "cryptoBackend" in src, \
        "an operator must be able to see which backend is live"


def test_the_fast_backend_is_actually_installed_here():
    import eth_keys.backends as b
    name = b.get_backend_class().__name__
    assert "CoinCurve" in name, (
        f"ECDSA backend is {name}; signature verification will be ~35x slower. "
        "Install coincurve.")


def test_signature_verification_is_within_budget():
    """A soft ceiling. If this fails, the fast path has been lost again."""
    from bench.harness import measure
    from trustfirewall.stateless import mint, verify
    KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    FP = "0x" + "ab" * 32
    body = b'{"q":"x"}'
    cred = mint(KEY, agent_id=42001, chain_id=8453, footprint=FP, tier="A2xH2",
                mcp_method="tools/call", mcp_name="search", body=body)
    s = measure("verify", lambda: verify(cred, mcp_method="tools/call",
                                         mcp_name="search", body=body), n=200)
    assert s.p95 < 2000, f"verify p95 {s.p95:.0f}µs — expected well under 2ms"


def test_header_path_does_not_parse_the_body():
    """The authorization decision must stay a header-speed operation."""
    from bench.harness import measure
    from trustfirewall.stateless import scope_for
    s = measure("scope", lambda: scope_for("tools/call", "search"), n=5000)
    assert s.p95 < 20, f"scope derivation p95 {s.p95:.1f}µs is not header-speed"


def test_benchmarks_report_percentiles_not_just_means():
    """A mean hides the tail, and the tail is what gets someone paged."""
    src = (ROOT / "bench" / "harness.py").read_text()
    for field in ("p50", "p95", "p99"):
        assert field in src
    assert "baseline" in src.lower(), "an absolute number without a baseline is noise"


def test_benchmarks_state_their_environment_caveat():
    from bench.harness import ENVIRONMENT_CAVEAT
    low = ENVIRONMENT_CAVEAT.lower()
    assert "loopback" in low and "python is the reference" in low


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:140]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
