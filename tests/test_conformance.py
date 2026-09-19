"""
test_conformance.py — the suite must certify the reference AND reject a fake.

A conformance suite that passes everything certifies nothing. These tests run it
against the reference gateway and against a gateway that accepts every request,
and assert it can tell them apart.

    python tests/test_conformance.py
"""
from __future__ import annotations

import multiprocessing, os, sys, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from conformance import run, format_report, Profile, Outcome, Level, CHECKS

GOOD, BAD = 8620, 8621


def _good():
    os.environ.update(XCP_POSTURE="enforce", XCP_RATE_LIMIT="1",
                      XCP_GLOBAL_RATE="200000")
    sys.path.insert(0, str(ROOT))
    import uvicorn
    from core.gateway.xcp_gateway import app
    uvicorn.run(app, host="127.0.0.1", port=GOOD, log_level="error")


def _permissive():
    """A gateway that honours everything — the failure happy-path tests miss."""
    sys.path.insert(0, str(ROOT))
    import uvicorn
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    a = FastAPI()

    # Parameter-free handlers on purpose: under spawn, a `Request` annotation
    # may not resolve and FastAPI then treats the parameter as a query field,
    # returning 422 instead of the 200 this mock is meant to produce.
    @a.get("/health")
    async def h(): return {"ok": True}

    @a.post("/v1/session/open")
    async def s(): return JSONResponse({"sessionId": "x"})

    @a.post("/v1/a2t/call")
    async def c(): return JSONResponse({"result": "ok"})

    @a.post("/v1/a2a/delegate")
    async def d(): return JSONResponse({"accepted": True})

    uvicorn.run(a, host="127.0.0.1", port=BAD, log_level="error")


_UP = False


def _boot():
    global _UP
    if _UP:
        return
    try:
        multiprocessing.set_start_method("spawn", force=True)
    except RuntimeError:
        pass
    for f in (_good, _permissive):
        multiprocessing.Process(target=f, daemon=True).start()
    for p in (GOOD, BAD):
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{p}/health", timeout=2)
                break
            except Exception:
                time.sleep(0.4)
    _UP = True


# ── the suite's own contract ───────────────────────────────────────────────

def test_clauses_are_unique_and_namespaced():
    ids = [c[0] for c in CHECKS]
    assert len(ids) == len(set(ids)), "duplicate clause ids"
    assert all(i.startswith("XCP-") for i in ids)


def test_suite_is_mostly_negative_checks():
    """
    A suite that only tested happy paths would certify nothing about a trust
    layer: a gateway that accepts everything passes every happy-path test.
    """
    titles = " ".join(c[1].lower() for c in CHECKS)
    assert titles.count("refuse") + titles.count("reject") >= 6


def test_suite_imports_nothing_from_the_implementation():
    """Black-box: a Go or Rust gateway must get the same verdict."""
    src = (ROOT / "conformance" / "suite.py").read_text()
    for forbidden in ("from core.", "import core", "from trustfirewall",
                      "from trust.", "from vault"):
        assert forbidden not in src, f"suite reaches into the implementation: {forbidden}"


# ── discrimination ─────────────────────────────────────────────────────────

def test_reference_implementation_is_conformant():
    _boot()
    rep = run(f"http://127.0.0.1:{GOOD}",
              [Profile.CORE, Profile.STATELESS, Profile.SECURITY])
    assert rep.conformant, format_report(rep)


def test_a_permissive_gateway_is_rejected():
    _boot()
    rep = run(f"http://127.0.0.1:{BAD}",
              [Profile.CORE, Profile.STATELESS, Profile.SECURITY])
    assert not rep.conformant, "a gateway that honours everything must fail"
    failed = {r.clause for r in rep.failures()}
    # Diagnostic on failure: which checks fired, and what did they see.
    detail = "\n".join(f"  {r.outcome.value:<6}{r.clause:<20}{r.detail[:70]}"
                        for r in rep.results)
    for clause in ("XCP-CORE-003", "XCP-CORE-006", "XCP-CORE-007"):
        assert clause in failed, f"{clause} did not catch it:\n{detail}"


def test_it_catches_the_specific_failures_that_matter():
    _boot()
    rep = run(f"http://127.0.0.1:{BAD}", [Profile.CORE, Profile.SECURITY])
    reasons = " ".join(r.detail for r in rep.failures()).lower()
    assert "unauthenticated" in reasons or "scope" in reasons
    assert "open relay" in reasons, "unmetered routing must be called out"


def test_a_should_failure_does_not_disqualify():
    """Otherwise the first reasonable deployment to fail one ignores the suite."""
    _boot()
    rep = run(f"http://127.0.0.1:{GOOD}", [Profile.CORE])
    warns = [r for r in rep.results if r.outcome is Outcome.WARN]
    for w in warns:
        assert w.level is Level.SHOULD
    assert rep.conformant or rep.failures()


def test_report_serialises_for_a_catalog():
    _boot()
    import json
    rep = run(f"http://127.0.0.1:{GOOD}", [Profile.CORE])
    d = rep.to_dict()
    json.dumps(d)
    assert set(d) >= {"target", "conformant", "counts", "profilesPassed", "results"}


def test_unreachable_target_errors_rather_than_passing():
    rep = run("http://127.0.0.1:1", [Profile.CORE])
    assert not rep.conformant, "an unreachable endpoint must not be certified"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:150]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
