"""
test_triage.py — the diagnostic must catch what the runbook is about.

A triage tool that reports green on a broken node is worse than none: it
converts "I should check" into "I checked". These tests run it against a
deliberately misconfigured node and assert it finds the things that matter.

    python tests/test_triage.py
"""
from __future__ import annotations

import multiprocessing, os, sys, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ops import triage, report, worst, Sev

GOOD, BAD = 9520, 9521
KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


def _good():
    os.environ.update(
        XCP_POSTURE="enforce", XCP_RATE_LIMIT="1",
        XCP_UPSTREAMS='{"research":"http://127.0.0.1:9999/mcp"}',
        XCP_NODE_KEY=KEY, XCP_NODE_DOMAIN="ok.test",
        XCP_NODE_URL=f"http://127.0.0.1:{GOOD}")
    sys.path.insert(0, str(ROOT))
    import uvicorn
    from core.gateway.xcp_gateway import app
    uvicorn.run(app, host="127.0.0.1", port=GOOD, log_level="error")


def _bad():
    os.environ.update(XCP_POSTURE="observe", XCP_RATE_LIMIT="0",
                      XCP_UPSTREAMS="{}")
    for k in ("XCP_NODE_KEY", "XCP_NODE_DOMAIN"):
        os.environ.pop(k, None)
    sys.path.insert(0, str(ROOT))
    import uvicorn
    from core.gateway.xcp_gateway import app
    uvicorn.run(app, host="127.0.0.1", port=BAD, log_level="error")


_UP = False


def _boot():
    global _UP
    if _UP:
        return
    try:
        multiprocessing.set_start_method("spawn", force=True)
    except RuntimeError:
        pass
    for fn in (_good, _bad):
        multiprocessing.Process(target=fn, daemon=True).start()
    for p in (GOOD, BAD):
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{p}/health", timeout=2)
                break
            except Exception:
                time.sleep(0.4)
    _UP = True


def _checks(port: int) -> dict[str, Sev]:
    return {f.check: f.sev for f in triage(f"http://127.0.0.1:{port}")}


# ── it must catch the things that matter ───────────────────────────────────

def test_observe_posture_is_critical_not_a_note():
    """Observe means calls are logged and not blocked. In production that is an
    incident, not a preference."""
    _boot()
    assert _checks(BAD)["enforcement posture"] is Sev.CRITICAL


def test_disabled_rate_limiting_is_critical():
    _boot()
    assert _checks(BAD)["abuse controls"] is Sev.CRITICAL


def test_missing_upstreams_is_flagged():
    _boot()
    assert _checks(BAD)["upstreams"] <= Sev.MEDIUM


def test_a_healthy_node_reports_clean():
    _boot()
    findings = triage(f"http://127.0.0.1:{GOOD}")
    assert worst(findings) is Sev.OK, \
        "\n".join(f.line() for f in findings if f.sev < Sev.OK)


def test_a_healthy_node_confirms_anonymous_calls_are_refused():
    _boot()
    c = _checks(GOOD)
    assert c.get("anonymous access") is Sev.OK


def test_an_unreachable_node_is_critical_and_stops_early():
    findings = triage("http://127.0.0.1:1")
    assert findings[0].sev is Sev.CRITICAL
    assert len(findings) == 1, "do not report on a node you could not reach"


# ── a diagnostic must be actionable ────────────────────────────────────────

def test_every_serious_finding_carries_a_next_action():
    """Reporting a symptom without a remedy moves the problem, it does not
    solve it."""
    _boot()
    for f in triage(f"http://127.0.0.1:{BAD}"):
        if f.sev < Sev.INFO:
            assert f.action, f"{f.check} has no action"
            assert len(f.action) > 30


def test_findings_are_ordered_worst_first():
    _boot()
    sevs = [f.sev for f in triage(f"http://127.0.0.1:{BAD}")]
    assert sevs == sorted(sevs)


def test_report_points_at_the_runbook_when_it_matters():
    _boot()
    text = report("x", triage(f"http://127.0.0.1:{BAD}"))
    assert "runbook" in text
    clean = report("x", triage(f"http://127.0.0.1:{GOOD}"))
    assert "runbook" not in clean, "do not send someone to a playbook for nothing"


def test_findings_serialise_for_incident_capture():
    _boot()
    import json
    json.dumps([f.to_dict() for f in triage(f"http://127.0.0.1:{GOOD}")])


# ── the runbook must cover what triage can report ──────────────────────────

def test_the_runbook_has_a_playbook_for_every_critical_finding():
    rb = (ROOT / "docs" / "runbook.md").read_text().lower()
    for topic in ("anonymous", "rate limiting is disabled",
                  "peer is compromised", "will not start", "crypto fast path"):
        assert topic in rb, f"runbook has no playbook for: {topic}"


def test_the_runbook_names_the_irreversible_failure_first():
    rb = (ROOT / "docs" / "runbook.md").read_text()
    assert "XCP_NODE_KEY" in rb[:1500], \
        "losing the node key is unrecoverable and must be near the top"


def test_the_runbook_cites_measured_capacity_not_guesses():
    rb = (ROOT / "docs" / "runbook.md").read_text()
    assert "0.21 ms" in rb and "make bench" in rb


def test_the_runbook_says_what_to_capture_before_restarting():
    rb = (ROOT / "docs" / "runbook.md").read_text().lower()
    assert "before restarting" in rb and "metrics" in rb


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
