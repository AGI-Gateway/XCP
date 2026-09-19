"""
test_limits.py — a node that routes for strangers must not be an open relay.

The properties that matter:
  · anonymous callers get the harshest allowance, because that is where abuse lives
  · capacity follows authority, so the lattice tiers order correctly
  · concurrency is limited separately from rate — a rate limit does not stop slow-loris
  · the limiter itself cannot be used to exhaust the node's memory
  · a limiter failure must not become an abuse bypass

    python tests/test_limits.py
"""
from __future__ import annotations

import sys, threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from trustfirewall.limits import (RateLimiter, Allowance, ALLOWANCES, ANONYMOUS,
                                  COST)


def _lim(**kw):
    kw.setdefault("global_rate_per_min", 10**9)
    kw.setdefault("global_burst", 10**9)
    kw.setdefault("global_concurrency", 10**6)
    return RateLimiter(**kw)


# ── capacity follows authority ─────────────────────────────────────────────

def test_every_lattice_cell_has_an_allowance():
    for a in range(3):
        for h in range(3):
            assert f"A{a}xH{h}" in ALLOWANCES


def test_anonymous_is_the_harshest():
    for cell, a in ALLOWANCES.items():
        assert a.rate_per_min >= ANONYMOUS.rate_per_min, cell
        assert a.concurrency >= ANONYMOUS.concurrency, cell
    assert ANONYMOUS.rate_per_min < min(a.rate_per_min for a in ALLOWANCES.values()) \
        or ANONYMOUS.rate_per_min <= ALLOWANCES["A0xH0"].rate_per_min


def test_capacity_increases_with_the_lattice():
    assert ALLOWANCES["A2xH2"].rate_per_min > ALLOWANCES["A1xH1"].rate_per_min
    assert ALLOWANCES["A1xH1"].rate_per_min > ALLOWANCES["A0xH0"].rate_per_min
    assert ALLOWANCES["A2xH2"].concurrency > ALLOWANCES["A0xH0"].concurrency


def test_unbacked_agent_with_a_corporate_human_is_still_throttled():
    """A0xH2 is 'shadowed' in the lattice — capacity must reflect that."""
    assert ALLOWANCES["A0xH2"].rate_per_min <= ALLOWANCES["A1xH1"].rate_per_min


# ── cost weighting ─────────────────────────────────────────────────────────

def test_expensive_calls_cost_more():
    assert RateLimiter.cost_of("tools/list") < RateLimiter.cost_of("tools/call")
    assert RateLimiter.cost_of("tools/call", "t2t:chain/a->b") > \
           RateLimiter.cost_of("tools/call")
    assert RateLimiter.cost_of("tools/call", "a2a:delegate/x") > \
           RateLimiter.cost_of("tools/list")


def test_unknown_method_gets_the_default_cost():
    assert RateLimiter.cost_of("something/new") == COST["_default"]


# ── the limits actually bite ───────────────────────────────────────────────

def test_rate_limit_triggers_and_reports_retry_after():
    lim = _lim()
    allowed = 0
    for _ in range(500):
        d = lim.check(agent_key="a", tier="A0xH0", method="tools/call")
        if d.allowed:
            allowed += 1
        else:
            assert d.limit == "rate" and d.retry_after >= 1
            break
    else:
        assert False, "an A0xH0 caller should exhaust its bucket"
    assert allowed <= ALLOWANCES["A0xH0"].burst + 2


def test_anonymous_exhausts_far_sooner_than_a2xh2():
    def burn(tier):
        lim = _lim()
        n = 0
        while lim.check(agent_key="x", tier=tier, method="tools/call").allowed:
            n += 1
            if n > 50_000:
                break
        return n
    assert burn("") < burn("A0xH0") + 5
    assert burn("A2xH2") > burn("A0xH0") * 5


def test_body_size_is_capped_per_tier():
    lim = _lim()
    d = lim.check(agent_key="a", tier="A0xH0", method="tools/call",
                  body_bytes=10 * 1024 * 1024)
    assert not d.allowed and d.limit == "body"


def test_concurrency_is_limited_independently_of_rate():
    """A rate limit does nothing against slow-loris; concurrency does."""
    lim = _lim()
    holds = [lim.hold(agent_key="a", tier="A0xH0") for _ in range(3)]
    for h in holds[:ALLOWANCES["A0xH0"].concurrency]:
        h.__enter__()
    d = lim.check(agent_key="a", tier="A0xH0", method="tools/list")
    assert not d.allowed and d.limit == "concurrency"
    for h in holds[:ALLOWANCES["A0xH0"].concurrency]:
        h.__exit__()
    assert lim.check(agent_key="a", tier="A0xH0", method="tools/list").allowed


def test_callers_do_not_share_a_bucket():
    lim = _lim()
    while lim.check(agent_key="noisy", tier="A0xH0", method="tools/call").allowed:
        pass
    assert lim.check(agent_key="quiet", tier="A0xH0", method="tools/call").allowed


def test_bucket_refills_over_time():
    lim = _lim()
    t = 1000.0
    while lim.check(agent_key="a", tier="A0xH0", method="tools/call", now=t).allowed:
        pass
    assert lim.check(agent_key="a", tier="A0xH0", method="tools/call",
                     now=t + 120).allowed, "the bucket should refill"


# ── the global ceiling ─────────────────────────────────────────────────────

def test_global_ceiling_holds_even_for_trusted_callers():
    """A node dying under trusted traffic is just as down as one under attack."""
    lim = RateLimiter(global_rate_per_min=60, global_burst=10,
                      global_concurrency=1000)
    n = 0
    while lim.check(agent_key=f"a{n}", tier="A2xH2", method="tools/list").allowed:
        n += 1
        if n > 1000:
            break
    assert n < 100, "the global ceiling must bind regardless of tier"
    assert lim.rejections.get("global", 0) >= 1


def test_global_concurrency_ceiling():
    lim = RateLimiter(global_rate_per_min=10**9, global_burst=10**9,
                      global_concurrency=2)
    a = lim.hold(agent_key="a", tier="A2xH2"); a.__enter__()
    b = lim.hold(agent_key="b", tier="A2xH2"); b.__enter__()
    d = lim.check(agent_key="c", tier="A2xH2", method="tools/list")
    assert not d.allowed and d.limit == "global"
    a.__exit__(); b.__exit__()


# ── the limiter must not become the vulnerability ──────────────────────────

def test_tracked_callers_are_bounded():
    """
    A limiter keyed on an attacker-supplied identifier is itself a memory
    exhaustion vector if it grows without limit.
    """
    lim = RateLimiter(global_rate_per_min=10**9, global_burst=10**9,
                      max_tracked=100)
    for i in range(5_000):
        lim.check(agent_key=f"sybil-{i}", tier="A0xH0", method="tools/list")
    assert lim.stats()["trackedCallers"] <= 101


def test_eviction_never_drops_an_inflight_caller():
    lim = RateLimiter(global_rate_per_min=10**9, global_burst=10**9, max_tracked=5)
    h = lim.hold(agent_key="busy", tier="A0xH0"); h.__enter__()
    for i in range(200):
        lim.check(agent_key=f"other-{i}", tier="A0xH0", method="tools/list")
    assert lim.stats()["globalInflight"] == 1
    h.__exit__()
    assert lim.stats()["globalInflight"] == 0


def test_fail_closed_is_the_default():
    """A public node cannot fail open: that turns a limiter bug into a bypass."""
    lim = _lim()
    assert lim.stats()["failClosed"] is True


def test_concurrent_checks_are_safe():
    lim = _lim()
    errors: list[Exception] = []

    def hammer():
        try:
            for _ in range(400):
                lim.check(agent_key="shared", tier="A2xH2", method="tools/call")
        except Exception as e:                       # pragma: no cover
            errors.append(e)

    ts = [threading.Thread(target=hammer) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert not errors


def test_stats_expose_why_requests_were_rejected():
    lim = _lim()
    lim.check(agent_key="a", tier="A0xH0", method="tools/call",
              body_bytes=99 * 1024 * 1024)
    assert lim.stats()["rejections"].get("body", 0) == 1


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
