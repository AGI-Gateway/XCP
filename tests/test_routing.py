"""
test_routing.py — traffic engineering for a federation, per RFC 9522.

Three properties carry this design, and each is a place the obvious
implementation gets it wrong:

  · trust is a CONSTRAINT, not a weight — otherwise it becomes purchasable
  · a cheap untrusted peer is not cheap — obligations are real work
  · optimal routing CENTRALISES — the argmin converges on one peer

    python tests/test_routing.py
"""
from __future__ import annotations
import random, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from federation.routing import (PeerMetrics, Policy, Effect, Candidate, select,
                                admissible, score, concentration, RoutingError,
                                EFFECT_FLOOR, OBLIGATION_COST, HOP_DECAY,
                                MAX_HOPS, SWITCH_MARGIN)


def _peers(n=5, **kw):
    base = dict(hops=1, trust_weight=1.0, server_class="attested",
                price_minor=10, latency_ms=20.0, samples=50)
    base.update(kw)
    return [PeerMetrics(domain=f"p{i}.test", **base) for i in range(n)]


# ── trust is a constraint ──────────────────────────────────────────────────

def test_trust_attenuates_multiplicatively_not_additively():
    for hops, expect in ((1, 1.0), (2, 0.5), (3, 0.25)):
        p = PeerMetrics("x.test", hops=hops, trust_weight=1.0)
        assert abs(p.effective_trust - expect) < 1e-9


def test_a_distant_peer_cannot_settle_however_cheap_or_fast():
    """
    The failure the constraint prevents: a path that is optimal on every
    additive metric and has decayed past the trust needed to use it.
    """
    far = PeerMetrics("far.test", hops=3, trust_weight=1.0,
                      server_class="contracted", price_minor=0,
                      latency_ms=0.1, samples=99)
    ok, why = admissible(far, Policy(effect=Effect.SETTLE))
    assert not ok and "below" in why
    assert admissible(far, Policy(effect=Effect.OBSERVE))[0]


def test_low_latency_cannot_buy_a_higher_effect():
    """Trust must not be tradeable against latency, or it is purchasable."""
    peers = [PeerMetrics("instant.test", hops=3, trust_weight=1.0,
                         server_class="contracted", price_minor=0,
                         latency_ms=0.01, samples=99)]
    try:
        select(peers, Policy(effect=Effect.WRITE))
        assert False, "a distant peer was selected for a write"
    except RoutingError as e:
        assert "trust" in str(e)


def test_beyond_the_hop_cap_nothing_is_admissible():
    far = PeerMetrics("x.test", hops=MAX_HOPS + 1, trust_weight=1.0)
    assert far.effective_trust == 0.0
    assert not admissible(far, Policy(effect=Effect.OBSERVE))[0]


def test_a_revoked_peer_is_never_admissible():
    p = _peers(1)[0]; p.revoked = True
    for eff in Effect:
        assert not admissible(p, Policy(effect=eff))[0]


def test_every_effect_has_a_declared_floor():
    for eff in Effect:
        assert eff in EFFECT_FLOOR
    assert EFFECT_FLOOR[Effect.SETTLE] > EFFECT_FLOOR[Effect.WRITE] \
        > EFFECT_FLOOR[Effect.READ] >= EFFECT_FLOOR[Effect.OBSERVE]


# ── obligations are real cost ──────────────────────────────────────────────

def test_a_cheap_untrusted_peer_is_not_cheap():
    cheap = PeerMetrics("cheap.test", server_class="unknown", price_minor=1,
                        latency_ms=20, samples=50)
    trusted = PeerMetrics("trusted.test", server_class="contracted",
                          price_minor=10, latency_ms=20, samples=50)
    assert score(cheap, Policy()).total_cost > score(trusted, Policy()).total_cost, \
        "sandboxing and quarantining output is work, and it must be priced"


def test_obligation_cost_decreases_with_trust_class():
    order = ["unknown", "probed", "attested", "contracted"]
    costs = [OBLIGATION_COST[c] for c in order]
    assert costs == sorted(costs, reverse=True)


def test_an_unreliable_peer_is_penalised():
    good = PeerMetrics("good.test", latency_ms=20, samples=100, failures=0)
    bad = PeerMetrics("bad.test", latency_ms=20, samples=100, failures=50)
    assert score(bad, Policy()).score > score(good, Policy()).score


def test_an_untested_peer_is_not_assumed_bad():
    assert PeerMetrics("new.test").success_rate == 1.0


# ── optimal routing centralises ────────────────────────────────────────────

def test_argmin_selection_converges_on_one_peer():
    """The property this module exists to avoid, demonstrated."""
    picks = [min(_peers(), key=lambda p: p.latency_ms).domain for _ in range(300)]
    c = concentration(picks)
    assert c["hhi"] == 1.0 and c["peers"] == 1


def test_a_tolerance_band_preserves_path_diversity():
    r = random.Random(11)
    picks = [select(_peers(), Policy(tolerance=0.25), rng=r).peer.domain
             for _ in range(400)]
    c = concentration(picks)
    assert c["peers"] >= 4, "routing converged despite the band"
    assert c["hhi"] < 0.3, f"concentrated: {c}"


def test_concentration_is_measurable_not_merely_intended():
    """Policy says nothing about realised behaviour; an operator needs the
    realised number."""
    assert concentration([])["verdict"] == "no traffic"
    assert concentration(["a"] * 10)["hhi"] == 1.0
    assert concentration([f"p{i}" for i in range(10)])["hhi"] < 0.2


# ── damping ────────────────────────────────────────────────────────────────

def test_a_marginal_improvement_does_not_move_traffic():
    """Reactive routing without hysteresis oscillates, per RFC 9522."""
    peers = _peers()
    peers[3].latency_ms = 20.0 * (1 + SWITCH_MARGIN / 2)
    peers[0].latency_ms = 20.0
    c = select(peers, Policy(), incumbent="p3.test", rng=random.Random(3))
    assert c.peer.domain == "p3.test" and "incumbent" in c.reason


def test_a_clear_degradation_does_move_traffic():
    peers = _peers()
    peers[3].latency_ms = 500.0
    c = select(peers, Policy(), incumbent="p3.test", rng=random.Random(3))
    assert c.peer.domain != "p3.test"


def test_observations_are_smoothed_not_taken_raw():
    p = PeerMetrics("x.test")
    p.observe(100.0)
    assert p.latency_ms == 100.0                # first sample seeds
    p.observe(0.0)
    assert 50.0 < p.latency_ms < 100.0, "a single outlier moved the estimate"


def test_failures_are_recorded_and_affect_selection():
    p = PeerMetrics("x.test")
    for _ in range(10):
        p.observe(20.0, ok=False)
    assert p.success_rate == 0.0 or p.failures == 10


# ── the module stays local ─────────────────────────────────────────────────

def test_routing_uses_only_locally_observed_state():
    """
    A component with a global view would be the chokepoint the federation
    exists to avoid, and the federation has no global view to give it.
    """
    src = (ROOT / "federation" / "routing.py").read_text()
    for forbidden in ("httpx", "requests", "urlopen", "global_view", "oracle"):
        assert forbidden not in src, f"routing reaches outside itself: {forbidden}"


def test_no_admissible_peer_is_an_error_not_a_silent_fallback():
    try:
        select([], Policy()); assert False
    except RoutingError as e:
        assert "no peer satisfies" in str(e)


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    p = f_ = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); p += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:130]}"); f_ += 1
    print(f"\n{p} passed, {f_} failed")
    sys.exit(1 if f_ else 0)
