"""
federation.routing — traffic engineering for a trust federation.

Applies the principles of [RFC9522] (which obsoletes [RFC3272]) to the problem
of choosing which peer serves a capability request. Most of that document
transfers directly. One thing does not, and it is the reason this module is not
a thin wrapper over a shortest-path algorithm.

THE ALGEBRA IS MIXED
--------------------
In IP traffic engineering, path metrics are additive (delay, cost) or concave
(bandwidth), and in both cases the optimal substructure that makes Dijkstra work
holds. In a trust federation there is a third dimension with different algebra:

    latency   additive along the path
    cost      additive along the path
    trust     MULTIPLICATIVE, and decaying -- each hop attenuates it

A path that is cheap and fast can therefore be worthless, because by the third
hop the trust remaining is insufficient to permit the effect the caller needs.
Optimising the additive terms first and checking trust afterwards produces
routes that look excellent and cannot be used.

So trust is applied as a CONSTRAINT, before optimisation, not as a weight
traded off against latency. You cannot buy a higher trust class with lower
latency, and an implementation that lets you has quietly made trust purchasable.

OPTIMAL ROUTING CENTRALISES
---------------------------
This is the uncomfortable part, and it connects two requirements that pull
against each other.

Pure latency or cost optimisation converges: every caller independently
discovers the same best peer and routes there. The result is precisely the
concentration that a federation exists to avoid, arrived at by everyone acting
rationally and locally.

The resolution is not a compromise with decentralisation ideology. [RFC9522]'s
RESOURCE-ORIENTED performance objective already requires avoiding
over-utilisation of some resources while others are under-utilised -- that is,
load balancing is a traffic-engineering goal in its own right, not a concession.
Path diversity here is that objective applied to a federation, and it happens to
also preserve the property that no peer becomes structurally necessary.

Concretely: selection is randomised among peers that are within a tolerance of
the best, rather than deterministic on the argument minimum.

DAMPING
-------
[RFC9522] warns that reactive traffic engineering oscillates: load moves to the
least-utilised resource, which becomes the most-utilised, and the load moves
back. A federation reacting to observed latency has exactly this failure mode.
Observations are therefore smoothed and switching requires the alternative to be
better by a margin, not merely better.

TAXONOMY
--------
In [RFC9522]'s terms this design is state-dependent, online, distributed,
local-information, and closed-loop. Distributed and local-information are
forced: the federation has no global view by construction, and a component with
one would be the chokepoint the design exists to avoid.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable, Optional

#: Trust attenuation per hop. Matches federation.node's decay.
HOP_DECAY = 0.5
MAX_HOPS = 3

#: How much worse than the best a candidate may be and still be selected.
#: Larger values buy path diversity at the cost of latency.
DEFAULT_TOLERANCE = 0.25

#: Smoothing factor for observed latency. Lower reacts more slowly.
EWMA_ALPHA = 0.2

#: A new route must beat the incumbent by this margin before traffic moves.
#: Without it, two near-equal peers trade load indefinitely.
SWITCH_MARGIN = 0.15


class Effect(IntEnum):
    """What the caller needs to be able to do. Ordered by how much trust it
    requires, because that ordering is what makes it a constraint."""
    OBSERVE = 0        # read, quarantined, nothing binding
    READ = 1           # read and rely on
    WRITE = 2          # cause state change
    SETTLE = 3         # move value


#: Minimum trust weight required to permit an effect. Derived from the
#: reachability matrix rather than invented here: an effect that the firewall
#: would refuse cannot be made permissible by routing.
EFFECT_FLOOR: dict[Effect, float] = {
    Effect.OBSERVE: 0.0,
    Effect.READ: 0.25,
    Effect.WRITE: 0.5,
    Effect.SETTLE: 1.0,     # direct peers only -- one hop of decay disqualifies
}

#: What a decision below the top trust class costs the CONSUMER, in units
#: comparable to transport price. A cheap untrusted peer is not cheap: its
#: output must be sandboxed, quarantined and re-verified, and that work is real.
OBLIGATION_COST: dict[str, int] = {
    "unknown": 40,
    "probed": 15,
    "attested": 4,
    "contracted": 0,
}


class RoutingError(Exception):
    pass


@dataclass
class PeerMetrics:
    """
    What a node knows about a peer. Local observation only -- nothing here is
    reported by the peer about itself, because a peer's self-description is not
    evidence.
    """
    domain: str
    hops: int = 1
    trust_weight: float = 1.0          # as observed by us, before decay
    server_class: str = "unknown"
    price_minor: int = 0               # what the peer charges per routed call
    latency_ms: float = 0.0            # smoothed
    samples: int = 0
    failures: int = 0
    inflight: int = 0
    revoked: bool = False
    last_seen: float = 0.0

    @property
    def effective_trust(self) -> float:
        """Trust after hop attenuation. Multiplicative, not additive."""
        if self.revoked or self.hops > MAX_HOPS:
            return 0.0
        return self.trust_weight * (HOP_DECAY ** max(0, self.hops - 1))

    @property
    def success_rate(self) -> float:
        if self.samples == 0:
            return 1.0                  # untested, not assumed bad
        return max(0.0, 1.0 - self.failures / self.samples)

    def observe(self, latency_ms: float, ok: bool = True) -> None:
        """Closed-loop feedback. Smoothed, per the oscillation warning."""
        self.samples += 1
        if not ok:
            self.failures += 1
        self.latency_ms = (latency_ms if self.samples == 1 else
                           (1 - EWMA_ALPHA) * self.latency_ms
                           + EWMA_ALPHA * latency_ms)
        self.last_seen = time.time()


@dataclass
class Candidate:
    peer: PeerMetrics
    score: float
    latency_ms: float
    total_cost: int
    trust: float
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"domain": self.peer.domain, "score": round(self.score, 4),
                "latencyMs": round(self.latency_ms, 2),
                "totalCost": self.total_cost, "trust": round(self.trust, 3),
                "hops": self.peer.hops, "reason": self.reason}


@dataclass
class Policy:
    """Per-request routing preference. Weights apply only AFTER constraints."""
    effect: Effect = Effect.READ
    latency_weight: float = 1.0
    cost_weight: float = 1.0
    tolerance: float = DEFAULT_TOLERANCE
    max_latency_ms: Optional[float] = None
    max_cost_minor: Optional[int] = None
    require_class: Optional[str] = None


def admissible(peer: PeerMetrics, policy: Policy) -> tuple[bool, str]:
    """
    Constraint filter. Runs BEFORE any optimisation, because a constraint that
    can be outweighed is a preference wearing a constraint's name.
    """
    if peer.revoked:
        return False, "revoked"
    if peer.hops > MAX_HOPS:
        return False, f"beyond {MAX_HOPS} hops"
    floor = EFFECT_FLOOR[policy.effect]
    if peer.effective_trust < floor:
        return False, (f"trust {peer.effective_trust:.2f} below the "
                       f"{floor:.2f} required for {policy.effect.name}")
    if policy.require_class and peer.server_class != policy.require_class:
        return False, f"class {peer.server_class} is not {policy.require_class}"
    if policy.max_latency_ms is not None and peer.latency_ms > policy.max_latency_ms:
        return False, "exceeds the latency budget"
    total = peer.price_minor + OBLIGATION_COST.get(peer.server_class, 40)
    if policy.max_cost_minor is not None and total > policy.max_cost_minor:
        return False, "exceeds the cost budget"
    return True, ""


def score(peer: PeerMetrics, policy: Policy) -> Candidate:
    """
    Lower is better. Latency and cost are additive; trust has already served
    its purpose as a constraint and is not traded against them here.
    """
    total_cost = peer.price_minor + OBLIGATION_COST.get(peer.server_class, 40)
    # An unreliable peer costs a retry, so failure rate inflates both terms.
    penalty = 1.0 / max(peer.success_rate, 0.05)
    s = (policy.latency_weight * peer.latency_ms
         + policy.cost_weight * total_cost) * penalty
    return Candidate(peer=peer, score=s, latency_ms=peer.latency_ms,
                     total_cost=total_cost, trust=peer.effective_trust)


def select(peers: Iterable[PeerMetrics], policy: Optional[Policy] = None,
           incumbent: Optional[str] = None,
           rng: Optional[random.Random] = None) -> Candidate:
    """
    Choose a peer.

    Selection is randomised among candidates within `tolerance` of the best
    rather than taken as the argument minimum, so that independent callers do
    not converge on one peer. That costs a little latency and buys the
    resource-oriented objective of [RFC9522] -- and, not incidentally, keeps
    any single peer from becoming structurally necessary.
    """
    p = policy or Policy()
    r = rng or random
    admitted: list[Candidate] = []
    refused: list[str] = []
    for peer in peers:
        ok, why = admissible(peer, p)
        if ok:
            admitted.append(score(peer, p))
        else:
            refused.append(f"{peer.domain}: {why}")
    if not admitted:
        raise RoutingError(
            "no peer satisfies the constraints for "
            f"{p.effect.name}: {'; '.join(refused) or 'no peers known'}")

    admitted.sort(key=lambda c: c.score)
    best = admitted[0].score
    band = [c for c in admitted if c.score <= best * (1.0 + p.tolerance)] or admitted[:1]

    # Hysteresis: keep the incumbent unless something is better by a margin.
    # Reactive routing without this oscillates, per [RFC9522].
    if incumbent:
        held = next((c for c in band if c.peer.domain == incumbent), None)
        if held is not None and held.score <= best * (1.0 + SWITCH_MARGIN):
            held.reason = "incumbent retained (within switch margin)"
            return held

    chosen = r.choice(band)
    chosen.reason = (f"selected from {len(band)} of {len(admitted)} admissible "
                     f"peers within {int(p.tolerance * 100)}% of best")
    return chosen


def concentration(history: Iterable[str]) -> dict[str, Any]:
    """
    Herfindahl index over realised routing decisions. Published so an operator
    can see whether their federation is concentrating in practice, which is not
    observable from the policy alone.
    """
    from collections import Counter
    counts = Counter(history)
    total = sum(counts.values())
    if total == 0:
        return {"hhi": 0.0, "peers": 0, "verdict": "no traffic"}
    shares = [n / total for n in counts.values()]
    hhi = sum(s * s for s in shares)
    top, top_n = counts.most_common(1)[0]
    verdict = ("concentrated: routing has converged despite the tolerance band"
               if hhi >= 0.5 else
               "moderate concentration" if hhi >= 0.25 else
               "well distributed")
    return {"hhi": round(hhi, 3), "peers": len(counts), "topPeer": top,
            "topShare": round(top_n / total, 3), "verdict": verdict}


__all__ = ["SWITCH_MARGIN", "Effect", "PeerMetrics", "Policy", "Candidate", "select",
           "admissible", "score", "concentration", "RoutingError",
           "EFFECT_FLOOR", "OBLIGATION_COST", "HOP_DECAY", "MAX_HOPS"]
