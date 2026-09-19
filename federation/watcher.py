"""
federation.watcher — someone has to actually check.

THE GAP THIS CLOSES
-------------------
Transport claims are optimistic: a node posts a commitment, waits out a
challenge window, and is paid. Four fraud proofs make cheating detectable. None
of that matters if nobody looks.

That was stated as a limitation and left there, which is the wrong place to
leave it. Optimistic systems do not fail because the proofs are weak; they fail
because verification is unpaid work and everyone rationally declines it. In a
sparse federation — which is every federation at the beginning — the expected
value of watching is near zero, so the security argument quietly becomes an
assumption about altruism.

WHAT A WATCHER DOES
-------------------
Samples posted claims, asks the claiming node to disclose a few routes, and
checks them. Sampling rather than exhaustive audit is the point: a node that
cannot predict which routes will be challenged must make all of them honest.

    detection probability  p = 1 - (1 - s)^k

for a sample of `k` routes when a fraction `s` of them are fraudulent. A node
inflating 10% of its claims is caught with probability 0.65 on twenty samples,
and the expected penalty is the bond, not the inflated amount — so inflation is
unprofitable long before detection is certain.

ECONOMICS, STATED PLAINLY
-------------------------
A watcher is worth running when

    expected_reward x detection_probability  >  cost_of_checking

`viability()` computes that rather than asserting it, because if the number is
negative the honest conclusion is that the challenge window is too short, the
reward too small, or the federation too sparse — not that watching is somebody
else's job.

Status: XCP is a draft proposal. The parameters here are defaults, not results:
none has been modelled against real adversaries.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

#: Share of a slashed bond paid to whoever proved the fraud.
CHALLENGER_SHARE = 0.20
DEFAULT_SAMPLE = 20


@dataclass
class SampleResult:
    node_id: str
    epoch: int
    sampled: int
    verified: int
    failures: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict[str, Any]:
        return {"nodeId": self.node_id, "epoch": self.epoch,
                "sampled": self.sampled, "verified": self.verified,
                "failures": self.failures, "clean": self.clean}


def detection_probability(fraud_rate: float, sample: int) -> float:
    """Chance of catching a node cheating at `fraud_rate` with `sample` draws."""
    if fraud_rate <= 0 or sample <= 0:
        return 0.0
    return 1.0 - (1.0 - min(fraud_rate, 1.0)) ** sample


def sample_size_for(fraud_rate: float, confidence: float = 0.95) -> int:
    """How many routes to draw to reach `confidence` against `fraud_rate`."""
    import math
    if fraud_rate <= 0 or fraud_rate >= 1:
        return DEFAULT_SAMPLE
    return max(1, math.ceil(math.log(1 - confidence) / math.log(1 - fraud_rate)))


@dataclass
class Viability:
    expected_reward_minor: int
    detection_probability: float
    cost_minor: int

    @property
    def expected_value_minor(self) -> float:
        return self.expected_reward_minor * self.detection_probability - self.cost_minor

    @property
    def worth_running(self) -> bool:
        return self.expected_value_minor > 0

    def to_dict(self) -> dict[str, Any]:
        return {"expectedRewardMinor": self.expected_reward_minor,
                "detectionProbability": round(self.detection_probability, 4),
                "costMinor": self.cost_minor,
                "expectedValueMinor": round(self.expected_value_minor, 2),
                "worthRunning": self.worth_running,
                "note": ("If this is negative the challenge window, the reward "
                         "share, or the number of claims is too small — not "
                         "that watching is somebody else's job.")}


def viability(*, bond_minor: int, fraud_rate: float, sample: int,
              cost_per_check_minor: int = 1,
              share: float = CHALLENGER_SHARE) -> Viability:
    return Viability(
        expected_reward_minor=int(bond_minor * share),
        detection_probability=detection_probability(fraud_rate, sample),
        cost_minor=cost_per_check_minor * sample)


@dataclass
class Watcher:
    """
    Samples claims and reports what failed. Deliberately does not submit the
    challenge itself: deciding to slash another operator is a judgement with
    consequences, and a tool that did it automatically would make a false
    positive expensive and irreversible.
    """
    sample: int = DEFAULT_SAMPLE
    rng: random.Random = field(default_factory=random.Random)
    checked: int = 0
    challenges: list[SampleResult] = field(default_factory=list)

    def audit_epoch(self, node_id: str, epoch: int, route_ids: list[str],
                    disclose: Callable[[str], dict[str, Any]],
                    verify: Callable[[dict[str, Any]], list[str]]) -> SampleResult:
        """
        `disclose` asks the node for one route's evidence; `verify` checks it.
        Both are injected so a watcher can run against a live peer, a captured
        bundle, or a test fixture without changing.
        """
        if not route_ids:
            return SampleResult(node_id, epoch, 0, 0,
                                ["node claimed an epoch with no routes"])
        picks = (route_ids if len(route_ids) <= self.sample
                 else self.rng.sample(route_ids, self.sample))
        res = SampleResult(node_id, epoch, len(picks), 0)
        for rid in picks:
            self.checked += 1
            try:
                evidence = disclose(rid)
            except Exception as e:
                res.failures.append(f"{rid}: node would not disclose ({type(e).__name__})")
                continue
            problems = verify(evidence)
            if problems:
                res.failures.append(f"{rid}: {problems[0]}")
            else:
                res.verified += 1
        if not res.clean:
            self.challenges.append(res)
        return res

    def report(self) -> dict[str, Any]:
        return {"routesChecked": self.checked,
                "epochsChallenged": len(self.challenges),
                "challenges": [c.to_dict() for c in self.challenges]}


def recommended_window(claims_per_epoch: int, watchers: int = 1,
                       checks_per_hour: int = 200) -> int:
    """
    How long a challenge window must stay open for the expected watcher
    population to sample meaningfully. Returns seconds.

    A seven-day default is not a safety property by itself — it is only safe if
    somebody can get through the work inside it.
    """
    if claims_per_epoch <= 0 or watchers <= 0:
        return 7 * 86400
    needed_hours = claims_per_epoch / max(1, checks_per_hour * watchers)
    return max(86400, int(needed_hours * 3600 * 3))     # 3x headroom


__all__ = ["Watcher", "SampleResult", "Viability", "viability",
           "detection_probability", "sample_size_for", "recommended_window",
           "CHALLENGER_SHARE"]
