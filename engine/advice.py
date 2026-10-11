"""
engine.advice — the boundary a classifier's output may not cross.

THE PRINCIPLE
-------------
Classification and authorization are separate concerns and must be separate
code paths. The classifier estimates what a request means and how risky it
looks. XCP decides, independently, whether the request is permitted under its
identity, mandate, scope, budget and security rules.

The reason is not tidiness. A classifier is a probabilistic function of
attacker-influenced input: the tool name, the arguments, the prior turns. If its
output can widen authority, then an attacker who can shift the classifier can
shift authority, and prompt injection becomes privilege escalation. The attack
does not need to beat the model often -- once is enough, and the model offers no
audit trail explaining why it was wrong.

So `Verdict` (engine.questions) is inert, nothing in the authorization path
accepts one, and the only way a verdict reaches XCP is as `Advice`, which can
express exactly two things:

    route     a preference between routes that differ ONLY in cost and latency
    scrutiny  a request to look harder

Neither can change whether a request is permitted. That is the guarantee, and
`tests/test_engine.py` asserts it by differential execution rather than by
inspection: for fuzzed verdicts, the permit outcome with advice must equal the
permit outcome without it.

WHY ADVICE CANNOT LOWER A TIER CEILING
--------------------------------------
The obvious design is to let a high risk score narrow the trust ceiling. It
looks safe, because narrowing is the direction XCP already trusts -- entitlements
may only restrict, `widens()` refuses, authority narrows at a boundary.

It is rejected here anyway. Narrowing is safe for *authority* and unsafe for
*availability*: a false "risky" reading would deny legitimate work, and the
denial would be caused by a model, be unexplainable to the operator, and vary
between runs. XCP's refusals are currently all attributable to a rule someone
wrote. Introducing one class of refusal attributable to a probability
distribution would be a real regression in a system whose value is that every
decision has a reason.

"XCP independently decides whether the request is permitted" is therefore taken
literally: no classifier output changes the permit outcome in EITHER direction.
Elevated scrutiny makes the node spend MORE -- prefer the conservative route,
raise audit detail -- which is always safe, because spending more is what the
node would have done with no classifier at all.

WHERE THE COUPLING WILL BE REINTRODUCED
---------------------------------------
Honestly: by an operator writing `if advice.scrutiny is ELEVATED: deny`. The
observation is in the decision record, so nothing stops them acting on it in
their own policy. That is their call to make and it is outside this module's
guarantee, which is why `Scrutiny` carries no `DENY` member and this module
offers no helper for it. If you want risk-based refusal, that is a rule you
write, own and can explain -- not a behaviour you inherit from a classifier
that happens to be installed.

Jev is marketed for precisely the coupling refused here: "guardrails: checking
risky tool calls (such as shell commands or refunds) before execution". For a
system whose job is authorization, that is the one application to decline.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any, Iterable, Optional, Sequence

from .questions import Tier, Verdict

__all__ = ["Scrutiny", "Route", "Advice", "advise", "RouteSet",
           "AUTHORIZATION_NEUTRAL_FIELDS", "RouteError"]


class Scrutiny(str, Enum):
    """
    How hard to look. Monotone in the safe direction only.

    There is no DENY member, and there will not be one. See the module
    docstring: a refusal caused by a probability distribution is a refusal
    nobody can explain.
    """
    NORMAL = "normal"
    ELEVATED = "elevated"     # prefer the conservative route, raise audit detail


class RouteError(Exception):
    """A route that could affect authorization."""


#: The ONLY fields a Route may declare. Enforced by Route.__post_init__ and
#: again by a test, because this allowlist is the structural half of the
#: guarantee: if a route could carry `skip_argfirewall` or `max_spend`, then
#: choosing a route would be choosing an authorization outcome, and the
#: classifier would be back in the authorization path through the side door.
#:
#: Adding a field here should feel like amending a constitution. Ask whether
#: two routes differing only in that field could ever permit different things.
AUTHORIZATION_NEUTRAL_FIELDS = frozenset({
    "name", "cost", "p50_micros", "description", "conservative",
})


@dataclass(frozen=True)
class Route:
    """
    A way to service a request that differs from other routes in cost and
    latency ONLY.

    This is the invariant that makes classifier-driven routing safe. If a
    cheaper route also had weaker guardrails, then "pick the cheap route" would
    mean "skip a check", and the classifier would be deciding authorization
    while appearing to decide cost. `tests/test_engine.py` asserts that every
    route reaches the same permit decision for the same request.
    """
    name: str
    #: Same units as federation.routing transport price, so the two compose.
    cost: int
    #: Median service time, for the accounting that justifies the cascade.
    p50_micros: int = 0
    description: str = ""
    #: The fallback when nothing is known. Exactly one route must be this: an
    #: abstention has to land somewhere, and it has to land on the route the
    #: node would have taken with no classifier installed.
    conservative: bool = False

    def __post_init__(self) -> None:
        declared = {f.name for f in fields(self)}
        extra = declared - AUTHORIZATION_NEUTRAL_FIELDS
        if extra:
            raise RouteError(
                f"Route declares {sorted(extra)}, which is not in "
                f"AUTHORIZATION_NEUTRAL_FIELDS. A route may differ from "
                f"another in cost and latency only; a field that can affect "
                f"what is permitted would put the classifier back in the "
                f"authorization path.")
        if self.cost < 0:
            raise RouteError("a negative cost would make a route free to prefer")


@dataclass(frozen=True)
class RouteSet:
    """The routes available for one decision, with exactly one conservative."""
    routes: tuple[Route, ...]

    def __post_init__(self) -> None:
        if not self.routes:
            raise RouteError("a RouteSet needs at least one route")
        names = [r.name for r in self.routes]
        if len(set(names)) != len(names):
            raise RouteError(f"duplicate route names: {names}")
        fallbacks = [r for r in self.routes if r.conservative]
        if len(fallbacks) != 1:
            raise RouteError(
                f"exactly one route must be conservative=True, found "
                f"{len(fallbacks)}. An abstention must land on the route the "
                f"node would take with no classifier at all, and that route "
                f"has to be named rather than inferred.")

    @property
    def conservative(self) -> Route:
        return next(r for r in self.routes if r.conservative)

    def get(self, name: str) -> Optional[Route]:
        return next((r for r in self.routes if r.name == name), None)

    @property
    def cheapest(self) -> Route:
        return min(self.routes, key=lambda r: (r.cost, r.p50_micros, r.name))


@dataclass(frozen=True)
class Advice:
    """
    What a classifier is permitted to say to XCP.

    Construct via `advise()`. Built directly it defaults to saying nothing,
    which is the correct value when in doubt.
    """
    #: A route name, or None for "no preference". Never a Route object: the
    #: router resolves the name against its own RouteSet, so advice cannot
    #: smuggle in a route the node does not offer.
    route: Optional[str] = None
    scrutiny: Scrutiny = Scrutiny.NORMAL
    #: Verdicts, for the decision record. Tainted data, never a reason.
    observations: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def none(cls) -> "Advice":
        """Say nothing. The value for every abstention and every error."""
        return cls()

    @property
    def silent(self) -> bool:
        return self.route is None and self.scrutiny is Scrutiny.NORMAL

    def resolve(self, routes: RouteSet) -> Route:
        """
        Pick a route. Falls back to the conservative one whenever advice is
        absent, unusable, or names something this node does not offer.

        Elevated scrutiny overrides a cheap preference: the two can disagree
        when one question says "simple" and another says "risky", and the
        resolution is always to spend more. A node that resolved that
        disagreement toward the cheap route would be letting a low-confidence
        "simple" cancel a high-confidence "risky".
        """
        if self.scrutiny is Scrutiny.ELEVATED:
            return routes.conservative
        if self.route is None:
            return routes.conservative
        chosen = routes.get(self.route)
        if chosen is None:
            # Not an error. A model trained against a different route set is a
            # configuration drift, and the safe reading of an unknown route
            # name is that we have no usable preference.
            return routes.conservative
        return chosen

    def audit_detail(self) -> str:
        return "elevated" if self.scrutiny is Scrutiny.ELEVATED else "normal"

    def to_record(self) -> dict[str, Any]:
        """
        For receipts. Deliberately has no field a reason could be read from:
        `route` is a cost choice and `observations` are marked tainted.
        """
        return {
            "route": self.route,
            "scrutiny": self.scrutiny.value,
            "observations": list(self.observations),
            "note": ("advisory only; this did not affect whether the request "
                     "was permitted"),
        }


def advise(verdicts: Iterable[Verdict], *,
           route_question: str = "complexity",
           risk_question: str = "risk",
           risk_levels: Sequence[str] = ("low", "medium", "high", "critical"),
           elevate_at: float = 2.0) -> Advice:
    """
    Convert verdicts into advice. The only constructor of non-silent Advice.

    `route_question` is a Choice whose options are route names. `risk_question`
    is a Score over ordered levels; its expected value crossing `elevate_at`
    raises scrutiny.

    Every failure mode returns silent advice:
      - the verdict abstained
      - no verdict matches either question id
      - the risk Score is bimodal, meaning the model is split between "trivial"
        and "critical"; the expected value then sits between two answers that
        are both wrong, so it is not usable as a severity
      - anything raises

    Note the asymmetry, which is the design: risk can only ever ELEVATE
    scrutiny, and complexity can only ever express a route preference that
    elevation overrides. There is no path from a verdict to a wider authority,
    a granted scope or a skipped check, because `Advice` has no field that
    could carry one.
    """
    by_id: dict[str, Verdict] = {}
    for v in verdicts:
        by_id[v.question_id] = v

    observations = tuple(v.to_observation() for v in by_id.values())

    scrutiny = Scrutiny.NORMAL
    risk = by_id.get(risk_question)
    if risk is not None and not risk.abstained:
        try:
            if risk.bimodal(risk_levels):
                # Split between the extremes. Elevate rather than route cheaply:
                # "either trivial or critical" is not a reason to economise.
                scrutiny = Scrutiny.ELEVATED
            else:
                expected = risk.expected(risk_levels)
                if expected is not None and expected >= elevate_at:
                    scrutiny = Scrutiny.ELEVATED
        except TypeError:
            # The question id was reused for a different kind. Say nothing.
            return Advice(observations=observations)

    route: Optional[str] = None
    complexity = by_id.get(route_question)
    if complexity is not None and not complexity.abstained:
        route = complexity.answer

    return Advice(route=route, scrutiny=scrutiny, observations=observations)
