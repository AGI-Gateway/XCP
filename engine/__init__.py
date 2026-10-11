"""
engine — a self-hosted decision and routing engine for XCP.

WHAT THIS IS
------------
A fast, local classifier that estimates what a request means and how risky it
looks, so a node can route cheap requests cheaply. It is a cost and latency
optimization and nothing else. It cannot change whether a request is permitted.

    from engine import classify, STANDARD_ROUTES

    advice = classify(server="research", tool="fetch",
                      scope="mcp:tools/fetch", arguments={"url": "https://x"})
    route = advice.resolve(STANDARD_ROUTES)      # a cost choice
    # ... XCP's own guardrail pipeline runs unchanged, whatever `advice` said

THE DESIGN PRINCIPLE
--------------------
Classification is separated from authorization. The classifier estimates; XCP
decides, independently, under its identity, mandate, scope, budget and security
rules. The separation is enforced in code rather than by convention:

  * `Verdict` (engine.questions) is inert. Nothing in the authorization path
    accepts one.
  * `Advice` (engine.advice) is the only thing that crosses the boundary, and
    it can express exactly two things -- a route preference and a request to
    look harder. It has no field that could grant a scope, raise a tier, skip
    a check or widen a budget.
  * A `Route` may declare only cost- and latency-related fields
    (`AUTHORIZATION_NEUTRAL_FIELDS`), so two routes cannot differ in what they
    permit. Otherwise "choose the cheap route" would quietly mean "skip a
    check".
  * `tests/test_engine.py` asserts the property by differential execution, not
    by inspection: across fuzzed verdicts, the permit outcome with advice must
    equal the permit outcome without it.

This matters because a classifier is a probabilistic function of
attacker-influenced input. If its output could widen authority, an attacker who
can shift the classifier could shift authority, and prompt injection would
become privilege escalation -- with no audit trail explaining why.

WHY SELF-HOSTED, AND WHY THAT IS NOT MAINLY ABOUT COST
------------------------------------------------------
TypeSafe's Jev established the useful interface for this job -- a state plus
typed questions, answered with calibrated probabilities -- and the typed
question shape here is borrowed from it deliberately. What is not borrowed is
the hosted endpoint.

XCP enforces data residency as a CONSTRAINT: a site outside
`Policy.permitted_sites` is inadmissible at any price, and `xcpsec.egress`
refuses destinations the operator has not declared. A hosted classifier is an
egress destination receiving the full request state. A node cannot
simultaneously enforce residency on its agents and ship their request bodies to
a third party for classification. In a private federation a hosted classifier is
not expensive, it is inadmissible.

The latency follows from the same choice. LiteLLM measured Jev's auto-router at
a 126.81 ms median per classification. The cascade here resolves most traffic in
microseconds, because most of what a gateway wants to know is knowable from
structure without a model at all.

HOW IT DEGRADES
---------------
To silence. No model installed, no model file, a corrupt label set, an
exception inside a tokenizer, a latency budget too small for the tier that
could have answered -- every one of these is an abstention with a recorded
reason, and an abstention resolves to the conservative route. You lose the
saving and keep every control. The engine's core is standard-library only so
that the machinery preventing a model from widening authority is present even
when no model is.

WHAT IT DOES NOT DO
-------------------
It does not refuse requests. Jev is marketed for "guardrails: checking risky
tool calls before execution", and that is the one application this engine
declines: a refusal attributable to a probability distribution is a refusal
nobody can explain, in a system whose value is that every decision has a
reason. Risk estimates are recorded as tainted observations and can raise
scrutiny. Turning one into a denial is a rule an operator writes and owns.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from .advice import (AUTHORIZATION_NEUTRAL_FIELDS, Advice, Route, RouteError,
                     RouteSet, Scrutiny, advise)
from .cascade import (Backend, Cascade, CascadeStats, DEFAULT_BUDGET_MICROS,
                      Deterministic, FastText, Rule, SetFit)
from .features import MAX_CHARS, cache_key, extract
from .questions import (Choice, MIN_CONFIDENCE, MIN_MARGIN, Noul, Question,
                        QuestionKind, Score, Tier, Verdict, softmax)

__all__ = [
    # questions
    "Question", "QuestionKind", "Noul", "Choice", "Score", "Verdict", "Tier",
    "softmax", "MIN_CONFIDENCE", "MIN_MARGIN",
    # the boundary
    "Advice", "Scrutiny", "Route", "RouteSet", "RouteError", "advise",
    "AUTHORIZATION_NEUTRAL_FIELDS",
    # cascade
    "Cascade", "Backend", "Deterministic", "FastText", "SetFit", "Rule",
    "CascadeStats", "DEFAULT_BUDGET_MICROS",
    # features
    "extract", "cache_key", "MAX_CHARS",
    # standard set
    "COMPLEXITY_LEVELS", "RISK_LEVELS", "COMPLEXITY", "RISK",
    "STANDARD_QUESTIONS", "STANDARD_ROUTES", "DEFAULT_RULES",
    "classify", "default_cascade",
]

# ── the standard question set ─────────────────────────────────────────────

#: Four complexity tiers. The same shape LiteLLM's auto-router uses for model
#: selection (SIMPLE / MEDIUM / COMPLEX / REASONING), because the mapping from
#: "how hard is this" to "which route" is the one most deployments want and
#: there is no reason to invent a different vocabulary for it.
COMPLEXITY_LEVELS: tuple[str, ...] = ("simple", "medium", "complex", "reasoning")

#: Ordered severity. Ordered matters: `Verdict.expected()` gives a continuous
#: score across these, which carries information the argmax discards.
RISK_LEVELS: tuple[str, ...] = ("low", "medium", "high", "critical")

COMPLEXITY = Choice(
    "complexity",
    "How much capability does servicing this request actually require?",
    COMPLEXITY_LEVELS)

RISK = Score(
    "risk",
    "How much damage could this request do if it were malicious or malformed?",
    RISK_LEVELS)

STANDARD_QUESTIONS: tuple[Question, ...] = (COMPLEXITY, RISK)

#: Routes named after the complexity levels, so the mapping is the identity and
#: nothing has to be configured to connect them.
#:
#: `reasoning` is the conservative route, which means an abstention costs money.
#: That is the intended asymmetry: with no classifier opinion there is no basis
#: to downgrade, so the node takes the full-strength path it would have taken
#: with no classifier installed. Downgrading requires positive evidence that a
#: cheaper route suffices. A deployment preferring a cheaper default declares
#: its own RouteSet -- this one does not get to make that call on their behalf.
STANDARD_ROUTES = RouteSet((
    Route("simple", cost=1, p50_micros=200_000,
          description="small model; lookups, list operations, formatting"),
    Route("medium", cost=4, p50_micros=600_000,
          description="mid model; ordinary tool calls"),
    Route("complex", cost=12, p50_micros=1_500_000,
          description="large model; multi-step or ambiguous work"),
    Route("reasoning", cost=40, p50_micros=6_000_000, conservative=True,
          description="reasoning model; the default when nothing is known"),
))

# ── default tier-0 rules ──────────────────────────────────────────────────
#
# Small on purpose. These demonstrate the shape and cover the cases every
# deployment shares; they are not a policy. An operator's own tool names are
# where the real signal is, and rules beat a model there on every axis that
# matters -- cost, latency, and being able to read why.


def _has(token: str):
    return lambda f: token in f


def _any(*tokens: str):
    return lambda f: any(t in f for t in tokens)


DEFAULT_RULES: tuple[Rule, ...] = (
    # List and schema operations are reads with a bounded result shape. There
    # is nothing for a model to weigh here.
    ("complexity", _any("scp:mcp:tools/list", "scp:mcp:resources/list",
                        "scp:mcp:prompts/list", "scp:mcp:tasks/list"),
     "simple"),
    ("risk", _any("scp:mcp:tools/list", "scp:mcp:resources/list",
                  "scp:mcp:prompts/list", "scp:mcp:tasks/list"), "low"),

    # An argument that names a command or a script is the highest-risk shape a
    # tool call takes, and it is identifiable from the KEY alone -- no value
    # ever has to reach a model to establish it. This is the clearest case for
    # why tier 0 exists.
    ("risk", _any("cmd:str", "command:str", "script:str", "shell:str",
                  "exec:str"), "critical"),
)


def default_cascade(rules: Sequence[Rule] = DEFAULT_RULES) -> Cascade:
    """A cascade from the environment, with the default rules in tier 0."""
    return Cascade.from_env(rules)


_SHARED: Optional[Cascade] = None


def classify(*, server: str = "", tool: str = "", method: str = "",
             scope: str = "", arguments: Optional[dict[str, Any]] = None,
             tier: str = "", cascade: Optional[Cascade] = None,
             questions: Sequence[Question] = STANDARD_QUESTIONS,
             budget_micros: Optional[int] = None) -> Advice:
    """
    Classify one request and return advice. Never raises.

    Takes the request's structural fields rather than a request object, so the
    gateway, a test and a training script can all call it without agreeing on a
    representation -- and so it is visible at every call site exactly what is
    handed to a model. Argument VALUES are reduced to types and shapes by
    `engine.features` and never reach the classifier.

    The returned `Advice` affects route selection and audit detail. It does not
    affect whether the request is permitted; see the module docstring.
    """
    global _SHARED
    try:
        if cascade is None:
            if _SHARED is None:
                _SHARED = default_cascade()
            cascade = _SHARED
        features = extract(server=server, tool=tool, method=method,
                           scope=scope, arguments=arguments, tier=tier)
        verdicts = cascade.ask(features, questions,
                               budget_micros=budget_micros)
        return advise(verdicts, risk_levels=RISK_LEVELS)
    except Exception:
        # The last line of fail-open-on-cost. A caller is mid-decision on a
        # request path; silence is always a valid answer and an exception here
        # would turn an optimization into an outage.
        return Advice.none()
