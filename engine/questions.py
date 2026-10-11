"""
engine.questions — typed questions, and verdicts that cannot be mistaken for
decisions.

THE SHAPE, AND WHY IT IS BORROWED
--------------------------------
TypeSafe's Jev established a good interface for this job: you pass a state and
typed questions, and you get typed answers with calibrated probabilities rather
than prose. Three question types cover almost everything a gateway wants to ask:

    Noul    yes/no            -> probability of yes
    Choice  one of N options   -> a probability per option
    Score   ordered levels     -> a continuous score and a distribution

That interface is worth adopting. What is not worth adopting is where the
inference happens. Jev is a hosted endpoint: the LiteLLM auto-router benchmark
measured a median of 126.81 ms per classification against a configured TypeSafe
URL, sending the current request plus up to three prior turns within an
8,000-character budget.

For XCP specifically that is not a latency problem, it is an authorization
problem. XCP treats data residency as a CONSTRAINT -- a site outside
`Policy.permitted_sites` is inadmissible at any price -- and `xcpsec.egress`
refuses any destination the operator has not declared. A hosted classifier is an
egress destination that receives the full request state. A node cannot both
enforce residency on its agents and ship their request bodies to a third party
to be classified. So in a private federation the only admissible classifier is
one that runs locally, and that is the central reason this module exists rather
than a client for someone else's.

WHAT A VERDICT IS, AND IS NOT
-----------------------------
A `Verdict` is an estimate. It carries calibrated probabilities, the tier that
produced it, and whether the cascade abstained. It is deliberately inert: it has
no method that grants anything, and nothing in the authorization path accepts
one. To affect XCP at all it must first be converted into `engine.advice.Advice`,
which can only express narrowing. See that module.

This split is the whole design. A classifier is a probabilistic component; the
moment its output can widen authority, an attacker who can shift the
classifier's output can shift authority, and prompt injection becomes privilege
escalation. Jev is marketed for exactly that coupling -- "guardrails: checking
risky tool calls before execution" -- and it is the one use this engine refuses
to support. The classifier may tell XCP to look harder. It may never tell XCP
that looking is unnecessary.

ABSTENTION IS A FIRST-CLASS ANSWER
----------------------------------
Every question can come back `abstained`. That happens when confidence is below
threshold, when the margin between the top two options is too narrow, when no
model is installed, or when a backend raised. Abstention costs the optimization
and nothing else: the caller proceeds as though it had never asked. A classifier
that must answer is a classifier that guesses, and a guess that reaches a
routing decision is a cost regression, while a guess that reaches an
authorization decision is a vulnerability.

NO DEPENDENCIES
---------------
This module and the rest of `engine`'s core are standard library only, for the
same reason `protocol.hashing` refuses to substitute a hash: the safety boundary
must not be contingent on an optional package being installed. The model
backends are optional and degrade to abstention; the machinery that stops a
model from widening authority is always present.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Sequence

__all__ = ["QuestionKind", "Question", "Noul", "Choice", "Score", "Verdict",
           "Tier", "MIN_CONFIDENCE", "MIN_MARGIN"]


#: Default confidence floor. Below this a verdict abstains.
#:
#: 0.70 rather than 0.5 because the cost of a wrong routing hint is paid on
#: every request that takes the wrong route, while the cost of abstaining is
#: paid once, as the full-price path the caller would have taken anyway. The
#: asymmetry favours abstaining.
MIN_CONFIDENCE = 0.70

#: Minimum gap between the top two options in a Choice.
#:
#: Confidence alone is not enough. Two options at 0.49 and 0.48 produce a top
#: probability that can clear a low bar while the answer is a coin flip. The
#: margin is what distinguishes "confident" from "least unconfident".
MIN_MARGIN = 0.15


class Tier(str, Enum):
    """
    Which stage of the cascade answered. Recorded so a deployment can see what
    it is paying for: if DETERMINISTIC answers 95% of traffic, the models are
    cost with no benefit and should be switched off.
    """
    DETERMINISTIC = "deterministic"   # exact rules, ~0 cost
    LINEAR = "linear"                 # fastText, microseconds
    SEMANTIC = "semantic"             # SetFit, tens of milliseconds
    CACHED = "cached"                 # a previous verdict for identical input
    NONE = "none"                     # nothing answered


class QuestionKind(str, Enum):
    NOUL = "noul"       # yes/no
    CHOICE = "choice"   # one of N
    SCORE = "score"     # ordered levels


@dataclass(frozen=True)
class Question:
    """
    A question with a closed answer set, known before inference.

    The answer set is closed on purpose. An open-ended answer would have to be
    parsed, and a parser over model output is a second place for the model to
    influence control flow.
    """
    id: str
    kind: QuestionKind
    prompt: str
    #: For CHOICE and SCORE, the permitted answers in order. For SCORE the
    #: order is meaningful (ascending severity); for CHOICE it is not.
    options: tuple[str, ...] = ()
    min_confidence: float = MIN_CONFIDENCE
    min_margin: float = MIN_MARGIN

    def __post_init__(self) -> None:
        if self.kind is QuestionKind.NOUL and self.options:
            raise ValueError("a Noul question has no options; it answers yes/no")
        if self.kind in (QuestionKind.CHOICE, QuestionKind.SCORE):
            if len(self.options) < 2:
                raise ValueError(
                    f"question {self.id!r} of kind {self.kind.value} needs at "
                    f"least two options; with one there is nothing to decide")
            if len(set(self.options)) != len(self.options):
                raise ValueError(f"question {self.id!r} has duplicate options")
        if not 0.0 < self.min_confidence <= 1.0:
            raise ValueError("min_confidence must be in (0, 1]")

    @property
    def answer_set(self) -> tuple[str, ...]:
        if self.kind is QuestionKind.NOUL:
            return ("no", "yes")
        return self.options


def Noul(id: str, prompt: str, *, min_confidence: float = MIN_CONFIDENCE
         ) -> Question:
    """A yes/no question. The verdict carries the probability of yes."""
    return Question(id=id, kind=QuestionKind.NOUL, prompt=prompt,
                    min_confidence=min_confidence)


def Choice(id: str, prompt: str, options: Sequence[str], *,
           min_confidence: float = MIN_CONFIDENCE,
           min_margin: float = MIN_MARGIN) -> Question:
    """One of N unordered options, with a probability for each."""
    return Question(id=id, kind=QuestionKind.CHOICE, prompt=prompt,
                    options=tuple(options), min_confidence=min_confidence,
                    min_margin=min_margin)


def Score(id: str, prompt: str, levels: Sequence[str], *,
          min_confidence: float = MIN_CONFIDENCE) -> Question:
    """
    An ordered rating. The verdict carries a continuous score as well as the
    distribution, because for ordered levels the expected value is more useful
    than the argmax: a request split evenly between "low" and "critical" is not
    a "medium" request, and a caller that sees only the argmax cannot tell those
    apart. `Verdict.bimodal` flags exactly that case.
    """
    return Question(id=id, kind=QuestionKind.SCORE, prompt=prompt,
                    options=tuple(levels), min_confidence=min_confidence,
                    # Ordered levels are adjacent by construction, so a small
                    # top-two gap is normal rather than suspicious. Requiring a
                    # margin here would abstain on most well-formed answers.
                    min_margin=0.0)


@dataclass(frozen=True)
class Verdict:
    """
    An estimate about a request. Inert by construction: see the module
    docstring and `engine.advice`.
    """
    question_id: str
    kind: QuestionKind
    #: answer -> calibrated probability. Empty when abstained.
    probabilities: dict[str, float] = field(default_factory=dict)
    tier: Tier = Tier.NONE
    abstained: bool = True
    reason: str = "no backend answered"
    #: Wall time spent, for the cost accounting that justifies the cascade.
    micros: int = 0

    # ---- reading an answer ----

    @property
    def answer(self) -> Optional[str]:
        """The most probable answer, or None when abstained."""
        if self.abstained or not self.probabilities:
            return None
        return max(self.probabilities.items(), key=lambda kv: kv[1])[0]

    @property
    def confidence(self) -> float:
        """Probability of the top answer. 0.0 when abstained."""
        if self.abstained or not self.probabilities:
            return 0.0
        return max(self.probabilities.values())

    @property
    def margin(self) -> float:
        """Gap between the top two answers. 0.0 when there is only one."""
        if len(self.probabilities) < 2:
            return 0.0
        top = sorted(self.probabilities.values(), reverse=True)
        return top[0] - top[1]

    @property
    def yes(self) -> Optional[bool]:
        """For a Noul: True, False, or None when abstained."""
        if self.kind is not QuestionKind.NOUL:
            raise TypeError(f"{self.question_id!r} is {self.kind.value}, not a Noul")
        a = self.answer
        return None if a is None else a == "yes"

    def p_yes(self) -> float:
        """Probability of yes for a Noul. 0.0 when abstained -- NOT 0.5.

        An abstention is not a 50/50 belief, it is the absence of a belief, and
        returning 0.5 would let a caller treat "I do not know" as "it is as
        likely as not" and then threshold it.
        """
        if self.kind is not QuestionKind.NOUL:
            raise TypeError(f"{self.question_id!r} is not a Noul")
        return 0.0 if self.abstained else self.probabilities.get("yes", 0.0)

    def expected(self, levels: Sequence[str]) -> Optional[float]:
        """
        Expected level index for a Score, in [0, len(levels)-1].

        None when abstained. This is the "continuous score": for ordered levels
        it carries information the argmax discards.
        """
        if self.kind is not QuestionKind.SCORE:
            raise TypeError(f"{self.question_id!r} is not a Score")
        if self.abstained or not self.probabilities:
            return None
        total = sum(self.probabilities.get(l, 0.0) for l in levels)
        if total <= 0:
            return None
        return sum(i * self.probabilities.get(l, 0.0)
                   for i, l in enumerate(levels)) / total

    def bimodal(self, levels: Sequence[str], *, threshold: float = 0.25
                ) -> bool:
        """
        True when probability mass sits at both ends rather than in the middle.

        A request the model thinks is either trivial or critical is not a
        medium-risk request, and treating the expected value as a severity
        would land exactly between two answers that are both wrong. A caller
        that sees this should abstain from optimizing and take the default path.
        """
        if self.kind is not QuestionKind.SCORE or self.abstained:
            return False
        return _is_bimodal(self.probabilities, levels, threshold)

    # ---- construction ----

    @classmethod
    def abstain(cls, question: Question, reason: str, *,
                tier: Tier = Tier.NONE, micros: int = 0) -> "Verdict":
        return cls(question_id=question.id, kind=question.kind,
                   probabilities={}, tier=tier, abstained=True,
                   reason=reason, micros=micros)

    @classmethod
    def answered(cls, question: Question, probabilities: dict[str, float],
                 tier: Tier, *, micros: int = 0) -> "Verdict":
        """
        Build a verdict, abstaining if it fails the question's own thresholds.

        The thresholds are applied HERE rather than left to the caller, so a
        backend cannot return a low-confidence answer that a caller forgets to
        check. The only way to get a non-abstained verdict is to clear the bar.
        """
        unknown = set(probabilities) - set(question.answer_set)
        if unknown:
            # A backend answering outside the closed answer set is a bug in the
            # backend, and silently dropping the extra labels would renormalise
            # the distribution around an answer the question did not offer.
            return cls.abstain(
                question,
                f"backend returned answers outside the question's set: "
                f"{sorted(unknown)}", tier=tier, micros=micros)

        clean = {k: float(v) for k, v in probabilities.items() if v > 0.0}
        total = sum(clean.values())
        if total <= 0.0:
            return cls.abstain(question, "backend returned no mass",
                               tier=tier, micros=micros)
        clean = {k: v / total for k, v in clean.items()}

        top = max(clean.values())

        if question.kind is QuestionKind.SCORE:
            # A Score is gated differently, and getting this wrong is easy.
            #
            # For a Noul or a Choice the argmax IS the answer, so a floor on it
            # is the right gate. For an ordered Score the DISTRIBUTION is the
            # answer -- `expected()` is the deliverable and the argmax throws
            # information away -- and probability mass legitimately spreads
            # across adjacent levels. {low: 0.55, medium: 0.45} is a perfectly
            # informative risk estimate whose top probability never reaches a
            # 0.70 floor.
            #
            # An argmax floor here is also actively harmful: it makes bimodality
            # undetectable. A distribution split 0.45/0.45 between "low" and
            # "critical" is exactly the case a caller most needs told about,
            # and it is the case an argmax floor rejects first.
            #
            # So the gate is interpretability: the distribution must be either
            # CONCENTRATED (most mass within one level of the top, so the
            # expected value means something) or clearly BIMODAL (mass at both
            # ends, which `advise()` escalates on). A flat distribution is
            # neither, and that is the only Score shape worth abstaining on.
            levels = question.options
            if not _interpretable(clean, levels, question.min_confidence):
                return cls.abstain(
                    question,
                    f"distribution is neither concentrated (>= "
                    f"{question.min_confidence:.2f} within one level of the "
                    f"top) nor bimodal; a flat spread over "
                    f"{list(levels)} carries no usable severity",
                    tier=tier, micros=micros)
        elif top < question.min_confidence:
            return cls.abstain(
                question,
                f"confidence {top:.3f} below floor {question.min_confidence:.2f}",
                tier=tier, micros=micros)

        if len(clean) >= 2 and question.min_margin > 0.0:
            ordered = sorted(clean.values(), reverse=True)
            gap = ordered[0] - ordered[1]
            if gap < question.min_margin:
                return cls.abstain(
                    question,
                    f"margin {gap:.3f} below floor {question.min_margin:.2f}; "
                    f"the top answer is the least unconfident one, not a "
                    f"confident one",
                    tier=tier, micros=micros)

        return cls(question_id=question.id, kind=question.kind,
                   probabilities=clean, tier=tier, abstained=False,
                   reason="", micros=micros)

    # ---- recording ----

    def to_observation(self) -> dict[str, Any]:
        """
        The form that goes into the decision record.

        Named `observation` rather than `decision` deliberately, and consumed
        by receipts as tainted data. If a refusal's reason ever cites one of
        these, classification has become authorization -- which
        tests/test_engine.py asserts against.
        """
        return {
            "questionId": self.question_id,
            "kind": self.kind.value,
            "tier": self.tier.value,
            "abstained": self.abstained,
            "answer": self.answer,
            "confidence": round(self.confidence, 4),
            "margin": round(self.margin, 4),
            "micros": self.micros,
            "reason": self.reason or None,
            "tainted": True,
        }


def _is_bimodal(probs: dict[str, float], levels: Sequence[str],
                threshold: float = 0.25) -> bool:
    """
    Mass at both ends and little in between.

    A module-level function rather than only a Verdict method, because
    `Verdict.answered` needs the answer before a Verdict exists -- and having
    two implementations of "is this bimodal" is how the gate and the reported
    flag would come to disagree.
    """
    if len(levels) < 3:
        return False
    lo = probs.get(levels[0], 0.0)
    hi = probs.get(levels[-1], 0.0)
    mid = sum(probs.get(l, 0.0) for l in levels[1:-1])
    return lo >= threshold and hi >= threshold and mid < max(lo, hi)


def _interpretable(probs: dict[str, float], levels: Sequence[str],
                   floor: float) -> bool:
    """
    Whether an ordered distribution carries a usable reading.

    Concentrated: at least `floor` of the mass lies within one level of the
    top, so the expected value is a real severity rather than an average of
    disagreement.

    Bimodal: mass at both extremes. Not concentrated, but highly informative --
    the caller is told the model cannot tell trivial from critical, which is a
    reason to spend more rather than to guess.

    Neither means flat, and a flat severity is no severity.
    """
    if not probs or not levels:
        return False
    if _is_bimodal(probs, levels):
        return True
    index = {l: i for i, l in enumerate(levels)}
    top = max(probs.items(), key=lambda kv: kv[1])[0]
    if top not in index:
        return False
    centre = index[top]
    window = sum(p for l, p in probs.items()
                 if l in index and abs(index[l] - centre) <= 1)
    return window >= floor


def softmax(scores: dict[str, float], *, temperature: float = 1.0
            ) -> dict[str, float]:
    """
    Scores to a distribution, numerically stable.

    Temperature is a calibration knob, not a confidence knob: >1 flattens an
    overconfident model so its probabilities mean what they say. See
    engine.calibration, which fits it rather than guessing.
    """
    if not scores:
        return {}
    if temperature <= 0:
        raise ValueError("temperature must be positive")
    hi = max(scores.values())
    exp = {k: math.exp((v - hi) / temperature) for k, v in scores.items()}
    total = sum(exp.values())
    return {k: v / total for k, v in exp.items()}
