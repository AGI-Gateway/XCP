"""
engine.cascade — ask the cheap thing first, and be willing to not know.

THE IDEA
--------
Kahneman's split is the reason Jev calls itself a System One model: fast
intuitive judgement instead of slow deliberate reasoning. Applied once, that
gets you a classifier in front of an LLM. Applied again, inside the classifier,
it gets you this:

    tier 0  DETERMINISTIC  exact rules              ~1 us      most traffic
    tier 1  LINEAR         fastText                 ~20-200 us the rest
    tier 2  SEMANTIC       SetFit                   ~5-50 ms   rarely
            -              abstain                  0          always available

Each tier runs only when the one above it abstained. The expensive model is a
fallback for genuine ambiguity rather than a thing every request pays for, and
because abstention is free and safe, the cascade can simply stop.

The numbers are the argument. A hosted classifier measured at a 126.81 ms
median (LiteLLM's Jev auto-router benchmark) is three orders of magnitude above
tier 1. XCP already treats a 35x signature-verification penalty as a defect
worth a dependency note in requirements.txt; adding 127 ms and a network round
trip to every request would dwarf everything else the gateway does. A cascade
that resolves most traffic in tier 0 and tier 1 keeps classification beneath
the noise floor of the authorization work it is meant to make cheaper.

WHY THE LATENCY BUDGET IS EXPLICIT
----------------------------------
`ask()` takes `budget_micros`. A tier whose typical cost exceeds the remaining
budget is skipped rather than attempted, because the purpose of this component
is to REDUCE per-request latency, and a classifier that occasionally adds 50 ms
to save a few has failed at its own job. The budget turns that from a hope into
an arithmetic check.

Skipping is an abstention like any other: the caller loses the hint and keeps
the conservative route.

FAIL-OPEN ON COST, FAIL-CLOSED ON AUTHORITY
-------------------------------------------
Every backend is wrapped. A missing package, an unreadable model file, a
corrupt label set, an exception from deep inside a tokenizer -- all become
abstentions with a recorded reason. None of them can raise into the caller's
request path, because the caller is a gateway mid-decision and a classifier
crash must not become a 500 on a request that was perfectly authorizable.

That asymmetry is the whole safety story: losing the classifier costs money and
latency, never a control. Which is only true because of `engine.advice` -- if
advice could widen authority, a backend that "failed" to an optimistic verdict
would be an availability bug on the cost side and a security bug on the other.
"""

from __future__ import annotations

import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional, Sequence

from .features import cache_key
from .questions import Question, QuestionKind, Tier, Verdict, softmax

__all__ = ["Backend", "Deterministic", "FastText", "SetFit", "Cascade",
           "CascadeStats", "DEFAULT_BUDGET_MICROS"]

#: Default per-request classification budget. 2 ms: enough for tier 0 and tier
#: 1 with room to spare, and not enough for tier 2, which must therefore be
#: enabled deliberately with a larger budget rather than wandered into.
DEFAULT_BUDGET_MICROS = 2_000


class Backend:
    """
    One tier. Subclasses implement `_answer`; the wrapper handles timing,
    exceptions and the budget so no subclass can forget to.
    """
    tier: Tier = Tier.NONE
    #: Typical cost, used against the budget BEFORE running. An estimate, not a
    #: measurement: the point is to avoid starting work we cannot afford.
    typical_micros: int = 0
    name: str = "backend"

    @property
    def available(self) -> bool:
        return False

    def _answer(self, features: str, question: Question) -> Verdict:
        raise NotImplementedError

    def ask(self, features: str, question: Question, *,
            remaining_micros: int) -> Verdict:
        if not self.available:
            return Verdict.abstain(
                question, f"{self.name} unavailable", tier=self.tier)
        if self.typical_micros > remaining_micros:
            return Verdict.abstain(
                question,
                f"{self.name} typically costs {self.typical_micros}us and "
                f"{remaining_micros}us of budget remain",
                tier=self.tier)
        t0 = time.perf_counter_ns()
        try:
            v = self._answer(features, question)
        except Exception as e:
            # Deliberately broad. The caller is a gateway mid-decision; a
            # tokenizer raising must not become a 500 on a request that was
            # perfectly authorizable.
            return Verdict.abstain(
                question, f"{self.name} raised {type(e).__name__}: {e}",
                tier=self.tier,
                micros=(time.perf_counter_ns() - t0) // 1000)
        micros = (time.perf_counter_ns() - t0) // 1000
        return Verdict(question_id=v.question_id, kind=v.kind,
                       probabilities=v.probabilities, tier=v.tier,
                       abstained=v.abstained, reason=v.reason, micros=micros)


# ── tier 0 ────────────────────────────────────────────────────────────────

#: A rule: (question_id, predicate over the feature string, answer).
Rule = tuple[str, Callable[[str], bool], str]


class Deterministic(Backend):
    """
    Exact rules, in the operator's own words.

    This tier exists because most of what a gateway wants to know is already
    knowable without a model. `tools/list` is a simple read; a tool named
    `exec` with a `cmd` argument is not. Encoding those as rules is cheaper,
    faster and -- the part that matters -- explainable, which a model's answer
    is not.

    A deployment where this tier answers most traffic should question whether
    it needs the models at all. That is a success, not a disappointment: the
    rules were the cheap answer and they were right.
    """
    tier = Tier.DETERMINISTIC
    typical_micros = 2
    name = "deterministic"

    def __init__(self, rules: Sequence[Rule] = ()) -> None:
        self.rules = tuple(rules)

    @property
    def available(self) -> bool:
        return bool(self.rules)

    def _answer(self, features: str, question: Question) -> Verdict:
        for qid, predicate, answer in self.rules:
            if qid != question.id:
                continue
            if not predicate(features):
                continue
            if answer not in question.answer_set:
                # A rule naming an answer the question does not offer is an
                # operator error worth surfacing, not silently skipping.
                return Verdict.abstain(
                    question,
                    f"rule for {qid!r} answers {answer!r}, which is not in "
                    f"{list(question.answer_set)}", tier=self.tier)
            # Confidence 1.0: a rule is not an estimate. It is the operator
            # asserting the answer, and if the rule is wrong the fix is to the
            # rule, which is a thing a human can read and change.
            return Verdict.answered(question, {answer: 1.0}, self.tier)
        return Verdict.abstain(question, "no rule matched", tier=self.tier)


# ── tier 1 ────────────────────────────────────────────────────────────────

class FastText(Backend):
    """
    A linear model over character and word n-grams.

    Chosen for tier 1 because of what it is, not what it scores: a dot product
    over a hashed feature vector, tens to low hundreds of microseconds on one
    CPU core, a model measured in megabytes, no GPU, no warm-up, no tokenizer
    stack. At that cost a classification is comparable to the signature
    verification already on the hot path, which is the only budget available.

    It generalises poorly beyond the n-grams it saw, which is exactly why there
    is a tier 2 and an abstention beneath it. The feature string from
    `engine.features` suits it well: short, structural, and already normalised.
    """
    tier = Tier.LINEAR
    typical_micros = 200
    name = "fasttext"

    def __init__(self, model_path: str = "", *,
                 label_prefix: str = "__label__",
                 temperature: float = 1.0) -> None:
        self.model_path = model_path or os.getenv("XCP_ENGINE_FASTTEXT", "")
        self.label_prefix = label_prefix
        self.temperature = temperature
        self._model: Any = None
        self._error = ""
        self._load()

    def _load(self) -> None:
        if not self.model_path:
            self._error = "no model path (set XCP_ENGINE_FASTTEXT)"
            return
        if not os.path.exists(self.model_path):
            self._error = f"model not found at {self.model_path}"
            return
        try:
            import fasttext                       # type: ignore[import-untyped]
        except Exception as e:
            self._error = f"fasttext not installed ({type(e).__name__})"
            return
        try:
            self._model = fasttext.load_model(self.model_path)
        except Exception as e:
            self._error = f"could not load model: {type(e).__name__}: {e}"

    @property
    def available(self) -> bool:
        return self._model is not None

    @property
    def error(self) -> str:
        return self._error

    def _answer(self, features: str, question: Question) -> Verdict:
        wanted = question.answer_set
        # k is the full label set: asking for fewer means renormalising over a
        # truncated distribution, which inflates confidence.
        labels, probs = self._model.predict(features, k=len(wanted) + 4)
        scores: dict[str, float] = {}
        for lab, p in zip(labels, probs):
            name = lab[len(self.label_prefix):] if lab.startswith(
                self.label_prefix) else lab
            if name in wanted:
                scores[name] = float(p)
        if not scores:
            return Verdict.abstain(
                question,
                f"model produced no label in {list(wanted)}", tier=self.tier)
        if self.temperature != 1.0:
            scores = softmax(scores, temperature=self.temperature)
        return Verdict.answered(question, scores, self.tier)


# ── tier 2 ────────────────────────────────────────────────────────────────

class SetFit(Backend):
    """
    A sentence-transformer body with a logistic head, fine-tuned contrastively.

    Chosen for tier 2 because of what it costs and what it buys. It needs very
    little labelled data -- a handful of examples per class -- which matters
    for a deployment classifying ITS OWN tool traffic, where nobody has ten
    thousand labelled requests and never will. In exchange it does a
    transformer forward pass: single-digit to tens of milliseconds on CPU, and
    a model two orders of magnitude larger than tier 1's.

    That cost is why it sits behind an abstention rather than in front. Under
    DEFAULT_BUDGET_MICROS it never runs at all; a deployment that wants it must
    raise the budget deliberately, having decided the latency is worth it for
    the fraction of traffic tier 1 cannot resolve.
    """
    tier = Tier.SEMANTIC
    typical_micros = 25_000
    name = "setfit"

    def __init__(self, model_path: str = "") -> None:
        self.model_path = model_path or os.getenv("XCP_ENGINE_SETFIT", "")
        self._model: Any = None
        self._labels: tuple[str, ...] = ()
        self._error = ""
        self._load()

    def _load(self) -> None:
        if not self.model_path:
            self._error = "no model path (set XCP_ENGINE_SETFIT)"
            return
        try:
            from setfit import SetFitModel        # type: ignore[import-untyped]
        except Exception as e:
            self._error = f"setfit not installed ({type(e).__name__})"
            return
        try:
            self._model = SetFitModel.from_pretrained(self.model_path)
            labels = getattr(self._model, "labels", None)
            self._labels = tuple(str(l) for l in labels) if labels else ()
            if not self._labels:
                # Without a label list the columns of predict_proba cannot be
                # named, and guessing the order is how a "high risk" column
                # gets read as "low". Refuse rather than guess.
                self._model = None
                self._error = ("model exposes no `labels`, so probability "
                               "columns cannot be named; refusing to guess "
                               "their order")
        except Exception as e:
            self._error = f"could not load model: {type(e).__name__}: {e}"

    @property
    def available(self) -> bool:
        return self._model is not None

    @property
    def error(self) -> str:
        return self._error

    def _answer(self, features: str, question: Question) -> Verdict:
        raw = self._model.predict_proba([features])
        row = raw[0]
        try:
            values = [float(x) for x in row]
        except TypeError:
            values = [float(x) for x in row.tolist()]
        if len(values) != len(self._labels):
            return Verdict.abstain(
                question,
                f"model returned {len(values)} probabilities for "
                f"{len(self._labels)} labels", tier=self.tier)
        wanted = set(question.answer_set)
        scores = {lab: v for lab, v in zip(self._labels, values)
                  if lab in wanted}
        if not scores:
            return Verdict.abstain(
                question,
                f"model labels {list(self._labels)} do not intersect "
                f"{list(question.answer_set)}", tier=self.tier)
        return Verdict.answered(question, scores, self.tier)


# ── the cascade ───────────────────────────────────────────────────────────

@dataclass
class CascadeStats:
    """
    What the cascade actually cost and who answered.

    Exists so the question "are the models earning their keep" has an answer
    from production rather than from a benchmark. If `by_tier` shows
    DETERMINISTIC answering 95% of traffic, the models are cost without
    benefit.
    """
    asked: int = 0
    answered: int = 0
    abstained: int = 0
    cache_hits: int = 0
    micros_total: int = 0
    by_tier: dict[str, int] = field(default_factory=dict)

    def record(self, v: Verdict, *, cached: bool) -> None:
        self.asked += 1
        self.micros_total += v.micros
        if cached:
            self.cache_hits += 1
        if v.abstained:
            self.abstained += 1
        else:
            self.answered += 1
            self.by_tier[v.tier.value] = self.by_tier.get(v.tier.value, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "asked": self.asked, "answered": self.answered,
            "abstained": self.abstained, "cacheHits": self.cache_hits,
            "microsTotal": self.micros_total,
            "microsMean": (self.micros_total // self.asked) if self.asked else 0,
            "byTier": dict(self.by_tier),
            "answerRate": round(self.answered / self.asked, 4) if self.asked else 0.0,
        }


class Cascade:
    """
    Tiers in ascending cost, first non-abstention wins, result cached.

    The cache is keyed on the feature string plus the question ids, so repeat
    request SHAPES are free. That matters more than it sounds: agent traffic is
    extremely repetitive -- the same tool with the same argument keys, over and
    over -- and the features deliberately discard argument values, so two calls
    to the same tool with different inputs share a key. The cache therefore hits
    on the axis that actually repeats.
    """

    def __init__(self, backends: Sequence[Backend] = (), *,
                 cache_size: int = 4096,
                 budget_micros: int = DEFAULT_BUDGET_MICROS) -> None:
        # Sorted by cost so "cheapest first" is a property of the structure
        # rather than of the caller remembering the order.
        self.backends = tuple(sorted(backends, key=lambda b: b.typical_micros))
        self.cache_size = cache_size
        self.budget_micros = budget_micros
        self._cache: "OrderedDict[str, Verdict]" = OrderedDict()
        self.stats = CascadeStats()

    @property
    def available_tiers(self) -> tuple[str, ...]:
        return tuple(b.name for b in self.backends if b.available)

    def diagnostics(self) -> dict[str, Any]:
        """Why a tier is not running. The first thing to look at when the
        engine is silently doing nothing, which is its safe failure mode and
        therefore an easy one to not notice."""
        return {
            "budgetMicros": self.budget_micros,
            "cacheSize": self.cache_size,
            "backends": [
                {"name": b.name, "tier": b.tier.value,
                 "typicalMicros": b.typical_micros,
                 "available": b.available,
                 "error": getattr(b, "error", "") or None,
                 "withinBudget": b.typical_micros <= self.budget_micros}
                for b in self.backends
            ],
            "stats": self.stats.to_dict(),
        }

    def ask(self, features: str, questions: Sequence[Question], *,
            budget_micros: Optional[int] = None) -> list[Verdict]:
        """
        Answer each question as cheaply as possible, or abstain.

        Never raises. The budget is shared across all questions in the call,
        spent cheapest-tier-first, so one expensive question cannot starve the
        others of the chance to be answered by tier 0.
        """
        budget = self.budget_micros if budget_micros is None else budget_micros
        qids = tuple(q.id for q in questions)
        out: list[Verdict] = []

        for q in questions:
            key = cache_key(features, (q.id,)) if self.cache_size else ""
            if key and key in self._cache:
                cached = self._cache[key]
                self._cache.move_to_end(key)
                hit = Verdict(question_id=cached.question_id, kind=cached.kind,
                              probabilities=cached.probabilities,
                              tier=Tier.CACHED, abstained=cached.abstained,
                              reason=cached.reason, micros=0)
                self.stats.record(hit, cached=True)
                out.append(hit)
                continue

            spent = 0
            reasons: list[str] = []
            verdict: Optional[Verdict] = None
            for b in self.backends:
                v = b.ask(features, q, remaining_micros=max(0, budget - spent))
                spent += v.micros
                if not v.abstained:
                    verdict = v
                    break
                reasons.append(f"{b.name}: {v.reason}")

            if verdict is None:
                verdict = Verdict.abstain(
                    q,
                    "; ".join(reasons) or "no backends configured",
                    tier=Tier.NONE, micros=spent)

            budget = max(0, budget - spent)
            if key:
                self._cache[key] = verdict
                while len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)
            self.stats.record(verdict, cached=False)
            out.append(verdict)

        return out

    @classmethod
    def from_env(cls, rules: Sequence[Rule] = ()) -> "Cascade":
        """
        Build from the environment, including every backend whether or not its
        model is present. An absent backend abstains and reports why in
        `diagnostics()`, which is more useful than a cascade that silently
        lacks a tier nobody can see is missing.
        """
        budget = int(os.getenv("XCP_ENGINE_BUDGET_MICROS",
                               str(DEFAULT_BUDGET_MICROS)))
        return cls([Deterministic(rules), FastText(), SetFit()],
                   budget_micros=budget)
