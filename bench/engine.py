"""
bench.engine — what the decision engine costs, and what it has to beat.

THE CLAIM, STATED HONESTLY
-------------------------
The engine exists to make routing decisions cheaply enough that making them is
worth it. That is a claim about a difference, so this measures two differences
rather than one absolute number:

  1. **Against doing nothing.** Classification is pure overhead on any request
     whose route it does not change. If `classify()` costs more than the
     routing decision saves, the component is a regression, and the only
     defensible position is to measure the overhead rather than assume it is
     small.

  2. **Against the hosted alternative.** LiteLLM's published Jev auto-router
     benchmark measured a 126.81 ms median per classification (p95 231.16 ms),
     against a configured TypeSafe endpoint.

WHAT THE SECOND COMPARISON DOES NOT ESTABLISH
---------------------------------------------
It is not a quality comparison, and reading it as one would be dishonest in
the direction that flatters this code.

Jev's 126.81 ms buys a genuine semantic model, reached over a network, scoring
the request plus up to three prior turns. Tier 0 here is rules over a feature
string, and tier 1 is a linear model over n-grams. On a request whose meaning
genuinely requires semantic understanding, Jev will be right and tier 0 will
abstain -- which is the correct outcome and still costs the full-price route.

So the honest reading is narrower and still useful: **most gateway traffic does
not need semantic understanding to be routed.** A `tools/list` call is a simple
read; a tool with a `cmd` argument is high risk. Both are decidable from
structure, in microseconds, with no model and no egress. The cascade exists so
that the expensive answer is reserved for the fraction of traffic that actually
needs it -- and measuring tier 0 against a hosted semantic model shows the size
of the prize for getting that fraction right, not that one replaces the other.

The residency argument is separate and does not depend on any of these numbers:
a hosted classifier receives the request state, and XCP cannot enforce data
residency on its agents while shipping their request bodies off-node to be
classified. See engine/__init__.py.

    python bench/engine.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.harness import (ENVIRONMENT_CAVEAT, Comparison,  # noqa: E402
                           comparison_table, measure, table)
from engine import (Cascade, DEFAULT_RULES, Deterministic,  # noqa: E402
                    STANDARD_QUESTIONS, STANDARD_ROUTES, classify, extract)

#: From LiteLLM's Jev auto-router benchmark. Quoted, not measured here: this
#: machine has no TypeSafe endpoint and inventing a number for the comparison
#: would be worse than citing someone else's.
JEV_P50_US = 126_810.0
JEV_P95_US = 231_160.0
JEV_SOURCE = "https://docs.litellm.ai/blog/jev-auto-router-benchmark"

N = 6000


def main() -> int:
    feat_list = extract(scope="mcp:tools/list")
    feat_cmd = extract(tool="run", scope="mcp:tools/run",
                       arguments={"cmd": "x", "timeout": 5})
    feat_unknown = extract(tool="obscure", scope="mcp:tools/obscure",
                           arguments={"a": 1, "b": "z", "c": [1, 2, 3]})

    cold = lambda f: Cascade(  # noqa: E731
        [Deterministic(DEFAULT_RULES)], cache_size=0
    ).ask(f, list(STANDARD_QUESTIONS))
    warm = Cascade([Deterministic(DEFAULT_RULES)])
    warm.ask(feat_list, list(STANDARD_QUESTIONS))        # prime

    samples = [
        measure("features only", lambda: extract(
            tool="fetch", scope="mcp:tools/fetch",
            arguments={"url": "https://x/y", "n": 3}), n=N,
            note="bounds and elides argument values"),
        measure("tier 0 answers, cold cache", lambda: cold(feat_list), n=N,
                note="two questions, rules only"),
        measure("tier 0 answers, warm cache",
                lambda: warm.ask(feat_list, list(STANDARD_QUESTIONS)), n=N,
                note="repeat request shape"),
        measure("tier 0 answers risk=critical", lambda: cold(feat_cmd), n=N,
                note="from the argument KEY; no value seen"),
        measure("all tiers abstain", lambda: cold(feat_unknown), n=N,
                note="no models installed; conservative route"),
        measure("classify() end to end", lambda: classify(
            tool="run", scope="mcp:tools/run", arguments={"cmd": "x"}), n=N,
            note="features + cascade + advise"),
        measure("classify() + resolve route", lambda: classify(
            scope="mcp:tools/list").resolve(STANDARD_ROUTES), n=N,
            note="the full decision a gateway makes"),
    ]
    print(table(samples, "Self-hosted cascade, no models installed"))

    # 1. Against doing nothing. The baseline is the work a gateway does anyway.
    baseline = measure("no classification", lambda: None, n=N,
                       note="the alternative: take the default route")
    full = next(s for s in samples if s.name == "classify() + resolve route")
    print(comparison_table([Comparison(baseline=baseline, treatment=full)],
                           "Overhead versus not classifying at all"))

    # 2. Against the hosted alternative.
    print(f"\nVersus a hosted classifier\n{'-' * 26}")
    print(f"  Jev (quoted)                     p50 {JEV_P50_US:>12,.0f} µs"
          f"   p95 {JEV_P95_US:>12,.0f} µs")
    print(f"  this cascade                     p50 {full.p50:>12,.2f} µs"
          f"   p95 {full.p95:>12,.2f} µs")
    print(f"  ratio                                {JEV_P50_US / full.p50:>12,.0f}x"
          f"        {JEV_P95_US / full.p95:>12,.0f}x")
    print(f"  source: {JEV_SOURCE}")
    print("\n  This is a COST comparison, not a quality one. Jev's latency buys")
    print("  a semantic model over a network; tier 0 is rules. On a request")
    print("  that genuinely needs semantics, tier 0 abstains and the node pays")
    print("  full price. The number shows the size of the prize for routing")
    print("  the structurally-decidable majority locally -- nothing more.")

    print(ENVIRONMENT_CAVEAT)

    out = ROOT / "bench" / "engine-results.json"
    out.write_text(json.dumps({
        "samples": [s.to_dict() for s in samples],
        "baseline": baseline.to_dict(),
        "quotedHosted": {"p50Us": JEV_P50_US, "p95Us": JEV_P95_US,
                         "source": JEV_SOURCE,
                         "note": "cost comparison only; see bench/engine.py"},
    }, indent=2) + "\n")
    print(f"\n  wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
