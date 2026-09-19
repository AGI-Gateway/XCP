#!/usr/bin/env python3
"""
settlement.py — two agents that have never met, transacting on evidence.

Runs the full proof-of-delivery loop:

    commit  →  work (recorded)  →  deliver  →  verify  →  accept  →  release

and then shows what happens when the evidence is tampered with, and what an
arbiter sees in a dispute.

    python examples/settlement.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from receipts import (TaskSpec, CallChain, build_receipt, sign_receipt,
                      accept_receipt, verify_receipt, verify_bundle, open_escrow,
                      State, digest)
from trust.tiers import AgentTier, HumanTier, resolve

# Well-known Anvil test keys. Never use these anywhere real.
PAYEE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
PAYER_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"

PAYER, PAYEE, ARBITER = 1001, 2002, 7777


def line(label: str, value: str = "") -> None:
    print(f"  {label:<26} {value}")


def rule(title: str) -> None:
    print(f"\n\033[1m{title}\033[0m\n{'─' * max(len(title), 58)}")


def main() -> int:
    print("\nXCP agent↔agent settlement — evidence, not trust")
    print("=" * 58)

    # The payer's trust tier decides whether a receipt is even required.
    tpl = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE)
    rule("0 · trust tier")
    line("tier", f"{tpl.cell} · {tpl.name}")
    line("settlement", tpl.settlement)
    line("requires receipt", str(tpl.requires_receipt))

    # ── commit ──
    rule("1 · commit — both sides agree what is being bought")
    task = TaskSpec(
        task_id="brief-2026-07", payer_agent=PAYER, payee_agent=PAYEE,
        description="Summarise 20 filings into a two-page briefing",
        acceptance=["covers all 20 filings", "under 2 pages"],
        amount_minor=25_000, currency="USDC", rail="x402",
        deadline=int(time.time()) + 3600)
    esc = open_escrow(task, arbiter_agent=ARBITER)
    line("task digest", task.task_digest[:26] + "…")
    line("amount", f"{task.amount_minor} {task.currency} via {task.rail}")
    line("escrow state", esc.state.value)

    # ── work ──
    rule("2 · work — every governed call is recorded as it happens")
    chain = CallChain()
    for i in range(4):
        chain.record(agent_id=PAYEE, scope="mcp:tools/research.fetch", tool="fetch",
                     args={"filing": f"10-K-{i}"}, result={"pages": 40 + i})
    chain.record(agent_id=PAYEE, scope="mcp:tools/summarize.run", tool="summarize",
                 args={"n": 4}, result={"pages": 2})
    line("calls recorded", str(len(chain)))
    line("scopes used", ", ".join(chain.scopes_used()))
    line("chain root", chain.root[:26] + "…")
    line("chain intact", str(chain.verify()))

    # ── deliver ──
    rule("3 · deliver — payee signs the evidence")
    output = {"title": "Q2 filings briefing", "pages": 2, "covered": 20}
    receipt = sign_receipt(PAYEE_KEY, build_receipt(task, chain, output))
    problems = esc.deliver(receipt, chain)
    line("output digest", receipt.output_digest[:26] + "…")
    line("verification", "clean" if not problems else problems[0])
    line("escrow state", esc.state.value)
    line("funds releasable?", str(esc.ready_to_release()) + "   ← delivery alone is not enough")

    # ── accept ──
    rule("4 · accept — payer countersigns against the evidence")
    receipt = accept_receipt(PAYER_KEY, receipt, PAYER)
    esc.accept(PAYER)
    line("accepted by", str(receipt.accepted_by))
    line("escrow state", esc.state.value)
    line("funds releasable?", str(esc.ready_to_release()))

    # ── third-party check ──
    rule("5 · independent check — an auditor re-verifies offline")
    bundle = esc.bundle(output_ref="https://acme.example/briefing.pdf")
    line("bundle verifies", "yes" if not verify_bundle(bundle) else "NO")
    line("bundle contains", "task · call chain · signed receipt · output ref")

    # ── tampering ──
    rule("6 · tampering — what the evidence catches")
    import copy
    for label, mutate in [
        ("hide a tool call", lambda b: b["callChain"]["records"].pop()),
        ("inflate the price", lambda b: b.__setitem__(
            "task", {**b["task"], "amount_minor": 250_000})),
        ("swap the deliverable", lambda b: b.__setitem__(
            "receipt", {**b["receipt"], "output_digest": digest(b"other")})),
    ]:
        bad = copy.deepcopy(bundle)
        mutate(bad)
        found = verify_bundle(bad)
        line(label, f"DETECTED — {found[0][:44]}" if found else "MISSED (!)")

    # ── dispute ──
    rule("7 · dispute — the other path")
    task2 = TaskSpec(task_id="brief-2026-08", payer_agent=PAYER, payee_agent=PAYEE,
                     description="Second briefing", acceptance=["covers all 20"],
                     amount_minor=25_000, rail="x402",
                     deadline=int(time.time()) + 3600)
    esc2 = open_escrow(task2, arbiter_agent=ARBITER)
    c2 = CallChain()
    c2.record(PAYEE, "mcp:tools/research.fetch", "fetch", {"filing": "1"}, {"pages": 12})
    r2 = sign_receipt(PAYEE_KEY, build_receipt(task2, c2, {"covered": 6}))
    esc2.deliver(r2, c2)
    esc2.dispute(PAYER, "briefing covered 6 of 20 filings")
    line("state", esc2.state.value)
    line("arbiter sees", f"{len(c2)} call(s) — evidence supports the complaint")
    esc2.resolve(ARBITER, release=False, note="acceptance criteria unmet")
    line("ruling", f"{esc2.state.value} (refunded to payer)")

    print("\n" + "=" * 58)
    print("Receipts prove the work was performed and the artifact is exactly this.")
    print("They do NOT prove the output is good — that stays an explicit decision,")
    print("but one made against evidence anyone can re-check.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
