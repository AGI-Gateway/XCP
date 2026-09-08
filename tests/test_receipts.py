"""
test_receipts.py — proof-of-delivery and evidence-conditioned settlement.

Covers the honest claim: receipts prove the work was *performed* and the output
is *exactly this artifact*; they do not prove quality. So the tests focus on
tamper detection, commitment binding, and the escrow state machine's refusal to
release funds without verified evidence.

    python tests/test_receipts.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from receipts.receipt import (TaskSpec, CallChain, CallRecord, build_receipt,
                              sign_receipt, accept_receipt, verify_receipt,
                              evidence_bundle, verify_bundle, ReceiptError,
                              digest, GENESIS)
from receipts.escrow import Escrow, State, open_escrow, EscrowError

# Well-known Anvil test keys — never use in production.
PAYEE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
PAYER_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"

try:
    from eth_account import Account
    PAYEE_ADDR = Account.from_key(PAYEE_KEY).address
    PAYER_ADDR = Account.from_key(PAYER_KEY).address
    _ETH = True
except ImportError:                                   # pragma: no cover
    _ETH = False
    PAYEE_ADDR = PAYER_ADDR = ""


def _task(**kw) -> TaskSpec:
    base = dict(task_id="t-1", payer_agent=1001, payee_agent=2002,
                description="Summarise 20 filings into a briefing",
                acceptance=["covers all 20", "under 2 pages"],
                amount_minor=25_000, currency="USDC", rail="x402",
                deadline=int(time.time()) + 3600)
    base.update(kw)
    return TaskSpec(**base)


def _chain(n: int = 3) -> CallChain:
    c = CallChain()
    for i in range(n):
        c.record(agent_id=2002, scope="mcp:tools/research.fetch", tool="fetch",
                 args={"url": f"https://example.com/{i}"}, result={"ok": True, "i": i})
    return c


def _delivered(task=None, chain=None, output=None):
    task = task or _task()
    chain = chain or _chain()
    r = build_receipt(task, chain, output or {"briefing": "..."})
    return task, chain, sign_receipt(PAYEE_KEY, r)


# ── commitment ─────────────────────────────────────────────────────────────

def test_task_digest_is_deterministic_and_sensitive():
    a, b = _task(), _task()
    assert a.task_digest == b.task_digest
    assert _task(amount_minor=25_001).task_digest != a.task_digest
    assert _task(description="something else").task_digest != a.task_digest


# ── call chain ─────────────────────────────────────────────────────────────

def test_empty_chain_is_genesis():
    assert CallChain().root == GENESIS and len(CallChain()) == 0


def test_chain_root_changes_per_append():
    c = CallChain()
    roots = [c.root]
    for i in range(3):
        c.record(2002, "mcp:tools/x", "x", {"i": i}, {"r": i})
        roots.append(c.root)
    assert len(set(roots)) == 4, "each append must change the root"
    assert c.verify()


def test_chain_detects_edited_record():
    c = _chain()
    c.records  # snapshot
    c._records[1].result_digest = digest(b"tampered")
    assert not c.verify(), "editing a record must break the chain"


def test_chain_detects_reorder():
    c = _chain()
    c._records[0], c._records[1] = c._records[1], c._records[0]
    assert not c.verify(), "reordering must break the chain"


def test_chain_detects_deletion():
    c = _chain()
    c._records.pop(1)
    assert not c.verify(), "deleting a record must break the chain"


def test_chain_rejects_out_of_order_append():
    c = CallChain()
    try:
        c.append(CallRecord(seq=5, agent_id=1, scope="s", tool="t",
                            args_digest="0x", result_digest="0x", ts=0))
        assert False, "should reject a gap in the sequence"
    except ReceiptError:
        pass


def test_chain_roundtrip_and_root_check():
    c = _chain()
    d = c.to_dict()
    assert CallChain.from_dict(d).root == c.root
    d["root"] = "0xdeadbeef"
    try:
        CallChain.from_dict(d)
        assert False, "should reject a mismatched declared root"
    except ReceiptError:
        pass


# ── receipts ───────────────────────────────────────────────────────────────

def test_valid_receipt_verifies():
    task, chain, r = _delivered()
    assert verify_receipt(r, task, chain, expected_payee_address=PAYEE_ADDR) == []


def test_receipt_bound_to_its_task():
    task, chain, r = _delivered()
    other = _task(task_id="t-2", description="a different job")
    problems = verify_receipt(r, other, chain)
    assert any("different task" in p for p in problems)


def test_amount_tampering_detected():
    task, chain, r = _delivered()
    r.amount_minor = 1                       # payee inflates/deflates after signing
    problems = verify_receipt(r, task, chain)
    assert any("amount mismatch" in p for p in problems)
    assert any("signature" in p.lower() for p in problems), \
        "mutating a signed field must also break the signature"


def test_output_swap_breaks_signature():
    task, chain, r = _delivered()
    r.output_digest = digest(b"a different deliverable")
    problems = verify_receipt(r, task, chain)
    assert problems, "swapping the output must be detected"


def test_chain_root_must_match_receipt():
    task, chain, r = _delivered()
    longer = _chain(5)
    problems = verify_receipt(r, task, longer)
    assert any("call chain root" in p for p in problems)


def test_unsigned_receipt_rejected():
    task = _task(); chain = _chain()
    r = build_receipt(task, chain, {"x": 1})
    assert any("unsigned" in p for p in verify_receipt(r, task, chain))


def test_no_calls_means_no_evidence():
    task = _task()
    empty = CallChain()
    r = sign_receipt(PAYEE_KEY, build_receipt(task, empty, {"x": 1}))
    assert any("no calls recorded" in p for p in verify_receipt(r, task, empty))


def test_late_delivery_flagged():
    past = _task(deadline=int(time.time()) - 10)
    chain = _chain()
    r = sign_receipt(PAYEE_KEY, build_receipt(past, chain, {"x": 1}))
    assert any("deadline" in p for p in verify_receipt(r, past, chain))


def test_acceptance_signature_verifies():
    task, chain, r = _delivered()
    r = accept_receipt(PAYER_KEY, r, task.payer_agent)
    assert r.accepted_by == task.payer_agent
    assert verify_receipt(r, task, chain) == []


def test_build_refuses_broken_chain():
    task = _task(); c = _chain()
    c._records.pop(0)
    try:
        build_receipt(task, c, {"x": 1})
        assert False, "must not build a receipt over a broken chain"
    except ReceiptError:
        pass


# ── evidence bundle ────────────────────────────────────────────────────────

def test_bundle_verifies_offline():
    task, chain, r = _delivered()
    r = accept_receipt(PAYER_KEY, r, task.payer_agent)
    b = evidence_bundle(task, chain, r, output_ref="ipfs://cid")
    assert verify_bundle(b) == []


def test_tampered_bundle_detected():
    task, chain, r = _delivered()
    b = evidence_bundle(task, chain, r)
    b["task"]["amount_minor"] = 1            # arbiter is shown a doctored task
    assert verify_bundle(b), "a doctored bundle must not verify"


def test_bundle_with_stripped_call_detected():
    task, chain, r = _delivered()
    b = evidence_bundle(task, chain, r)
    b["callChain"]["records"].pop()          # hide a call
    assert verify_bundle(b), "removing evidence must be detected"


# ── escrow ─────────────────────────────────────────────────────────────────

def test_escrow_requires_amount_and_distinct_parties():
    for bad in (_task(amount_minor=0), _task(payee_agent=1001)):
        try:
            open_escrow(bad)
            assert False, "should refuse to open"
        except EscrowError:
            pass


def test_happy_path_releases():
    task, chain, r = _delivered()
    esc = open_escrow(task)
    assert esc.state == State.OPEN and not esc.ready_to_release()
    assert esc.deliver(r, chain) == []
    assert esc.state == State.DELIVERED
    assert not esc.ready_to_release(), "delivery alone must not release funds"
    esc.accept(task.payer_agent)
    assert esc.state == State.RELEASED and esc.ready_to_release()


def test_invalid_receipt_is_not_a_delivery():
    task = _task(); chain = _chain()
    r = build_receipt(task, chain, {"x": 1})     # unsigned
    esc = open_escrow(task)
    problems = esc.deliver(r, chain)
    assert problems
    assert esc.state == State.OPEN, "a rejected claim must not advance state"
    assert not esc.ready_to_release()


def test_only_payer_can_accept_or_dispute():
    task, chain, r = _delivered()
    esc = open_escrow(task); esc.deliver(r, chain)
    for fn in (lambda: esc.accept(9999), lambda: esc.dispute(9999, "no")):
        try:
            fn(); assert False, "only the payer may act"
        except EscrowError:
            pass


def test_dispute_then_arbiter_refund():
    task, chain, r = _delivered()
    esc = open_escrow(task, arbiter_agent=777)
    esc.deliver(r, chain)
    esc.dispute(task.payer_agent, "briefing missed 6 filings")
    assert esc.state == State.DISPUTED
    try:
        esc.resolve(888, release=True)
        assert False, "wrong arbiter must be refused"
    except EscrowError:
        pass
    esc.resolve(777, release=False, note="acceptance criteria unmet")
    assert esc.state == State.REFUNDED and esc.refundable()
    assert not esc.ready_to_release()


def test_dispute_requires_a_reason():
    task, chain, r = _delivered()
    esc = open_escrow(task); esc.deliver(r, chain)
    try:
        esc.dispute(task.payer_agent, "   ")
        assert False, "a dispute must state a reason"
    except EscrowError:
        pass


def test_expiry_refunds_without_delivery():
    task = _task(deadline=int(time.time()) + 1)
    esc = open_escrow(task)
    esc.tick(now=int(time.time()) + 10)
    assert esc.state == State.REFUNDED


def test_auto_accept_is_off_by_default():
    task, chain, r = _delivered()
    esc = open_escrow(task)
    esc.deliver(r, chain)
    esc.tick(now=int(time.time()) + 10_000_000)
    assert esc.state == State.DELIVERED, "auto-accept must be opt-in"
    assert not esc.ready_to_release()


def test_auto_accept_when_explicitly_enabled():
    task, chain, r = _delivered()
    esc = open_escrow(task, auto_accept_after=60)
    esc.deliver(r, chain)
    esc.tick(now=r.delivered_at + 61)
    assert esc.state == State.RELEASED


def test_terminal_states_are_sticky():
    task, chain, r = _delivered()
    esc = open_escrow(task); esc.deliver(r, chain); esc.accept(task.payer_agent)
    esc.tick(now=int(time.time()) + 10_000_000)
    assert esc.state == State.RELEASED
    try:
        esc.deliver(r, chain); assert False, "cannot deliver after release"
    except EscrowError:
        pass


def test_escrow_bundle_and_summary():
    task, chain, r = _delivered()
    esc = open_escrow(task); esc.deliver(r, chain); esc.accept(task.payer_agent)
    assert verify_bundle(esc.bundle("https://acme.example/out.pdf")) == []
    s = esc.summary()
    assert s["state"] == "released" and s["readyToRelease"] is True
    assert s["callCount"] == len(chain) and len(s["history"]) >= 3


def test_trust_lattice_requires_receipts_for_settling_tiers():
    from trust.tiers import lattice_table
    for row in lattice_table():
        if row["settlement"] != "none":
            assert row["requires_receipt"], \
                f"{row['cell']} settles but does not require proof-of-delivery"


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
