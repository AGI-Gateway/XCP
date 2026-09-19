"""
test_transport.py — paid routing, and the privacy boundary it must not breach.

Two properties carry this design:
  · a node cannot bill for traffic nobody signed for
  · paying per route must not publish who routed to whom

    python tests/test_transport.py
"""
from __future__ import annotations

import sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from federation.transport import (TransportReceipt, EpochCommitment, RoutingLedger,
                                  RouteClass, sign_receipt, verify_receipt,
                                  merkle_root, merkle_proof, verify_proof,
                                  bucket_count, prove_bad_signature,
                                  prove_not_in_tree, prove_double_claim,
                                  prove_total_mismatch, TransportError)

PAYER = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
OTHER = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
NODE = "0x" + "ab" * 32


def _r(rid="r1", price=100, epoch=1, node=NODE, cls=RouteClass.A2T):
    return TransportReceipt(route_id=rid, node_id=node, payer_agent=42001,
                            route_class=cls, price_minor=price, epoch=epoch,
                            scope="mcp:tools/search", peer_hint="acme.example",
                            ts=int(time.time()))


def _signed(**kw):
    return sign_receipt(PAYER, _r(**kw))


# ── a node cannot mint its own revenue ─────────────────────────────────────

def test_signed_receipt_verifies():
    assert verify_receipt(_signed(), expected_node=NODE) == []


def test_unsigned_receipt_is_not_billable():
    assert any("unsigned" in p for p in verify_receipt(_r()))


def test_node_cannot_alter_the_price_after_signing():
    r = _signed(price=100)
    r.price_minor = 100_000
    assert verify_receipt(r), "mutating a signed field must break the signature"


def test_receipt_is_bound_to_one_node():
    r = _signed()
    assert any("different node" in p for p in
               verify_receipt(r, expected_node="0x" + "cd" * 32))


def test_ledger_refuses_unsigned_and_duplicate_routes():
    led = RoutingLedger(node_id=NODE)
    assert led.record(_r()) != []                       # unsigned
    assert led.record(_signed(rid="a")) == []
    assert any("already claimed" in p for p in led.record(_signed(rid="a")))


def test_cannot_record_into_a_committed_epoch():
    led = RoutingLedger(node_id=NODE)
    led.record(_signed(rid="a", epoch=5))
    led.commit(5)
    assert any("already committed" in p for p in led.record(_signed(rid="b", epoch=5)))


# ── the privacy boundary ───────────────────────────────────────────────────

def test_commitment_publishes_totals_not_topology():
    """
    The whole point: paying per route must not reveal who routed to whom.
    """
    led = RoutingLedger(node_id=NODE)
    for i in range(5):
        led.record(_signed(rid=f"r{i}", price=10))
    c = led.commit(1)
    blob = c.to_dict()
    flat = str(blob)
    assert "acme.example" not in flat, "counterparty leaked into the commitment"
    assert "mcp:tools/search" not in flat, "scope leaked into the commitment"
    assert "42001" not in flat, "payer identity leaked into the commitment"
    assert set(blob) == {"node_id", "epoch", "root", "route_count",
                         "total_minor", "currency", "spec_version"}


def test_leaf_excludes_scope_and_counterparty():
    """Even someone who later obtains a leaf learns nothing about the workload."""
    a = _signed(rid="x")
    b = _signed(rid="x")
    b.scope, b.peer_hint = "pay:x402/transfer", "someone-else.example"
    assert a.leaf == b.leaf, "scope/peer must not be in the billable payload"


def test_reveals_is_honest_about_the_residual_leak():
    led = RoutingLedger(node_id=NODE)
    led.record(_signed())
    r = led.commit(1).reveals()
    assert "route count" in r["public"]
    assert "counterparties" in r["private"]
    assert "volume" in r["residualLeak"]


def test_bucketing_blunts_the_volume_signal():
    led = RoutingLedger(node_id=NODE)
    for i in range(947):
        led.record(_signed(rid=f"r{i}", price=1))
    c = led.commit(1, bucket=100)
    assert c.route_count == 1000, "count should round up to a bucket"
    assert c.total_minor == 947, "the amount owed stays exact"
    assert bucket_count(1, 100) == 100 and bucket_count(101, 100) == 200


def test_disclosure_reveals_exactly_one_route():
    led = RoutingLedger(node_id=NODE)
    for i in range(6):
        led.record(_signed(rid=f"r{i}", price=5))
    led.commit(1)
    d = led.prove(1, "r3")
    assert d["receipt"]["routeId"] == "r3"
    assert verify_proof(d["leaf"], d["proof"], d["root"])
    assert "r5" not in str(d), "disclosing one route must not expose the others"


# ── merkle machinery ───────────────────────────────────────────────────────

def test_merkle_proofs_round_trip_at_odd_sizes():
    for n in (1, 2, 3, 5, 8, 13):
        leaves = [merkle_root([str(i)]) if False else f"0x{i:064x}" for i in range(n)]
        root = merkle_root(leaves)
        for leaf in leaves:
            assert verify_proof(leaf, merkle_proof(leaves, leaf), root), n


def test_proof_for_a_foreign_leaf_fails():
    leaves = [f"0x{i:064x}" for i in range(4)]
    root = merkle_root(leaves)
    assert not verify_proof(f"0x{99:064x}", merkle_proof(leaves, leaves[0]), root)


# ── fraud proofs ───────────────────────────────────────────────────────────

def test_forged_signature_is_provable():
    led = RoutingLedger(node_id=NODE)
    led.record(_signed(rid="a"))
    led.commit(1)
    d = led.prove(1, "a")
    assert not prove_bad_signature(d), "an honest receipt must not look fraudulent"
    d["payerAddress"] = "0x0000000000000000000000000000000000000001"
    assert prove_bad_signature(d), "a mismatched payer must be provable"


def test_leaf_outside_the_tree_is_provable():
    led = RoutingLedger(node_id=NODE)
    for i in range(4):
        led.record(_signed(rid=f"r{i}"))
    led.commit(1)
    d = led.prove(1, "r0")
    assert not prove_not_in_tree(d)
    d["leaf"] = f"0x{7:064x}"
    assert prove_not_in_tree(d)


def test_double_claiming_across_epochs_is_provable():
    """A node splits the same route across two epochs to bill it twice."""
    led = RoutingLedger(node_id=NODE)
    led.record(_signed(rid="dup", epoch=1)); c1 = led.commit(1)
    led.claimed_routes.discard("dup")            # simulate the cheat
    led.record(_signed(rid="dup", epoch=2)); c2 = led.commit(2)
    assert prove_double_claim(c1, c2, led.prove(1, "dup"), led.prove(2, "dup"))


def test_inflated_total_is_provable():
    led = RoutingLedger(node_id=NODE)
    for i in range(3):
        led.record(_signed(rid=f"r{i}", price=10))
    c = led.commit(1)
    assert not prove_total_mismatch(c, led.receipts[1])
    c.total_minor = 999_999
    assert prove_total_mismatch(c, led.receipts[1])


def test_same_epoch_is_not_a_double_claim():
    led = RoutingLedger(node_id=NODE)
    led.record(_signed(rid="a")); c = led.commit(1)
    d = led.prove(1, "a")
    assert not prove_double_claim(c, c, d, d)


# ── earnings ───────────────────────────────────────────────────────────────

def test_earnings_group_by_route_class():
    led = RoutingLedger(node_id=NODE)
    led.record(_signed(rid="a", price=10, cls=RouteClass.A2T))
    led.record(_signed(rid="b", price=20, cls=RouteClass.WRAP))
    led.record(_signed(rid="c", price=30, cls=RouteClass.RELAY))
    e = led.earnings()
    assert e["routes"] == 3 and e["totalMinor"] == 60
    assert e["byClass"] == {"a2t": 1, "wrap": 1, "relay": 1}


def test_committing_an_empty_epoch_is_refused():
    try:
        RoutingLedger(node_id=NODE).commit(9); assert False
    except TransportError:
        pass


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
