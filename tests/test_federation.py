"""
test_federation.py — a web of nodes with no central authority.

The invariants that make this safe rather than just decentralised:
  · a node is verified against the cert its own domain served — no third party
  · transitive trust DECAYS and is CAPPED, so one bad node can't launder trust
  · vouching from an untrusted introducer is ignored
  · revocation spreads by gossip and needs no chain
  · nodes may disagree; nothing requires consensus

    python tests/test_federation.py
"""
from __future__ import annotations

import sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from federation import (NodeRecord, Attestation, Federation, PeerTrust,
                        verify_node_record, digest, FederationError,
                        NODE_RECORD_PATH)

CERT_A = b"--fake-der-a--"
CERT_B = b"--fake-der-b--"
ID_A, ID_B = digest(CERT_A), digest(CERT_B)


def _rec(domain="node-a.example", node_id=None, **kw):
    return NodeRecord(domain=domain, node_id=node_id or ID_A,
                      gateway_url=f"https://{domain}", **kw)


def _fed(domain="me.example"):
    return Federation(self_domain=domain, self_node_id=digest(b"me"))


def _att(subject, subject_id, issuer, issuer_id, trust=PeerTrust.VERIFIED, ttl=3600):
    now = int(time.time())
    return Attestation(subject_domain=subject, subject_node_id=subject_id,
                       issuer_domain=issuer, issuer_node_id=issuer_id,
                       trust=trust, issued_at=now, expires_at=now + ttl)


# ── node records + verification ────────────────────────────────────────────

def test_record_validates():
    assert _rec().validate() == []
    assert NodeRecord(domain="", node_id=ID_A, gateway_url="https://x").validate()
    assert NodeRecord(domain="a.example", node_id="nope",
                      gateway_url="https://a.example").validate()
    assert NodeRecord(domain="a.example", node_id=ID_A,
                      gateway_url="http://a.example").validate(), "must require https"


def test_verification_needs_no_third_party():
    rec = _rec("node-a.example", ID_A)
    assert verify_node_record(rec, CERT_A, "node-a.example") == []


def test_record_served_from_wrong_domain_is_rejected():
    rec = _rec("node-a.example", ID_A)
    problems = verify_node_record(rec, CERT_A, "attacker.example")
    assert any("served from" in p for p in problems)


def test_node_id_must_match_the_tls_certificate():
    rec = _rec("node-a.example", ID_A)
    problems = verify_node_record(rec, CERT_B, "node-a.example")
    assert any("does not match the certificate" in p for p in problems)


def test_no_chain_required_by_default():
    r = _rec()
    assert r.chain_id == 0 and r.session_registry == ""
    assert _fed().summary()["chainRequired"] is False


def test_well_known_path_is_stable():
    assert NODE_RECORD_PATH == "/.well-known/xcp-node.json"


# ── transitive trust ───────────────────────────────────────────────────────

def test_direct_peer_has_full_weight():
    f = _fed()
    p = f.add_verified_peer("b.example", ID_B, "https://b.example")
    assert p.hops == 1 and p.weight == 1.0
    assert f.trust_of("b.example")[0] == PeerTrust.VERIFIED


def test_trust_decays_per_hop():
    f = _fed()
    f.add_verified_peer("b.example", ID_B)
    f.ingest_attestation(_att("c.example", digest(b"c"), "b.example", ID_B))
    _, w2 = f.trust_of("c.example")
    assert 0 < w2 < 1.0, "a peer-of-a-peer must be trusted less than a peer"
    f.ingest_attestation(_att("d.example", digest(b"d"), "c.example", digest(b"c")))
    _, w3 = f.trust_of("d.example")
    assert 0 < w3 < w2, "trust must keep decaying with distance"


def test_trust_is_capped_by_hops():
    f = _fed()
    f.add_verified_peer("h1.example", digest(b"h1"))
    prev = "h1.example"
    for i in range(2, 8):
        cur = f"h{i}.example"
        f.ingest_attestation(_att(cur, digest(cur.encode()), prev,
                                  digest(prev.encode())))
        prev = cur
    assert max(p.hops for p in f.peers.values()) <= f.max_hops
    assert f.trust_of("h7.example")[0] == PeerTrust.UNKNOWN


def test_untrusted_introducer_is_ignored():
    f = _fed()
    # nobody vouched for the issuer, so its vouching means nothing
    assert f.ingest_attestation(_att("c.example", digest(b"c"),
                                     "stranger.example", digest(b"s"))) is None
    assert f.trust_of("c.example")[0] == PeerTrust.UNKNOWN


def test_compromised_node_cannot_launder_full_trust():
    f = _fed()
    f.add_verified_peer("b.example", ID_B)
    # b goes bad and vouches for an attacker at the highest trust it can claim
    f.ingest_attestation(_att("evil.example", digest(b"evil"), "b.example", ID_B,
                              trust=PeerTrust.ATTESTED))
    trust, weight = f.trust_of("evil.example")
    assert weight < 1.0, "introduced trust must never equal direct trust"
    direct = f.trust_of("b.example")[1]
    assert weight < direct


def test_expired_attestation_ignored():
    f = _fed()
    f.add_verified_peer("b.example", ID_B)
    assert f.ingest_attestation(_att("c.example", digest(b"c"), "b.example",
                                     ID_B, ttl=-10)) is None


def test_self_vouching_ignored():
    f = _fed("me.example")
    f.add_verified_peer("b.example", ID_B)
    assert f.ingest_attestation(_att("me.example", digest(b"me"), "b.example",
                                     ID_B)) is None


def test_direct_relationship_beats_introduction():
    f = _fed()
    f.add_verified_peer("b.example", ID_B)
    f.add_verified_peer("c.example", digest(b"c"))          # direct
    f.ingest_attestation(_att("c.example", digest(b"c"), "b.example", ID_B))
    assert f.peers["c.example"].hops == 1, "must not downgrade a direct peer"
    assert f.trust_of("c.example")[1] == 1.0


# ── revocation without a chain ─────────────────────────────────────────────

def test_revocation_marks_and_returns_gossip_targets():
    f = _fed()
    f.add_verified_peer("b.example", ID_B, "https://b.example")
    f.add_verified_peer("c.example", digest(b"c"), "https://c.example")
    targets = f.revoke(ID_B)
    assert f.trust_of("b.example")[0] == PeerTrust.UNKNOWN
    assert "https://c.example" in targets
    assert "https://b.example" not in targets, "don't gossip to the revoked node"


def test_revocation_only_accepted_from_a_trusted_peer():
    f = _fed()
    f.add_verified_peer("b.example", ID_B)
    assert f.ingest_revocation(digest(b"x"), "stranger.example") is False
    assert f.ingest_revocation(digest(b"x"), "b.example") is True


def test_revoked_node_cannot_be_reintroduced():
    f = _fed()
    f.add_verified_peer("b.example", ID_B)
    evil = digest(b"evil")
    f.revoke(evil)
    assert f.ingest_attestation(_att("evil.example", evil, "b.example", ID_B)) is None


# ── bootstrap + independence ───────────────────────────────────────────────

def test_bootstrap_from_any_seed_excludes_self():
    f = _fed("me.example")
    rec = _rec(seed_peers=["a.example", "me.example", "b.example"])
    assert f.bootstrap_targets(rec) == ["a.example", "b.example"]


def test_two_nodes_may_disagree():
    """No consensus requirement — divergent views are legitimate."""
    f1, f2 = _fed("one.example"), _fed("two.example")
    f1.add_verified_peer("x.example", digest(b"x"))
    f2.revoke(digest(b"x"))
    assert f1.trust_of("x.example")[0] != PeerTrust.UNKNOWN
    assert f2.trust_of("x.example")[0] == PeerTrust.UNKNOWN


def test_reachable_is_ordered_and_filters_revoked():
    f = _fed()
    f.add_verified_peer("b.example", ID_B)
    f.ingest_attestation(_att("c.example", digest(b"c"), "b.example", ID_B))
    f.add_verified_peer("d.example", digest(b"d"))
    f.revoke(digest(b"d"))
    got = [p.domain for p in f.reachable()]
    assert "d.example" not in got
    assert got[0] in ("b.example",), "direct peers rank above introduced ones"


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
