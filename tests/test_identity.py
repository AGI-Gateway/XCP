"""
test_identity.py — a node identity that survives certificate rotation.

Identity used to be the certificate footprint, which made it an ephemeral
credential: every Let's Encrypt renewal produced a stranger, orphaned peers, and
invalidated attestations others had issued. These tests pin the fix.

    python tests/test_identity.py
"""
from __future__ import annotations

import sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from federation.identity import (NodeIdentity, CertBinding, BindingSet,
                                 sign_binding, verify_binding, rotate, accept,
                                 node_id_from_address, IdentityError,
                                 ROTATION_GRACE)
from federation import Federation, FederationError

C1 = "0x" + "11" * 32
C2 = "0x" + "22" * 32
C3 = "0x" + "33" * 32
DOM = "a.example"


def _id():
    return NodeIdentity.generate()


# ── the property the whole change exists for ───────────────────────────────

def test_identity_survives_rotation():
    i = _id()
    bs1 = rotate(i, C1, domain=DOM)
    bs2 = rotate(i, C2, domain=DOM, existing=bs1)
    bs3 = rotate(i, C3, domain=DOM, existing=bs2)
    assert bs1.current.node_id == bs3.current.node_id == i.node_id, \
        "renewing a certificate must not change who the node is"


def test_node_id_is_derived_from_the_key_not_the_cert():
    i = _id()
    assert i.node_id == node_id_from_address(i.address)
    assert C1 not in i.node_id and C2 not in i.node_id


def test_rotation_is_not_a_new_peer():
    """Trust, hops and any attestation that introduced a peer must survive."""
    i = _id()
    fed = Federation(self_domain="me.example", self_node_id="0x" + "ff" * 32)
    fed.add_verified_peer(DOM, i.node_id, "https://a.example", sequence=1)
    before = fed.trust_of(DOM)
    assert fed.note_rotation(DOM, i.node_id, sequence=2) is True
    assert fed.trust_of(DOM) == before, "a renewal must not reset trust"
    assert fed.peers[DOM].sequence == 2


# ── binding verification ───────────────────────────────────────────────────

def test_valid_binding_verifies():
    i = _id()
    b = sign_binding(i, C1, domain=DOM, sequence=1)
    assert verify_binding(b, expected_node_id=i.node_id, expected_domain=DOM,
                          tls_footprint=C1) == []


def test_binding_must_match_the_live_certificate():
    i = _id()
    b = sign_binding(i, C1, domain=DOM, sequence=1)
    assert any("presented over TLS" in p for p in
               verify_binding(b, tls_footprint=C2))


def test_binding_is_bound_to_its_domain():
    i = _id()
    b = sign_binding(i, C1, domain=DOM, sequence=1)
    assert any("served from" in p for p in
               verify_binding(b, expected_domain="attacker.example",
                              tls_footprint=C1))


def test_unsigned_binding_is_refused():
    b = CertBinding(node_id="0x" + "ab" * 32, cert_footprint=C1, sequence=1,
                    not_before=0, not_after=int(time.time()) + 99)
    assert any("unsigned" in p for p in verify_binding(b, tls_footprint=C1))


def test_a_third_party_cannot_bind_a_certificate_to_someone_elses_identity():
    victim, attacker = _id(), _id()
    b = sign_binding(attacker, C1, domain=DOM, sequence=1)
    b.node_id = victim.node_id                    # claim to be the victim
    problems = verify_binding(b, expected_node_id=victim.node_id,
                              tls_footprint=C1)
    assert problems, "an attacker must not bind a cert to another identity"


def test_expired_binding_is_refused():
    i = _id()
    b = sign_binding(i, C1, domain=DOM, sequence=1, ttl=10)
    assert any("expired" in p for p in
               verify_binding(b, tls_footprint=C1,
                              now=int(time.time()) + 1000))


def test_tampering_with_a_signed_field_breaks_the_signature():
    i = _id()
    b = sign_binding(i, C1, domain=DOM, sequence=1)
    b.cert_footprint = C2
    assert verify_binding(b, expected_node_id=i.node_id)


# ── the downgrade attack ───────────────────────────────────────────────────

def test_old_binding_cannot_be_replayed_after_rotation():
    """
    Without ordering, an attacker replays a superseded binding to make a peer
    accept a certificate the node has rotated away from — perhaps one whose key
    they stole.
    """
    i = _id()
    bs1 = rotate(i, C1, domain=DOM)
    bs2 = rotate(i, C2, domain=DOM, existing=bs1)
    replay = BindingSet(current=bs1.current)       # attacker serves the old one
    ok, _which, problems = accept(replay, tls_footprint=C1,
                                  expected_node_id=i.node_id,
                                  expected_domain=DOM,
                                  known_sequence=bs2.sequence)
    assert not ok, "a peer must refuse a binding older than one it has seen"
    assert any("replayed" in p or "older than" in p for p in problems)


def test_federation_refuses_a_sequence_regression():
    i = _id()
    fed = Federation(self_domain="me.example", self_node_id="0x" + "ff" * 32)
    fed.add_verified_peer(DOM, i.node_id, sequence=5)
    try:
        fed.add_verified_peer(DOM, i.node_id, sequence=3)
        assert False, "should refuse a downgrade"
    except FederationError:
        pass


def test_note_rotation_rejects_stale_and_foreign_ids():
    i, other = _id(), _id()
    fed = Federation(self_domain="me.example", self_node_id="0x" + "ff" * 32)
    fed.add_verified_peer(DOM, i.node_id, sequence=3)
    assert fed.note_rotation(DOM, i.node_id, 3) is False      # not newer
    assert fed.note_rotation(DOM, other.node_id, 9) is False  # different identity
    assert fed.note_rotation("unknown.example", i.node_id, 9) is False


# ── overlap during a rotation ──────────────────────────────────────────────

def test_previous_certificate_is_accepted_during_the_grace_window():
    """Both certs are briefly live during a renewal; a peer must not alarm."""
    i = _id()
    bs1 = rotate(i, C1, domain=DOM)
    bs2 = rotate(i, C2, domain=DOM, existing=bs1)
    ok, which, notes = accept(bs2, tls_footprint=C1, expected_node_id=i.node_id,
                              expected_domain=DOM)
    assert ok and which == "previous"
    assert any("rotation in progress" in n for n in notes)


def test_only_one_generation_back_is_accepted():
    i = _id()
    bs = rotate(i, C1, domain=DOM)
    bs = rotate(i, C2, domain=DOM, existing=bs)
    bs = rotate(i, C3, domain=DOM, existing=bs)
    ok, _w, _n = accept(bs, tls_footprint=C1, expected_node_id=i.node_id,
                        expected_domain=DOM)
    assert not ok, "a certificate two rotations old must not be accepted"


def test_grace_window_eventually_closes():
    i = _id()
    bs1 = rotate(i, C1, domain=DOM, ttl=100)
    bs2 = rotate(i, C2, domain=DOM, existing=bs1)
    later = int(time.time()) + 100 + ROTATION_GRACE + 10
    ok, _w, _n = accept(bs2, tls_footprint=C1, expected_node_id=i.node_id,
                        expected_domain=DOM, now=later)
    assert not ok, "the previous certificate must stop being accepted"


# ── record-level integration ───────────────────────────────────────────────

def test_record_with_a_binding_verifies_against_a_rotated_cert():
    from federation import NodeRecord, verify_node_record, digest as fdigest
    i = _id()
    der = b"--cert-two--"
    bs = rotate(i, C1, domain=DOM)
    bs = rotate(i, fdigest(der), domain=DOM, existing=bs)
    rec = NodeRecord(domain=DOM, node_id=i.node_id,
                     gateway_url="https://a.example", bindings=bs.to_dict())
    assert verify_node_record(rec, der, DOM) == []
    assert rec.sequence == 2


def test_legacy_record_still_verifies_but_is_flagged():
    from federation import NodeRecord, verify_node_record, digest as fdigest
    der = b"--legacy--"
    rec = NodeRecord(domain=DOM, node_id=fdigest(der),
                     gateway_url="https://a.example")
    assert verify_node_record(rec, der, DOM) == []
    bad = verify_node_record(rec, b"--other--", DOM)
    assert any("legacy" in p for p in bad)


def test_record_rejects_a_footprint_with_no_binding():
    from federation import NodeRecord
    rec = NodeRecord(domain=DOM, node_id="0x" + "ab" * 32,
                     gateway_url="https://a.example", cert_footprint=C1)
    assert any("no signed binding" in p for p in rec.validate())


def test_signing_needs_the_private_key():
    i = NodeIdentity(address="0x" + "ab" * 20)
    try:
        sign_binding(i, C1, domain=DOM, sequence=1); assert False
    except IdentityError:
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
