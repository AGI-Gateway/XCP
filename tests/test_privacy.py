"""
test_privacy.py — erasure that does not break the audit, and does not overclaim.

XCP deliberately holds personal data: the trust lattice is built on knowing which
human an agent acts for. That collides with the right to erasure, because
`CallChain` is designed so removing a record changes the root.

The tests below pin both halves of the resolution: erasure must actually destroy
content, and it must not pretend to have deleted things the operator is legally
obliged to keep.

    python tests/test_privacy.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from privacy import (KeyRing, seal, unseal, commitment_survives, pseudonymise,
                     ShredError, erase, pending_expiry, data_map, CLASSES,
                     classify, erasable, due_for_expiry, Basis, Subject,
                     RetentionError)
from receipts import CallChain, CallRecord, digest as rdigest

NOW = int(time.time())


def _chain_over(sealeds):
    c = CallChain()
    for i, s in enumerate(sealeds):
        c.append(CallRecord(seq=i, agent_id=42001, scope="mcp:tools/fetch",
                            tool="fetch", args_digest=s.commitment,
                            result_digest=rdigest(b"r"), ts=1000 + i))
    return c


# ── the property the whole design rests on ─────────────────────────────────

def test_erasure_destroys_content_but_the_chain_still_verifies():
    ring = KeyRing()
    sealeds = [seal(ring, "sub_a", {"patient": f"P{i}"}) for i in range(4)]
    chain = _chain_over(sealeds)
    root = chain.root
    assert chain.verify() and unseal(ring, sealeds[0])["patient"] == "P0"

    erase(ring, "sub_a", held=[("call_chain", NOW)])

    try:
        unseal(ring, sealeds[0])
        assert False, "content must be unreadable after erasure"
    except ShredError:
        pass
    assert chain.verify(), "erasure must not break the audit chain"
    assert chain.root == root, "the root must not change"
    assert all(commitment_survives(s) for s in sealeds)


def test_a_shredded_subject_cannot_be_silently_revived():
    """Minting a new key would un-erase them without anyone noticing."""
    ring = KeyRing()
    seal(ring, "sub_b", {"x": 1})
    erase(ring, "sub_b", held=[("call_chain", NOW)])
    try:
        seal(ring, "sub_b", {"x": 2})
        assert False, "must refuse to re-key an erased subject"
    except ShredError:
        pass


def test_erasure_is_irreversible_even_for_the_operator():
    ring = KeyRing()
    s = seal(ring, "sub_c", {"secret": "value"})
    erase(ring, "sub_c", held=[("call_chain", NOW)])
    assert ring.is_shredded("sub_c")
    assert "sub_c" not in ring.subjects()
    assert commitment_survives(s), "the commitment is all that should remain"


def test_tampered_ciphertext_is_detected():
    ring = KeyRing()
    s = seal(ring, "sub_d", {"a": 1})
    s.ciphertext = s.ciphertext[:-4] + "AAAA"
    try:
        unseal(ring, s)
        assert False, "AEAD must reject tampering"
    except ShredError:
        pass


# ── erasure must not overclaim ─────────────────────────────────────────────

def test_settled_financial_records_are_not_erased_on_request():
    """
    Art. 17(3)(b)/(e). Deleting records an operator is legally obliged to keep
    is as wrong as refusing every request.
    """
    ring = KeyRing(); ring.key_for("sub_e")
    rep = erase(ring, "sub_e", held=[("settlement_receipt", NOW)])
    assert not rep.complete
    assert "settlement_receipt" not in rep.erased
    r = rep.retained[0]
    assert r.basis == Basis.LEGAL_OBLIGATION.value
    assert r.erased_automatically_at > NOW, "a retention with no end date is not a basis"


def test_the_key_is_kept_while_a_retained_class_must_stay_readable():
    """Destroying it would leave the operator unable to meet the very obligation
    they cited as the reason to keep the data."""
    ring = KeyRing(); ring.key_for("sub_f")
    rep = erase(ring, "sub_f", held=[("call_chain", NOW),
                                     ("settlement_receipt", NOW)])
    assert rep.key_destroyed is False
    assert any("RETAINED" in n for n in rep.notes)


def test_unsettled_receipts_are_erasable():
    """No financial obligation attaches, so the exemption does not apply."""
    ok, _ = erasable("unsettled_receipt")
    assert ok
    blocked, reason = erasable("settlement_receipt")
    assert not blocked and "legal_obligation" in reason


def test_every_refusal_carries_a_basis_and_an_end_date():
    for cid, c in CLASSES.items():
        if c.contains_personal_data and not c.erasable_on_request:
            ok, reason = erasable(cid)
            assert not ok
            assert c.basis.value in reason
            assert c.retention_seconds > 0, f"{cid} refuses erasure with no expiry"
            assert c.note, f"{cid} refuses erasure with no explanation"


def test_report_states_plainly_when_erasure_is_partial():
    ring = KeyRing(); ring.key_for("sub_g")
    rep = erase(ring, "sub_g", held=[("call_chain", NOW),
                                     ("settlement_receipt", NOW)])
    text = rep.human_summary()
    assert "PARTIAL" in text
    assert "Retained, and why" in text
    import json
    json.dumps(rep.to_dict())


def test_an_unknown_class_is_erased_rather_than_kept():
    ring = KeyRing(); ring.key_for("sub_h")
    rep = erase(ring, "sub_h", held=[("mystery_blob", NOW)])
    assert "mystery_blob" in rep.erased
    assert any("unknown class" in n for n in rep.notes)


# ── retention ──────────────────────────────────────────────────────────────

def test_retention_expiry_is_computed_not_assumed():
    old = NOW - 200 * 86400
    due = due_for_expiry([("call_chain", old), ("settlement_receipt", old)], NOW)
    ids = {c for c, _ in due}
    assert "call_chain" in ids, "90-day class should be expired at 200 days"
    assert "settlement_receipt" not in ids, "7-year class should not be"


def test_pending_expiry_reports_what_a_sweep_should_delete():
    rows = pending_expiry([("call_chain", NOW - 200 * 86400)], NOW)
    assert rows and rows[0]["action"] == "delete"


def test_session_bindings_expire_within_the_protocol_cap():
    from federation.identity import ROTATION_GRACE  # noqa: F401
    assert classify("session_binding").retention_seconds <= 7 * 86400


def test_entitlements_are_the_shortest_lived_personal_class():
    """The most directly identifying data should be held the least."""
    ent = classify("entitlements").retention_seconds
    others = [c.retention_seconds for c in CLASSES.values()
              if c.contains_personal_data and c.id not in
              ("entitlements", "session_binding") and c.retention_seconds > 0]
    assert all(ent < o for o in others)


def test_unknown_class_is_rejected_loudly():
    try:
        classify("invented")
        assert False
    except RetentionError as e:
        assert "declared class" in str(e)


# ── the data map ───────────────────────────────────────────────────────────

def test_data_map_is_complete_and_serialisable():
    import json
    m = data_map()
    json.dumps(m)
    assert set(m) >= {"controllerRole", "classes", "personalDataClasses",
                      "erasureExemptions", "transfers", "notLegalAdvice"}
    assert len(m["classes"]) == len(CLASSES)


def test_data_map_names_the_processor_relationship():
    """A node routing for another organisation's users is a processor, and that
    is the thing an adopter's legal team will ask about first."""
    role = data_map()["controllerRole"].lower()
    assert "processor" in role and "controller" in role


def test_data_map_flags_cross_border_transfer():
    assert "transfer" in data_map()["transfers"].lower()


def test_credentials_are_declared_as_not_held():
    c = classify("credential")
    assert "never stored" in c.note.lower() or "do not hold" in c.note.lower()


# ── pseudonymisation is not anonymisation ──────────────────────────────────

def test_pseudonymise_is_stable_and_not_a_name():
    a = pseudonymise("alice@example.com", b"salt")
    assert a == pseudonymise("alice@example.com", b"salt")
    assert "alice" not in a and a.startswith("sub_")
    assert a != pseudonymise("alice@example.com", b"other-salt")


def test_hashing_is_documented_as_insufficient_for_erasure():
    """A hash of personal data is still personal data when it is linkable, so
    digesting a field does not discharge an erasure obligation."""
    src = (ROOT / "privacy" / "shredding.py").read_text().lower()
    assert "pseudonymisation, not anonymisation" in src
    assert "args_digest" in src


# ── regulatory alignment ───────────────────────────────────────────────────

def test_security_audit_meets_the_ai_act_six_month_floor():
    """
    EU AI Act Art. 19 / 26(6) require at least six CALENDAR months. Six calendar
    months can run to 184 days, so a 180-day default sits under the floor while
    looking entirely reasonable. That was a real defect found on review.
    """
    assert classify("security_audit").retention_days >= 184


def test_the_floor_is_not_applied_to_deployments_that_do_not_owe_it():
    """
    Raising everyone's retention to a floor they do not owe trades an AI Act
    finding for a GDPR one: keeping personal data longer than necessary.
    """
    from compliance import reconcile_retention
    for c in reconcile_retention(ai_act_applies=False):
        assert c.resolved
        assert "not applicable" in c.floor_source


def test_retention_conflicts_are_surfaced_not_hidden():
    from compliance import reconcile_retention, unresolved
    conflicts = reconcile_retention(ai_act_applies=True)
    assert conflicts, "the AI Act floor and GDPR ceiling both bind; say so"
    for c in conflicts:
        assert "Art. 5(1)(e)" in c.ceiling_principle
        assert c.guidance
    # call_chain is genuinely below the floor; the tool must not pretend otherwise
    assert any(not c.resolved for c in conflicts), \
        "a reconciliation that always shows green is a sales document"


def test_the_floor_override_is_opt_in_and_never_lowers_retention():
    from compliance import apply_ai_act_floor
    overrides = apply_ai_act_floor()
    for cid, days in overrides.items():
        assert days >= classify(cid).retention_days, "an override must not shorten"
        assert days >= 184


def test_dora_does_not_impose_a_log_floor():
    """A common misreading is importing the AI Act six-month figure into DORA.
    Del. Reg. 2024/1774 Art. 12 leaves the period to the entity."""
    import compliance.frameworks as F
    dora_logs = [c for c in F.CONTROLS
                 if c.framework is F.Framework.DORA and "2024/1774" in c.reference]
    assert dora_logs, "the DORA log-retention clause should be mapped"
    assert "no fixed floor" in dora_logs[0].gap_note.lower()


def test_every_framework_control_states_a_gap():
    """A mapping with no gaps is a sales document, not a compliance artifact."""
    import compliance.frameworks as F
    for c in F.CONTROLS:
        assert c.gap_note, f"{c.framework.value} {c.reference} claims coverage with no caveat"


def test_nothing_claims_to_make_anyone_compliant():
    import compliance.frameworks as F
    src = (ROOT / "compliance" / "frameworks.py").read_text().lower()
    assert "does not make anything compliant" in src
    for c in F.CONTROLS:
        assert c.coverage.value != "compliant"


def test_frameworks_cover_the_regimes_an_adopter_will_ask_about():
    import compliance.frameworks as F
    names = {f.value for f in F.Framework}
    for expected in ("eu_ai_act", "dora", "gdpr", "soc2", "nist_ai_rmf",
                     "nis2", "colorado_ai", "ccpa", "iso_27001", "iso_42001"):
        assert expected in names, f"{expected} not mapped"


def test_transparency_obligation_is_declared_a_gap_not_claimed():
    """XCP has no interface to a human; claiming Art. 50 coverage would be false."""
    import compliance.frameworks as F
    art50 = [c for c in F.CONTROLS if "Art. 50" in c.reference]
    assert art50 and art50[0].coverage is F.Coverage.GAP


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:130]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
