"""
test_covenants.py — every gap is either closed or carried by a commitment.

A control mapping that stops at "this is organisational" leaves an adopter where
they started. These tests enforce the discipline: if software cannot close a
residual, a named party must commit to it, with evidence someone can inspect.

    python tests/test_covenants.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import compliance.frameworks as F
from compliance.covenants import (COVENANTS, Owes, covenant, for_owner,
                                  for_clause, contract_annex,
                                  coverage_statement, CovenantError)
from compliance.resilience import (concentration, recovery_plan, STATE,
                                   degradation_scenarios)


# ── nothing is left dangling ───────────────────────────────────────────────

def test_every_open_gap_names_the_covenant_that_carries_it():
    dangling = [c for c in F.CONTROLS
                if c.coverage.value in ("gap", "operator")
                and "Covenant" not in c.gap_note]
    assert not dangling, \
        f"no commitment carries: {[(c.framework.value, c.reference) for c in dangling]}"


def test_referenced_covenants_exist():
    import re
    for c in F.CONTROLS:
        for cid in re.findall(r"COV-\d{2}", c.gap_note):
            covenant(cid)          # raises if unknown


def test_unknown_covenant_is_rejected():
    try:
        covenant("COV-99"); assert False
    except CovenantError:
        pass


# ── a covenant must be enforceable ─────────────────────────────────────────

def test_every_covenant_names_owner_evidence_and_clauses():
    """A commitment missing any of these is not enforceable."""
    for c in COVENANTS:
        assert c.owes in Owes
        assert len(c.commitment) > 40, f"{c.id} commitment is too vague"
        assert c.evidence, f"{c.id} has no evidence anyone could inspect"
        assert c.clauses, f"{c.id} cites no clause"
        assert c.why_not_code, f"{c.id} does not justify being a covenant"
        assert c.frequency in ("once", "continuous", "annual", "per-incident",
                               "per-arrangement")


def test_covenant_ids_are_unique():
    ids = [c.id for c in COVENANTS]
    assert len(ids) == len(set(ids))


def test_annex_reads_as_contract_language():
    text = contract_annex()
    assert "shall" in text
    assert "not legal advice" in text.lower()
    for c in COVENANTS:
        assert c.id in text


def test_annex_can_be_scoped_to_one_party():
    app = contract_annex(Owes.APPLICATION)
    assert "COV-03" in app, "the Art. 50 disclosure belongs to the application"
    assert "COV-14" not in app, "SOC 2 control environment is not the app's"


def test_the_application_owes_the_transparency_disclosure():
    """XCP has no interface to a human, so claiming Art. 50 would be false."""
    art50 = for_clause("Art. 50")
    assert art50 and art50[0].owes is Owes.APPLICATION


def test_contract_and_transfer_duties_are_per_arrangement():
    for cid in ("COV-09", "COV-10", "COV-11"):
        assert covenant(cid).frequency == "per-arrangement", \
            "a duty owed per counterparty must not be a one-off tick"


def test_backup_erasure_is_covenanted_because_code_cannot_reach_it():
    c = covenant("COV-15")
    assert "backup" in c.commitment.lower()
    assert "GDPR Art. 17" in c.clauses


def test_no_covenant_claims_compliance():
    blob = " ".join(c.commitment + c.evidence for c in COVENANTS).lower()
    assert "is compliant" not in blob and "ensures compliance" not in blob
    assert coverage_statement()["notLegalAdvice"] is True


# ── measurable residuals must not be covenants ─────────────────────────────

def test_concentration_is_measured_not_promised():
    """A measurement is a stronger control than a promise; DORA Art. 29's
    computable half belongs in code."""
    r = concentration({"a": 90, "b": 10})
    assert r.hhi > 0.5 and "CONCENTRATED" in r.verdict
    flat = concentration({f"p{i}": 10 for i in range(10)})
    assert flat.hhi < 0.2


def test_concentration_handles_an_empty_estate():
    r = concentration({})
    assert r.total_peers == 0 and "no reachable capability" in r.verdict


def test_single_source_capabilities_are_called_out():
    r = concentration({"a": 50, "b": 50}, critical=["payments"])
    assert "single peer" in r.verdict


def test_recovery_plan_names_the_unrecoverable_item_first():
    p = recovery_plan()
    assert p["unrecoverable"] == ["node identity key"], \
        "losing the node key is unlike losing anything else and must be flagged"
    assert all(s["backup"] for s in p["state"])
    assert "rehearsed" in p["note"]


def test_every_state_item_declares_rpo_rto_and_impact():
    for s in STATE:
        assert s.rpo_seconds >= 0 and s.rto_seconds > 0
        assert s.loss_impact and s.where


def test_resilience_scenarios_cover_the_failures_this_build_has_actually_had():
    """Each of these was a real defect found during development."""
    text = " ".join(s["scenario"] + s["expected"]
                    for s in degradation_scenarios()).lower()
    for failure in ("rotating identities", "poisoned catalog",
                    "rotates its certificate", "sealing key"):
        assert failure in text, f"{failure} is not covered by a scenario"


# ── the overall position stays honest ──────────────────────────────────────

def test_coverage_statement_reports_gaps_alongside_wins():
    s = coverage_statement()
    assert s["controlCoverage"].get("gap", 0) > 0, \
        "a mapping reporting zero gaps is a sales document"
    assert s["covenants"] == len(COVENANTS)
    assert "counsel" in s["position"]


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
