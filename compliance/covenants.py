"""
compliance.covenants — the commitments code cannot make for you.

A control mapping that stops at "this is organisational" leaves the adopter
exactly where they started. This module goes one step further: for every residual
that software cannot close, it states the **covenant** — a binding commitment,
phrased so it can go into a DPA, a procurement schedule or a DORA Art. 30
contract without a lawyer rewriting it from scratch.

Three things each covenant names, because a commitment missing any of them is
not enforceable:

  · **who owes it** — operator, deployer, or the application built on top
  · **what discharges it** — the evidence someone would actually inspect
  · **which clauses it answers** — so an auditor can trace the mapping

A covenant is deliberately a weaker control than a measurement. Where a gap can
be measured it belongs in `compliance.resilience` instead, and three that were
recorded here originally moved there on review.

Nothing in this file makes anyone compliant. It is contract language, not advice,
and it has not been reviewed by counsel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Owes(str, Enum):
    OPERATOR = "operator"        # whoever runs the node
    DEPLOYER = "deployer"        # whoever puts an AI system into use
    APPLICATION = "application"  # whoever builds the agent on top
    BOTH = "operator_and_deployer"


@dataclass(frozen=True)
class Covenant:
    id: str
    owes: Owes
    commitment: str          # the binding sentence
    evidence: str            # what discharges it
    clauses: tuple[str, ...]
    why_not_code: str        # why this cannot be automated
    frequency: str = "once"  # once | continuous | annual | per-incident

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "owes": self.owes.value,
                "commitment": self.commitment, "evidence": self.evidence,
                "clauses": list(self.clauses), "whyNotCode": self.why_not_code,
                "frequency": self.frequency}

    def as_contract_clause(self) -> str:
        return (f"{self.id}. The {self.owes.value.replace('_', ' ')} shall "
                f"{self.commitment[0].lower()}{self.commitment[1:]} "
                f"Evidence of compliance: {self.evidence} "
                f"(Ref: {'; '.join(self.clauses)}.)")


O = Owes

COVENANTS: tuple[Covenant, ...] = (
    # ── classification: everything downstream depends on getting this right ──
    Covenant(
        "COV-01", O.DEPLOYER,
        "Determine, and record in writing, whether the AI system it puts into "
        "use is high-risk under Annex III, and re-assess whenever the system's "
        "purpose changes.",
        "A dated classification memo naming the Annex III category considered "
        "and the reasoning for inclusion or exclusion.",
        ("EU AI Act Art. 6", "Annex III"),
        "XCP is infrastructure and makes no inference about a person. Whether "
        "the system built on it is high-risk depends entirely on what that "
        "system decides, which XCP cannot observe.",
        "annual"),
    Covenant(
        "COV-02", O.DEPLOYER,
        "Assess whether its use of XCP makes it a provider rather than a "
        "deployer — in particular on substantial modification, prompt "
        "engineering or retrieval augmentation — and accept provider "
        "obligations if so.",
        "A written value-chain assessment, reviewed by counsel.",
        ("EU AI Act Art. 25",),
        "The trigger is a legal characterisation of what you built, not a "
        "property of the code you built it with.",
        "annual"),

    # ── disclosure the application owes, not the infrastructure ──────────────
    Covenant(
        "COV-03", O.APPLICATION,
        "Inform natural persons that they are interacting with an AI system, "
        "at the interface where that interaction happens.",
        "Screenshots or UX copy showing the disclosure in the live product.",
        ("EU AI Act Art. 50",),
        "XCP sits between an agent and its tools and has no interface to a "
        "human. It cannot make a disclosure to someone it never sees, and "
        "claiming otherwise would be false.",
        "continuous"),

    # ── assessments: process obligations ─────────────────────────────────────
    Covenant(
        "COV-04", O.DEPLOYER,
        "Carry out a data protection impact assessment before processing that "
        "is likely to result in a high risk to individuals, using the data map "
        "as the technical annex.",
        "A completed DPIA referencing `xcp privacy map` output, with the "
        "residual-risk decision signed off.",
        ("GDPR Art. 35",),
        "A DPIA is a judgement about risk to people in a specific context. The "
        "data map supplies the inputs; the assessment is the deliverable.",
        "once"),
    Covenant(
        "COV-05", O.DEPLOYER,
        "Carry out a fundamental rights impact assessment where Art. 27 "
        "applies, before first use.",
        "A completed FRIA naming affected groups and mitigation measures.",
        ("EU AI Act Art. 27",),
        "Same reason as COV-04: an assessment of impact on people cannot be "
        "derived from a codebase.",
        "once"),
    Covenant(
        "COV-06", O.DEPLOYER,
        "Test the deployed system for algorithmic discrimination in "
        "consequential decisions and act on the findings.",
        "Dated test results with demographic breakdowns and remediation.",
        ("Colorado C.R.S. 6-1-1703",),
        "XCP records what a system did; it has no view of outcomes by protected "
        "characteristic, and adding one would mean collecting exactly the data "
        "minimisation says not to.",
        "annual"),

    # ── human oversight: the surface exists, the attention does not ──────────
    Covenant(
        "COV-07", O.DEPLOYER,
        "Assign named, competent persons to oversee the system, with the "
        "authority and the training to use the revocation and kill-switch "
        "controls XCP provides.",
        "A named rota, evidence of training, and a rehearsed revocation drill.",
        ("EU AI Act Art. 14", "EU AI Act Art. 26(2)"),
        "The intervention surface is implemented. Whether a competent human is "
        "actually watching, and will act, is the part that matters and the part "
        "no code supplies.",
        "continuous"),
    Covenant(
        "COV-08", O.OPERATOR,
        "Retain the automatically generated logs for the period the governing "
        "law requires, having first determined which floor applies and "
        "reconciled it against data minimisation.",
        "A retention decision record citing `xcp privacy reconcile` output and "
        "the basis for the period chosen.",
        ("EU AI Act Art. 19", "EU AI Act Art. 26(6)", "GDPR Art. 5(1)(e)",
         "DORA Del. Reg. 2024/1774 Art. 12"),
        "The defaults meet the AI Act floor, but whether that floor applies to "
        "you — and whether data protection law overrides it — is a legal "
        "determination about your deployment.",
        "annual"),

    # ── third-party risk: contract, not code ────────────────────────────────
    Covenant(
        "COV-09", O.OPERATOR,
        "Put the contractual provisions DORA requires in place before "
        "federating with, or routing for, a financial entity — including "
        "service levels, audit and access rights, exit strategy, "
        "sub-outsourcing conditions and data location.",
        "An executed contract containing the Art. 30 terms, and a register "
        "entry for the arrangement.",
        ("DORA Art. 28", "DORA Art. 30"),
        "These are contract terms between legal persons. Federation is "
        "permissionless by design, which makes this covenant more important "
        "rather than less: the software will happily peer with someone you have "
        "no agreement with.",
        "per-arrangement"),
    Covenant(
        "COV-10", O.BOTH,
        "Execute a processor agreement before routing traffic on behalf of "
        "another organisation's users, and flow the same terms down to any "
        "peer it re-routes through.",
        "A signed DPA naming the categories in the data map, with sub-processor "
        "terms covering federated peers.",
        ("GDPR Art. 28", "GDPR Art. 44-49"),
        "Routing for someone else's users makes you a processor. That is a "
        "legal relationship, and federation makes it transitive in a way the "
        "code cannot paper over.",
        "per-arrangement"),
    Covenant(
        "COV-11", O.OPERATOR,
        "Establish a lawful basis for each international transfer created by "
        "peering across a border, before the peering is established.",
        "Transfer impact assessments and executed SCCs or an adequacy finding.",
        ("GDPR Ch. V", "PIPL Art. 38-40"),
        "Peers are explicit in XCP, so this is a decision rather than a default "
        "— but the basis for the transfer is a legal instrument. China's PIPL "
        "additionally requires a CAC security assessment, which is a regulatory "
        "process with no technical equivalent.",
        "per-arrangement"),

    # ── operations ──────────────────────────────────────────────────────────
    Covenant(
        "COV-12", O.OPERATOR,
        "Rehearse recovery from the documented state inventory at least "
        "annually, including restoring the node identity key from offline "
        "backup.",
        "A dated restore test with measured RTO against the targets in "
        "`compliance.resilience.recovery_plan()`.",
        ("SOC 2 A1.2", "DORA Art. 11-12"),
        "The state inventory and targets are shipped. A recovery plan nobody "
        "has rehearsed is not a control, and only you can rehearse yours.",
        "annual"),
    Covenant(
        "COV-13", O.OPERATOR,
        "Classify incidents against the applicable significance thresholds and "
        "report within the statutory deadlines.",
        "An incident register with classification reasoning and dated "
        "submissions to the relevant authority.",
        ("NIS2 Art. 23", "DORA Art. 19", "GDPR Art. 33"),
        "Detection and containment are supported. Classification is a judgement "
        "against thresholds that differ per regime, and reporting is an act "
        "only a legal person can perform.",
        "per-incident"),
    Covenant(
        "COV-14", O.OPERATOR,
        "Operate the control environment SOC 2 assesses: board oversight, "
        "personnel screening, security awareness training, and change approval.",
        "Policies, training records and approval trails covering the audit "
        "period.",
        ("SOC 2 CC1", "SOC 2 CC2", "SOC 2 CC4", "SOC 2 CC5"),
        "Most of what a SOC 2 auditor tests is people and process. No library "
        "contributes to it, and a vendor implying otherwise is selling.",
        "continuous"),
    Covenant(
        "COV-15", O.OPERATOR,
        "Ensure destruction of a subject key propagates to every backup, "
        "replica and snapshot within the period promised to data subjects.",
        "A documented deletion procedure covering backups, and evidence of a "
        "test erasure traced through to snapshot expiry.",
        ("GDPR Art. 17",),
        "`KeyRing.destroy` removes the key from the running process. Reaching "
        "your backups is an operational obligation this code cannot discharge, "
        "and it is where erasure most commonly fails in practice.",
        "continuous"),
    Covenant(
        "COV-16", O.OPERATOR,
        "Commission independent security testing proportionate to risk, "
        "including threat-led penetration testing where DORA requires it, and "
        "an independent audit of the smart contracts before they hold value.",
        "Dated test reports and remediation records.",
        ("DORA Art. 24-27", "EU AI Act Art. 15"),
        "The codebase ships a conformance suite and its own tests. Neither is "
        "independent, and `NodeRegistry.sol` has never been audited or deployed "
        "to a public network.",
        "annual"),
)

_BY_ID = {c.id: c for c in COVENANTS}


class CovenantError(Exception):
    pass


def covenant(cid: str) -> Covenant:
    if cid not in _BY_ID:
        raise CovenantError(f"unknown covenant {cid!r}")
    return _BY_ID[cid]


def for_owner(owes: Owes) -> list[Covenant]:
    return [c for c in COVENANTS
            if c.owes is owes or (c.owes is Owes.BOTH and owes in
                                  (Owes.OPERATOR, Owes.DEPLOYER))]


def for_clause(fragment: str) -> list[Covenant]:
    f = fragment.lower()
    return [c for c in COVENANTS if any(f in cl.lower() for cl in c.clauses)]


def contract_annex(owes: Optional[Owes] = None) -> str:
    """
    The covenants as numbered clauses, ready to paste into a schedule.

    Deliberately plain: a schedule an adopter's counsel can edit is more useful
    than one that reads like marketing.
    """
    items = for_owner(owes) if owes else list(COVENANTS)
    head = ("SCHEDULE — OPERATIONAL COVENANTS\n"
            "Commitments that the accompanying software does not and cannot "
            "discharge.\nThis is contract language, not legal advice; it has not "
            "been reviewed by counsel.\n")
    return head + "\n" + "\n\n".join(c.as_contract_clause() for c in items)


def coverage_statement() -> dict[str, Any]:
    """
    The honest summary: what the code does, what a covenant carries, and what is
    still open.
    """
    from collections import Counter
    import compliance.frameworks as F
    cov = Counter(c.coverage.value for c in F.CONTROLS)
    covered_clauses = {cl for c in COVENANTS for cl in c.clauses}
    return {
        "controls": len(F.CONTROLS),
        "controlCoverage": dict(cov),
        "covenants": len(COVENANTS),
        "clausesCoveredByCovenant": sorted(covered_clauses),
        "byOwner": {o.value: len([c for c in COVENANTS if c.owes is o])
                    for o in Owes},
        "position": (
            "Software controls where the obligation is technical; measurements "
            "where a residual is computable; covenants where it is neither. "
            "Nothing here constitutes compliance, which is determined by "
            "counsel and, for SOC 2, by a licensed CPA firm."),
        "notLegalAdvice": True,
    }


__all__ = ["Covenant", "Owes", "COVENANTS", "covenant", "for_owner",
           "for_clause", "contract_annex", "coverage_statement", "CovenantError"]
