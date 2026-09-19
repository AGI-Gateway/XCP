"""
privacy.retention — what is held, for how long, and on what basis.

WHY THIS IS HARD HERE
---------------------
XCP deliberately captures personal data. The trust lattice is *built* on knowing
which human an agent acts for: H1 is a verified individual, H2 adds entitlements
— groups, cost centre, approval limit. Receipts then tie that principal to
specific actions in a tamper-evident chain.

That collides with the right to erasure, and the collision is real rather than
rhetorical. `receipts.CallChain` is designed so that removing a record changes
the root. Deletion and tamper-evidence are in direct tension: the property that
makes the audit trustworthy is the property that makes it undeletable.

Two wrong answers are common, and this module exists to avoid both:

  · delete everything on request, including financial records an operator is
    legally obliged to retain
  · refuse all erasure, citing "immutability", which is not a lawful basis

THE RESOLUTION
--------------
Never put personal data *in* the immutable structure. Put a commitment to the
ciphertext there, and keep the payload encrypted under a key that belongs to one
data subject. Erasure destroys the key — see `privacy.shredding`. The chain
still verifies as a sequence; its contents simply become unreadable.

A note that matters: **a hash of personal data is still personal data** when it
is linkable. Hashing is pseudonymisation, not anonymisation — anyone holding a
candidate value can confirm a match. So `args_digest` alone does not discharge
anything, which is why shredding is keyed rather than hash-only.

ERASURE IS NOT ABSOLUTE
-----------------------
Under GDPR Art. 17(3), erasure does not apply where processing is necessary for
compliance with a legal obligation, or for the establishment or defence of legal
claims. A settled payment record is usually in that category — tax and AML
retention commonly runs six or seven years. So each class below declares whether
it can be erased on request, and if not, when the obligation lapses and it is
erased anyway.

This is a design, not legal advice. Retention periods are defaults that an
operator must confirm against their own jurisdiction and sector.

Status: XCP is a draft proposal.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

DAY = 86400
YEAR = 365 * DAY

#: EU AI Act Art. 19 (providers) and Art. 26(6) (deployers) set a floor of six
#: CALENDAR months on automatically generated logs. Six calendar months can run
#: to 184 days, so a "180 day" default silently sits under the floor — which is
#: how a reasonable-looking retention setting becomes a finding. 190 days gives
#: margin for clock skew and a monthly sweep.
#:
#: The floor applies "unless provided otherwise in applicable Union or national
#: law, in particular Union law on the protection of personal data" — so GDPR
#: Art. 5(1)(e) can pull the other way. See compliance.reconcile_retention().
AI_ACT_LOG_FLOOR = 190 * DAY


class Basis(str, Enum):
    """Lawful basis for processing (GDPR Art. 6)."""
    CONTRACT = "contract"                  # 6(1)(b) — performing the service
    LEGAL_OBLIGATION = "legal_obligation"  # 6(1)(c) — tax, AML, statutory records
    LEGITIMATE_INTEREST = "legitimate_interest"  # 6(1)(f) — security, abuse prevention
    CONSENT = "consent"                    # 6(1)(a)


class Subject(str, Enum):
    """Whose data it is. Determines who may exercise rights over it."""
    HUMAN = "human"          # the principal an agent acts for
    OPERATOR = "operator"    # a node operator — org data, but often an individual
    NONE = "none"            # no personal data (catalogs, specs, public records)


@dataclass(frozen=True)
class DataClass:
    """One category of data, with its retention and erasure position."""
    id: str
    description: str
    subject: Subject
    basis: Basis
    retention_seconds: int
    erasable_on_request: bool
    contains_personal_data: bool = True
    note: str = ""

    @property
    def retention_days(self) -> int:
        return self.retention_seconds // DAY

    def expired(self, created_at: int, now: Optional[int] = None) -> bool:
        if self.retention_seconds <= 0:
            return False                    # retained until erased explicitly
        return (now or int(time.time())) > created_at + self.retention_seconds

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "description": self.description,
                "subject": self.subject.value, "basis": self.basis.value,
                "retentionDays": self.retention_days,
                "erasableOnRequest": self.erasable_on_request,
                "containsPersonalData": self.contains_personal_data,
                "note": self.note}


#: Every category of data this software causes an operator to hold.
#: Anything not listed here should not be stored — if a new field does not fit a
#: class, that is a signal to reconsider collecting it.
CLASSES: dict[str, DataClass] = {c.id: c for c in [
    DataClass(
        id="session_binding",
        description="Certificate footprint bound to an agent id, and the tier it "
                    "was granted.",
        subject=Subject.HUMAN, basis=Basis.CONTRACT,
        retention_seconds=7 * DAY, erasable_on_request=True,
        note="Already capped at 7 days by the protocol; expires on its own."),
    DataClass(
        id="entitlements",
        description="Attributes asserted by an enterprise IdP: groups, cost "
                    "centre, approval limit, employee identifier.",
        subject=Subject.HUMAN, basis=Basis.CONTRACT,
        retention_seconds=DAY, erasable_on_request=True,
        note="The most directly identifying data in the system. Held only for "
             "the life of the mandate it narrows — never persisted to an audit "
             "record."),
    DataClass(
        id="call_chain",
        description="Tool calls an agent made: scope, tool, argument and result "
                    "digests, timestamps.",
        subject=Subject.HUMAN, basis=Basis.CONTRACT,
        retention_seconds=90 * DAY, erasable_on_request=True,
        note="A behavioural profile of the principal. Payloads are shredded on "
             "request; the chain keeps verifying because it commits to "
             "ciphertext, not plaintext."),
    DataClass(
        id="security_audit",
        description="Denials, rate-limit rejections, revocations, and the "
                    "identity asserted at the time.",
        subject=Subject.HUMAN, basis=Basis.LEGITIMATE_INTEREST,
        retention_seconds=AI_ACT_LOG_FLOOR, erasable_on_request=False,
        note="Meets the EU AI Act six-month log floor (Art. 19 / Art. 26(6)), "
             "which 180 days does not: six calendar months can run to 184 days. "
             "Retained against abuse and incident investigation. Art. 17(1)(c) "
             "allows an objection to be overridden by compelling legitimate "
             "grounds, but the window is bounded and short."),
    DataClass(
        id="settlement_receipt",
        description="Proof-of-delivery and transport receipts that resulted in "
                    "a payment: amounts, parties, signatures.",
        subject=Subject.HUMAN, basis=Basis.LEGAL_OBLIGATION,
        retention_seconds=7 * YEAR, erasable_on_request=False,
        note="A settled financial record. Art. 17(3)(b) and (e): erasure does "
             "not apply where retention is required by law or needed to defend "
             "a legal claim. Tax and AML retention commonly runs 6-7 years; "
             "confirm your own jurisdiction. Erased automatically when the "
             "obligation lapses."),
    DataClass(
        id="unsettled_receipt",
        description="Receipts for work that was never accepted or paid.",
        subject=Subject.HUMAN, basis=Basis.CONTRACT,
        retention_seconds=90 * DAY, erasable_on_request=True,
        note="No financial obligation attaches, so the Art. 17(3) exemption "
             "does not apply and these are erasable on request."),
    DataClass(
        id="telemetry",
        description="Spans, metrics and logs exported to an observability "
                    "backend: pseudonymous agent ids, trust tiers, scope "
                    "families, decisions and timings.",
        subject=Subject.HUMAN, basis=Basis.LEGITIMATE_INTEREST,
        retention_seconds=30 * DAY, erasable_on_request=True,
        note="Telemetry is a data-EXPORT path, and exporting to a third-party "
             "vendor is a new processor and usually an international transfer. "
             "Scrubbed by default: identifiers are pseudonymised per process, "
             "scope names are reduced to their family, and tool arguments and "
             "result payloads are never recorded at any detail level. "
             "XCP_OTEL_DETAIL=full raises this and should only be used with a "
             "self-hosted collector.",
        ),
    DataClass(
        id="node_record",
        description="Federation peers: domains, node identities, bindings, "
                    "attestations.",
        subject=Subject.OPERATOR, basis=Basis.LEGITIMATE_INTEREST,
        retention_seconds=0, erasable_on_request=True,
        note="Organisational rather than personal in most cases, but a "
             "sole-trader operator is an individual. Erasable by de-peering."),
    DataClass(
        id="catalog",
        description="Discovered MCP servers, APIs and their metadata.",
        subject=Subject.NONE, basis=Basis.LEGITIMATE_INTEREST,
        retention_seconds=0, erasable_on_request=True,
        contains_personal_data=False,
        note="Public technical metadata. Listed so the data map is complete."),
    DataClass(
        id="credential",
        description="Upstream API credentials.",
        subject=Subject.HUMAN, basis=Basis.CONTRACT,
        retention_seconds=0, erasable_on_request=True,
        note="Never stored by XCP. Held in the operator's secret backend, or "
             "sealed so the gateway cannot read it. Listed because an auditor "
             "will ask, and the answer is 'we do not hold these'."),
]}


class RetentionError(Exception):
    pass


def classify(class_id: str) -> DataClass:
    if class_id not in CLASSES:
        raise RetentionError(
            f"unknown data class {class_id!r}. Every stored field must belong to "
            "a declared class; if a new one does not fit, reconsider collecting it.")
    return CLASSES[class_id]


def erasable(class_id: str) -> tuple[bool, str]:
    """
    Can a subject demand erasure of this class today, and if not, why not?

    The reason matters as much as the answer: "no" without a lawful basis and an
    end date is not a defensible response to a data subject.
    """
    c = classify(class_id)
    if not c.contains_personal_data:
        return True, "contains no personal data"
    if c.erasable_on_request:
        return True, f"erasable on request (basis: {c.basis.value})"
    return False, (
        f"retained under {c.basis.value} for {c.retention_days} days "
        f"({c.retention_days // 365} years); erased automatically when the "
        f"obligation lapses. {c.note}")


def due_for_expiry(records: list[tuple[str, int]],
                   now: Optional[int] = None) -> list[tuple[str, int]]:
    """
    Which (class_id, created_at) records have outlived their retention. Run this
    on a schedule: a retention policy nobody executes is a liability, not a
    control.
    """
    out = []
    for class_id, created in records:
        try:
            c = classify(class_id)
        except RetentionError:
            out.append((class_id, created))      # unknown class: do not keep it
            continue
        if c.expired(created, now):
            out.append((class_id, created))
    return out


def data_map() -> dict[str, Any]:
    """
    The record of processing activities an operator needs for Art. 30, and the
    basis of a processor agreement with anyone they route for.
    """
    return {
        "specVersion": "0.1-draft",
        "controllerRole": (
            "An operator routing for their own users is a CONTROLLER. An "
            "operator routing for another organisation's users is a PROCESSOR, "
            "and that organisation is the controller — a processor agreement is "
            "required before federating with them."),
        "classes": [c.to_dict() for c in CLASSES.values()],
        "personalDataClasses": [c.id for c in CLASSES.values()
                                if c.contains_personal_data],
        "erasureExemptions": [
            {"class": c.id, "basis": c.basis.value,
             "retentionDays": c.retention_days, "reason": c.note}
            for c in CLASSES.values() if not c.erasable_on_request],
        "transfers": (
            "Federation moves data across borders by design. Peering with a "
            "node outside your jurisdiction is an international transfer and "
            "needs its own basis (Art. 44+). `Federation` peers are explicit, "
            "so this is a decision an operator makes rather than a default."),
        "notLegalAdvice": (
            "Retention periods are defaults. Confirm them against your own "
            "jurisdiction and sector before relying on them."),
    }


__all__ = ["DataClass", "Basis", "Subject", "CLASSES", "classify", "erasable",
           "due_for_expiry", "data_map", "RetentionError", "DAY", "YEAR",
           "AI_ACT_LOG_FLOOR"]
