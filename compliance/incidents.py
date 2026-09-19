"""
compliance.incidents — classification, and the clocks that start on detection.

WHY THIS IS A TECHNICAL CONTROL AND NOT PAPERWORK
--------------------------------------------------
Four regulators impose four different deadlines on the same event, and every one
of them runs from **awareness**, not from resolution:

    GDPR Art. 33      72 hours to the supervisory authority
    DORA Art. 19       4 hours from classification (and <=24h from detection)
                       to initial notification, then intermediate and final
    EU AI Act Art. 73  15 days for a serious incident; 2 days if widespread
    SOC 2 CC7.3-7.4    no statutory clock, but the auditor tests that you have
                       one and follow it

A team that discovers a breach on Friday evening and starts asking which
deadlines apply has already lost most of the window. So the clock starts when the
incident is recorded, the obligations are computed rather than remembered, and
the record is the evidence an auditor asks for.

WHAT THIS DOES NOT DO
---------------------
It does not detect anything, and it does not file anything. Detection is the weak
link — see the DORA Art. 10 entry in `compliance.frameworks` — and submission to
an authority is a human act through their portal. Classification thresholds here
are defaults that must be confirmed against the applicable RTS and the operator's
own materiality assessment.

Status: XCP is a draft proposal. Not legal advice.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

HOUR = 3600
DAY = 24 * HOUR


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    MAJOR = "major"            # DORA "major"; GDPR notifiable
    CRITICAL = "critical"      # widespread or life-safety


class Kind(str, Enum):
    PERSONAL_DATA_BREACH = "personal_data_breach"
    ICT_DISRUPTION = "ict_disruption"
    AI_SERIOUS_INCIDENT = "ai_serious_incident"
    SECURITY_EVENT = "security_event"
    THIRD_PARTY = "third_party"      # a peer or provider was compromised


@dataclass
class Obligation:
    framework: str
    reference: str
    due_at: int
    description: str
    satisfied_at: int = 0

    @property
    def overdue(self) -> bool:
        return not self.satisfied_at and int(time.time()) > self.due_at

    def hours_remaining(self, now: Optional[int] = None) -> float:
        return round((self.due_at - (now or int(time.time()))) / HOUR, 1)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["dueOn"] = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(self.due_at))
        d["overdue"] = self.overdue
        d["hoursRemaining"] = self.hours_remaining()
        return d


@dataclass
class Incident:
    """
    One recorded event. `detected_at` is what every clock runs from — not when
    it started, and not when it was fixed.
    """
    id: str
    kind: Kind
    severity: Severity
    detected_at: int
    summary: str
    personal_data_affected: bool = False
    subjects_affected: int = 0
    high_risk_to_subjects: bool = False     # triggers GDPR Art. 34
    critical_function_affected: bool = False
    cross_border: bool = False
    high_risk_ai_system: bool = False
    obligations: list[Obligation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["severity"] = self.severity.value
        d["detectedOn"] = time.strftime("%Y-%m-%d %H:%M UTC",
                                        time.gmtime(self.detected_at))
        d["obligations"] = [o.to_dict() for o in self.obligations]
        d["overdue"] = [o.to_dict() for o in self.obligations if o.overdue]
        return d

    def next_due(self) -> Optional[Obligation]:
        pending = [o for o in self.obligations if not o.satisfied_at]
        return min(pending, key=lambda o: o.due_at) if pending else None

    def satisfy(self, reference: str, now: Optional[int] = None) -> bool:
        for o in self.obligations:
            if o.reference == reference and not o.satisfied_at:
                o.satisfied_at = now or int(time.time())
                return True
        return False


def classify(incident: Incident) -> Incident:
    """
    Compute every notification obligation this event triggers. Deliberately
    over-inclusive at the margins: a spurious obligation costs an operator a
    filing, a missed one costs them a penalty.
    """
    t = incident.detected_at
    obs: list[Obligation] = []

    # GDPR Art. 33 — 72 hours from awareness, to the supervisory authority.
    if incident.personal_data_affected:
        obs.append(Obligation(
            "gdpr", "Art. 33", t + 72 * HOUR,
            "Notify the supervisory authority. If later than 72h, the "
            "notification must state the reasons for the delay."))
        # Art. 34 — notify subjects without undue delay when high risk.
        if incident.high_risk_to_subjects:
            obs.append(Obligation(
                "gdpr", "Art. 34", t + 72 * HOUR,
                "Communicate to affected data subjects without undue delay; "
                "high risk to rights and freedoms was assessed as present."))
        else:
            incident.notes.append(
                "Art. 34 not triggered: no high risk to subjects assessed. "
                "Record the reasoning — the assessment itself is auditable.")

    # DORA Art. 19 — the tightest clock in the set.
    if incident.kind in (Kind.ICT_DISRUPTION, Kind.SECURITY_EVENT,
                         Kind.THIRD_PARTY) or incident.critical_function_affected:
        if incident.severity in (Severity.MAJOR, Severity.CRITICAL):
            obs.append(Obligation(
                "dora", "Art. 19 initial", t + 4 * HOUR,
                "Initial notification to the competent authority: within 4 "
                "hours of classifying the incident as major, and no later than "
                "24 hours from detection."))
            obs.append(Obligation(
                "dora", "Art. 19 intermediate", t + 72 * HOUR,
                "Intermediate report once regular activity is restored."))
            obs.append(Obligation(
                "dora", "Art. 19 final", t + 30 * DAY,
                "Final report including root cause analysis."))
        else:
            incident.notes.append(
                "Not classified major under DORA, so Art. 19 reporting does not "
                "apply. Confirm against the RTS thresholds — client impact, "
                "duration, geographical spread, data losses, criticality.")

    # EU AI Act Art. 73 — only for providers of high-risk systems.
    if incident.kind is Kind.AI_SERIOUS_INCIDENT or incident.high_risk_ai_system:
        window = 2 * DAY if incident.severity is Severity.CRITICAL else 15 * DAY
        obs.append(Obligation(
            "eu_ai_act", "Art. 73", t + window,
            f"Report the serious incident to the market surveillance authority "
            f"within {window // DAY} days."))

    # Cross-border adds coordination, not a new deadline.
    if incident.cross_border:
        incident.notes.append(
            "Cross-border: identify the lead supervisory authority (GDPR "
            "Art. 56) and expect coordination across competent authorities.")

    # Always: an internal record, which is what SOC 2 actually tests.
    obs.append(Obligation(
        "soc2", "CC7.3", t + 24 * HOUR,
        "Record evaluation and response internally. No statutory clock, but an "
        "auditor tests that a documented process exists and was followed."))

    incident.obligations = obs
    if not incident.personal_data_affected and incident.subjects_affected:
        incident.notes.append(
            "subjects_affected is non-zero while personal_data_affected is "
            "false — check the classification before relying on it.")
    return incident


def open_incident(kind: Kind, severity: Severity, summary: str, *,
                  detected_at: Optional[int] = None, **flags: Any) -> Incident:
    """Record an incident and compute its obligations immediately."""
    now = detected_at or int(time.time())
    iid = f"inc-{now}-{abs(hash(summary)) % 100000:05d}"
    known = {f for f in Incident.__dataclass_fields__}
    inc = Incident(id=iid, kind=kind, severity=severity, detected_at=now,
                   summary=summary,
                   **{k: v for k, v in flags.items() if k in known})
    return classify(inc)


def overdue(incidents: list[Incident],
            now: Optional[int] = None) -> list[dict[str, Any]]:
    n = now or int(time.time())
    out = []
    for inc in incidents:
        for o in inc.obligations:
            if not o.satisfied_at and n > o.due_at:
                out.append({"incident": inc.id, "framework": o.framework,
                            "reference": o.reference,
                            "overdueHours": round((n - o.due_at) / HOUR, 1)})
    return out


def timeline(inc: Incident) -> str:
    lines = [f"Incident {inc.id}  [{inc.severity.value}] {inc.kind.value}",
             f"  detected: {inc.to_dict()['detectedOn']}",
             f"  {inc.summary}", "", "  Notification obligations:"]
    for o in sorted(inc.obligations, key=lambda x: x.due_at):
        state = ("satisfied" if o.satisfied_at
                 else ("OVERDUE" if o.overdue else f"{o.hours_remaining()}h left"))
        lines.append(f"    {o.framework:<10} {o.reference:<22} "
                     f"{o.to_dict()['dueOn']}  [{state}]")
        lines.append(f"      {o.description}")
    if inc.notes:
        lines += ["", "  Notes:"] + [f"    - {n}" for n in inc.notes]
    return "\n".join(lines)


__all__ = ["Incident", "Obligation", "Kind", "Severity", "classify",
           "open_incident", "overdue", "timeline", "HOUR", "DAY"]
