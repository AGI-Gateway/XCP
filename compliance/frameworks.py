"""
compliance.frameworks — what this codebase does, mapped to what regulators ask.

READ THIS FIRST
---------------
**This module does not make anything compliant.** Compliance is a determination
made by qualified counsel, and for SOC 2 by a licensed CPA firm attesting to your
*organisation's* controls over a period of observation. Most of what an auditor
tests is HR, vendor management, change approval and physical security — none of
which is code and none of which lives here.

What this provides is narrower and, used honestly, more useful:

  · a mapping from specific controls to the code that implements them
  · generated evidence an auditor can actually inspect
  · a **gap register** naming what is not covered

The gap register is the point. A mapping that shows only green is a sales
document; the value to an adopter is knowing precisely where they still have
work, before they discover it in an audit.

WHERE XCP SITS IN THE AI ACT
----------------------------
Worth stating plainly, because it is commonly got wrong in both directions.

XCP is **not** a high-risk AI system and **not** a general-purpose AI model. It
is infrastructure: it verifies identity, gates authority and records what
happened. It makes no inference and no decision about a person.

What it is, is a **compliance enabler** for operators who *do* deploy high-risk
systems. Art. 12 requires automatic logging over a system's lifetime; Art. 14
requires human oversight with the ability to intervene. A tamper-evident call
chain and a revocable, human-delegated mandate are directly responsive to both.
Deploying XCP does not make a high-risk system compliant — it supplies evidence
and control surfaces the operator would otherwise have to build.

Status: XCP is a draft proposal. This mapping is a starting point for a
conversation with counsel, not a substitute for one.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Framework(str, Enum):
    EU_AI_ACT = "eu_ai_act"          # Reg. (EU) 2024/1689
    DORA = "dora"                    # Reg. (EU) 2022/2554
    GDPR = "gdpr"                    # Reg. (EU) 2016/679
    SOC2 = "soc2"                    # AICPA Trust Services Criteria
    NIST_AI_RMF = "nist_ai_rmf"      # NIST AI 100-1 (voluntary, US)
    NIST_CSF = "nist_csf"            # NIST CSF 2.0
    ISO_42001 = "iso_42001"          # AI management systems
    ISO_27001 = "iso_27001"          # ISMS
    UK_GDPR = "uk_gdpr"
    CCPA = "ccpa"                    # California, + CPRA
    PIPL = "pipl"                    # China
    LGPD = "lgpd"                    # Brazil
    DPDP = "dpdp"
    NIS2 = "nis2"
    COLORADO_AI = "colorado_ai"                    # India


class Coverage(str, Enum):
    IMPLEMENTED = "implemented"      # the code does this, with a test
    PARTIAL = "partial"              # some of it; the rest is on the operator
    ENABLER = "enabler"              # supplies evidence/surface, not the control
    OPERATOR = "operator"            # entirely the operator's obligation
    GAP = "gap"                      # required, and not addressed anywhere


@dataclass
class Control:
    framework: Framework
    reference: str                   # article / criterion
    requirement: str
    coverage: Coverage
    implemented_by: str = ""         # module, or "" when not code
    evidence: str = ""               # what an auditor can inspect
    gap_note: str = ""               # what remains, stated plainly

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["framework"] = self.framework.value
        d["coverage"] = self.coverage.value
        return d


C = Control
F = Framework
COV = Coverage

CONTROLS: list[Control] = [
    # ── EU AI Act ──────────────────────────────────────────────────────────
    C(F.EU_AI_ACT, "Art. 12 — record-keeping",
      "High-risk systems must automatically log events over their lifetime, "
      "enabling traceability of functioning.",
      COV.ENABLER, "receipts.CallChain, core.gateway audit",
      "Hash-chained call records; tampering changes the root.",
      "XCP logs what passed through it. Logging the AI system's own inferences "
      "and inputs remains the operator's job."),
    C(F.EU_AI_ACT, "Art. 14 — human oversight",
      "High-risk systems must be overseeable by humans who can intervene or "
      "interrupt operation.",
      COV.ENABLER, "trust.tiers, core.contracts.SessionRegistry",
      "Mandates are signed by a human principal, scope-limited, and revocable "
      "in about one block.",
      "Supplies the intervention surface. Whether a human actually exercises "
      "oversight is a process control."),
    C(F.EU_AI_ACT, "Art. 15 — accuracy, robustness, cybersecurity",
      "High-risk systems must be resilient to unauthorised third-party attempts "
      "to alter use or performance.",
      COV.PARTIAL, "security.xcpsec, trustfirewall",
      "Argument firewall, execution sandbox, prompt-injection boundaries, "
      "supply-chain pinning, rate limits.",
      "Accuracy and robustness of the *model* are out of scope entirely."),
    C(F.EU_AI_ACT, "Art. 26 — deployer obligations",
      "Deployers must use high-risk systems per instructions and monitor "
      "operation.",
      COV.OPERATOR, "", "", "Entirely the deployer's obligation." " Covenant COV-07 carries the residual."),
    C(F.EU_AI_ACT, "Art. 73 — serious incident reporting",
      "Providers must report serious incidents to market surveillance "
      "authorities, generally within 15 days.",
      COV.PARTIAL, "compliance.incidents",
      "Incident classification with an AI Act clock.",
      "The clock and record exist. Determining that an event is a 'serious "
      "incident' under Art. 3(49) is a judgement the operator must make."),
    C(F.EU_AI_ACT, "Art. 6 / Annex III — classification",
      "Whether a system is high-risk depends on its purpose and domain.",
      COV.OPERATOR, "",
      "compliance.frameworks documents XCP's own position.",
      "XCP is infrastructure, not a high-risk AI system. An operator embedding "
      "it in an Annex III use case carries the classification themselves." " Covenant COV-01 carries the residual."),

    # ── DORA ───────────────────────────────────────────────────────────────
    C(F.DORA, "Art. 9 — protection and prevention",
      "ICT security tools, policies and procedures to ensure resilience of "
      "means of transfer.",
      COV.PARTIAL, "security.xcpsec.mtls, trustfirewall.limits",
      "TLS 1.3 only with certificate pinning, per-tier quotas, global ceiling.",
      "Network segmentation, endpoint hardening and physical controls are the "
      "operator's."),
    C(F.DORA, "Art. 10 — detection",
      "Mechanisms to promptly detect anomalous activity.",
      COV.PARTIAL, "trustfirewall.limits, core.gateway metrics",
      "Rejection counters by cause, Prometheus metrics, audit records.",
      "No alerting, no SIEM integration, no anomaly baselining. An operator "
      "must wire these into their own monitoring."),
    C(F.DORA, "Art. 17-19 — ICT incident management and reporting",
      "Classify incidents and report major ones to the competent authority on "
      "a defined timetable.",
      COV.PARTIAL, "compliance.incidents",
      "Classification against DORA criteria plus initial/intermediate/final "
      "notification clocks.",
      "Submission to the authority is manual. Thresholds must be confirmed "
      "against the applicable RTS."),
    C(F.DORA, "Art. 28 — general third-party risk principles",
      "Maintain a register of information on all contractual arrangements for "
      "ICT services.",
      COV.PARTIAL, "compliance.register, federation",
      "Generated register covering peers, subcontractors and data locations.",
      "The register covers XCP's own federation. Arrangements outside XCP must "
      "be added by the operator." " Covenant COV-09 carries the residual."),
    C(F.DORA, "Art. 28(8) — exit strategies",
      "Exit strategies for ICT services supporting critical functions, without "
      "disruption or detriment.",
      COV.PARTIAL, "compliance.register, federation.Federation",
      "Peering is explicit and revocable; catalog and receipts export as JSON.",
      "No tested exit runbook and no portability guarantee for a running "
      "workload mid-flight."),
    C(F.DORA, "Art. 29 — concentration risk",
      "Assess risk arising from contracting providers that are not easily "
      "substitutable.",
      COV.ENABLER, "federation",
      "Federation is many-node by design; no node is structurally required.",
      "Whether an operator has in fact concentrated on one peer is theirs to "
      "assess." " Covenant COV-09 carries the residual."),
    C(F.DORA, "Art. 30 — contractual provisions",
      "Contracts must specify service descriptions, data locations, access and "
      "audit rights, subcontracting and termination.",
      COV.PARTIAL, "compliance.register, privacy.retention",
      "Data map, residency constraints, declared subcontracting chain.",
      "The contract itself is a legal document the operator must execute. This "
      "supplies the technical facts it needs to state." " Covenant COV-09 carries the residual."),
    C(F.DORA, "Art. 24-27 — resilience testing",
      "Test ICT tools and systems periodically; threat-led penetration testing "
      "for significant entities.",
      COV.GAP, "",
      "Conformance suite exercises protocol behaviour, not resilience.",
      "No load testing, no chaos testing, no TLPT. A financial entity subject "
      "to DORA must arrange these independently." " Covenant COV-16 carries the residual."),

    # ── GDPR ───────────────────────────────────────────────────────────────
    C(F.GDPR, "Art. 5(1)(c) — data minimisation",
      "Adequate, relevant and limited to what is necessary.",
      COV.IMPLEMENTED, "privacy.retention",
      "Nine declared classes; anything unlisted should not be stored. "
      "Entitlements held for one day.",
      "The classes constrain what XCP itself stores. An application built on "
      "top can still collect more, and the argument digests in a call chain are "
      "only minimising if the caller keeps payloads out of tool arguments in "
      "the first place."),
    C(F.GDPR, "Art. 5(1)(e) — storage limitation",
      "Kept no longer than necessary.",
      COV.IMPLEMENTED, "privacy.retention.due_for_expiry",
      "Per-class retention with a computed expiry sweep.",
      "The sweep must actually be scheduled by the operator."),
    C(F.GDPR, "Art. 6 — lawful basis",
      "Each processing operation needs a basis.",
      COV.IMPLEMENTED, "privacy.retention.Basis",
      "A basis is recorded per data class.",
      "Each class declares a basis, but whether it is the RIGHT basis for your processing depends on your relationship with the subject. Consent, in particular, is rarely the right basis for infrastructure logging."),
    C(F.GDPR, "Art. 17 — right to erasure",
      "Erasure on request, subject to the Art. 17(3) exemptions.",
      COV.IMPLEMENTED, "privacy.shredding, privacy.erasure",
      "Crypto-shredding: the key is destroyed, the audit chain still verifies. "
      "Retained classes are reported with a basis and an end date.",
      "Crypto-shredding covers what this node holds. Copies already gossiped to federated peers are beyond reach, and key destruction must also reach your backups — an operational obligation this code cannot discharge."),
    C(F.GDPR, "Art. 25 — data protection by design and by default",
      "Technical measures implementing the principles.",
      COV.IMPLEMENTED, "privacy, vault.sealed, federation.transport",
      "Personal data kept out of published artifacts: transport commitments "
      "carry totals not counterparties; sealed credentials are unreadable to "
      "the gateway.",
      "The defaults are minimising, but an operator can configure them otherwise, and an application built on top can collect far more than XCP ever sees."),
    C(F.GDPR, "Art. 28 — processor obligations",
      "Processing only on documented instructions; assist the controller.",
      COV.PARTIAL, "privacy.retention.data_map",
      "The data map names the controller/processor split explicitly.",
      "A signed processor agreement is required before federating on another "
      "organisation's behalf. No template is shipped."),
    C(F.GDPR, "Art. 30 — records of processing",
      "Maintain a record of processing activities.",
      COV.IMPLEMENTED, "privacy.retention.data_map",
      "Generated Art. 30 record covering categories, bases and retention.",
      "Must be extended with the operator's own processing outside XCP."),
    C(F.GDPR, "Art. 32 — security of processing",
      "Appropriate technical measures including encryption and resilience.",
      COV.PARTIAL, "vault, security.xcpsec, privacy.shredding",
      "AES-256-GCM at rest for personal payloads, TLS 1.3 in transit, sealed "
      "credentials, sandboxed execution.",
      "Key management in production is the operator's; `KeyRing` is in-process."),
    C(F.GDPR, "Art. 33-34 — breach notification",
      "Notify the supervisory authority within 72 hours; notify subjects where "
      "high risk.",
      COV.PARTIAL, "compliance.incidents",
      "Breach classification with a 72-hour clock and a subject-notification "
      "assessment.",
      "Detection is what triggers the clock, and detection is weak — see "
      "DORA Art. 10."),
    C(F.GDPR, "Art. 35 — data protection impact assessment",
      "A DPIA is required for processing likely to result in high risk.",
      COV.GAP, "",
      "",
      "No DPIA is shipped. Systematic monitoring of individuals via agent "
      "activity plausibly triggers Art. 35(3)(a); an operator should assume one "
      "is needed and involve their DPO." " Covenant COV-04 carries the residual."),
    C(F.GDPR, "Ch. V (Art. 44-49) — international transfers",
      "Transfers outside the EEA need an adequacy decision or safeguards.",
      COV.PARTIAL, "compliance.residency, federation",
      "Residency policy enforced at peering time; transfers are refused unless "
      "the peer's jurisdiction is permitted.",
      "SCCs and a transfer impact assessment remain legal work."),

    # ── SOC 2 ──────────────────────────────────────────────────────────────
    C(F.SOC2, "CC6.1 — logical access",
      "Logical access security over protected information assets.",
      COV.IMPLEMENTED, "trustfirewall, trust.tiers",
      "Per-request credential verification and scope-gated mandates; every "
      "denial is audited.",
      "Session binding and the mandate gate cover access to the gateway. Your identity provider, and joiner-mover-leaver process, sit outside and are usually where the audit finding lands."),
    C(F.SOC2, "CC6.6 — access restricted to authorised users",
      "Authentication before access.",
      COV.IMPLEMENTED, "trustfirewall.stateless",
      "Call-bound credentials; unverified calls refused and metered.",
      "Graded reachability and abuse controls cover the network boundary. Physical and host-level access are yours."),
    C(F.SOC2, "CC6.7 — transmission and disposal",
      "Data protected in transit and disposed of securely.",
      COV.IMPLEMENTED, "security.xcpsec.mtls, privacy.shredding",
      "TLS 1.3 only; crypto-shredded disposal.",
      "TLS 1.3 in transit and crypto-shredding at rest. Disposal of the underlying media, and of backups, is an operational control."),
    C(F.SOC2, "CC7.2 — monitoring for anomalies",
      "Monitor system components for anomalies indicative of malicious acts.",
      COV.PARTIAL, "trustfirewall.limits, core.gateway metrics",
      "Rejection counters and metrics.",
      "No alerting or baselining; an operator must integrate a SIEM."),
    C(F.SOC2, "CC7.3-7.4 — incident response",
      "Evaluate security events and respond to identified incidents.",
      COV.PARTIAL, "compliance.incidents",
      "Classification and notification clocks.",
      "No tested incident response plan and no runbook — see gap register."),
    C(F.SOC2, "CC8.1 — change management",
      "Authorise, design, test and approve changes.",
      COV.PARTIAL, "CI, GOVERNANCE.md",
      "Tests gate every release; protocol changes need an RFC and a comment "
      "period; images are signed with provenance.",
      "Segregation of duties and formal approval records are organisational."),
    C(F.SOC2, "CC1 / CC2 / CC4 / CC5 — control environment",
      "Governance, communication, monitoring and control activities.",
      COV.OPERATOR, "",
      "",
      "Board oversight, HR screening, security awareness training and vendor "
      "management are organisational controls no codebase supplies." " Covenant COV-14 carries the residual."),
    C(F.SOC2, "A1 — availability",
      "Capacity, backup and recovery to meet commitments.",
      COV.GAP, "",
      "",
      "No SLO, no backup or restore procedure, no DR plan, no tested RTO/RPO." " Covenant COV-12 carries the residual."),

    # ── US and other ───────────────────────────────────────────────────────
    C(F.NIST_AI_RMF, "GOVERN 1.2 / MAP 2.3",
      "Accountability and traceability of AI system actions.",
      COV.ENABLER, "receipts, trust.tiers",
      "Attributable, signed records of which agent acted under whose authority.",
      "Voluntary framework; no certification exists."),
    C(F.NIST_CSF, "PR.AC / DE.CM / RS.RP",
      "Protect-access, detect-monitor, respond-planning.",
      COV.PARTIAL, "trustfirewall, compliance.incidents",
      "Access control and incident classification.",
      "Recovery (RC) functions are absent."),
    C(F.ISO_42001, "Clause 8 — AI system lifecycle",
      "Operational planning and control for AI systems.",
      COV.ENABLER, "receipts, privacy",
      "Logging and data governance surfaces.",
      "Certification requires a management system, not a library."),
    C(F.ISO_27001, "A.5.23 / A.8.16 — cloud services, monitoring",
      "Information security for cloud use and activity monitoring.",
      COV.PARTIAL, "trustfirewall, compliance.register", "",
      "Server trust classes and supply-chain pinning give you the technical half. Supplier due diligence, contracts and exit planning are the other half."),
    C(F.UK_GDPR, "Mirrors GDPR",
      "Substantively aligned with GDPR post-Brexit.",
      COV.PARTIAL, "privacy",
      "Same controls as GDPR.",
      "UK international transfer rules differ; check the IDTA."),
    C(F.CCPA, "§1798.105 / §1798.120 — deletion and opt-out",
      "Right to delete; right to opt out of sale or sharing.",
      COV.PARTIAL, "privacy.erasure",
      "Deletion via crypto-shredding.",
      "XCP does not sell or share personal data, so opt-out does not arise. "
      "'Do Not Sell' signalling is not implemented."),
    C(F.PIPL, "Art. 38-40 — cross-border transfer",
      "Security assessment or certification before transferring out of China.",
      COV.GAP, "",
      "Residency policy can block the transfer.",
      "CAC security assessment is a regulatory process, not a technical one." " Covenant COV-11 carries the residual."),
    C(F.LGPD, "Art. 18 — data subject rights", "Rights broadly mirroring GDPR.",
      COV.PARTIAL, "privacy", "Same mechanisms.", "Brazilian specifics unreviewed."),
    C(F.DPDP, "§12-13 — erasure and grievance",
      "Erasure on withdrawal of consent; grievance redressal.",
      COV.PARTIAL, "privacy.erasure", "Erasure mechanism.",
      "No grievance officer workflow."),
]


# ── views ──────────────────────────────────────────────────────────────────

def controls(framework: Optional[Framework] = None) -> list[Control]:
    return [c for c in CONTROLS if framework is None or c.framework == framework]


def gaps() -> list[Control]:
    """
    Everything required and not addressed. The most important output here: an
    adopter needs to know where the work still is before an auditor tells them.
    """
    return [c for c in CONTROLS if c.coverage is Coverage.GAP]


def operator_obligations() -> list[Control]:
    """Controls that are real but cannot be discharged by any codebase."""
    return [c for c in CONTROLS if c.coverage is Coverage.OPERATOR]


def summary() -> dict[str, Any]:
    from collections import Counter
    by_f: dict[str, Any] = {}
    for f in Framework:
        cs = controls(f)
        if not cs:
            continue
        by_f[f.value] = dict(Counter(c.coverage.value for c in cs))
    return {
        "disclaimer": (
            "This is a control mapping, not a compliance certification. "
            "Compliance is determined by counsel, and SOC 2 by a licensed CPA "
            "firm auditing your organisation over a period of observation. Most "
            "audited controls are organisational, not technical."),
        "xcpClassification": (
            "XCP is infrastructure: it verifies identity, gates authority and "
            "records what happened. It makes no inference and no decision about "
            "a person, so it is neither a high-risk AI system nor a "
            "general-purpose AI model under the EU AI Act. It is a compliance "
            "ENABLER for operators who deploy such systems."),
        "totals": dict(Counter(c.coverage.value for c in CONTROLS)),
        "byFramework": by_f,
        "gapCount": len(gaps()),
        "gaps": [{"framework": c.framework.value, "reference": c.reference,
                  "gap": c.gap_note} for c in gaps()],
    }


def evidence_index() -> list[dict[str, Any]]:
    """What an auditor can actually inspect, per control."""
    return [{"framework": c.framework.value, "reference": c.reference,
             "coverage": c.coverage.value, "implementedBy": c.implemented_by,
             "evidence": c.evidence}
            for c in CONTROLS if c.evidence]


__all__ = ["Framework", "Coverage", "Control", "CONTROLS", "controls", "gaps",
           "operator_obligations", "summary", "evidence_index"]


# ── added on review: obligations the first pass did not cover ──────────────
CONTROLS += [
    # The six-month log floor, and the conflict it creates.
    C(F.EU_AI_ACT, "Art. 19 / Art. 26(6) — six-month log floor",
      "Providers and deployers must keep automatically generated logs, to the "
      "extent under their control, for at least six months unless other Union "
      "or national law provides otherwise — in particular data protection law.",
      COV.IMPLEMENTED, "privacy.retention.AI_ACT_LOG_FLOOR",
      "security_audit retains for 190 days. Six CALENDAR months runs to 184 "
      "days, so a 180-day default sits under the floor — that was a real defect "
      "found on review, not a hypothetical.",
      "Confirm the floor applies to your system, and reconcile it against GDPR "
      "Art. 5(1)(e), which pulls the other way. compliance.reconcile_retention() "
      "surfaces every class where the two conflict."),

    C(F.EU_AI_ACT, "Art. 25 — responsibilities along the value chain",
      "Deployers and third parties become providers of a high-risk system in "
      "defined circumstances, including substantial modification.",
      COV.OPERATOR, "-",
      "XCP is a component, not a system.",
      "Whether building on XCP makes you a provider depends on what you build. "
      "Substantial modification and prompt engineering are the usual triggers. "
      "A legal question, not a technical one." " Covenant COV-02 carries the residual."),

    C(F.EU_AI_ACT, "Art. 27 — fundamental rights impact assessment",
      "Certain deployers must perform a FRIA before putting a high-risk system "
      "into use.",
      COV.ENABLER, "privacy.data_map, compliance.evidence_index",
      "The data map and control inventory are inputs to a FRIA.",
      "The assessment itself is a process obligation and is yours." " Covenant COV-05 carries the residual."),

    C(F.EU_AI_ACT, "Art. 50 — transparency to natural persons",
      "Persons must be informed when they interact with an AI system.",
      COV.GAP, "-",
      "XCP sits between an agent and its tools and has no interface to a human.",
      "The application built on top owes this disclosure. XCP cannot discharge "
      "it and does not attempt to." " Covenant COV-03 carries the residual."),

    C(F.EU_AI_ACT, "Art. 72 — post-market monitoring",
      "Providers must operate a post-market monitoring system proportionate to "
      "the risk.",
      COV.ENABLER, "core.gateway metrics, receipts.CallChain",
      "Metrics and hash-chained records feed a monitoring system.",
      "Operating one, and acting on what it shows, is organisational."),

    # DORA: the log-retention clause that does NOT set a floor.
    C(F.DORA, "Del. Reg. (EU) 2024/1774 Art. 12 — log retention",
      "Financial entities shall establish the retention period themselves, "
      "considering business and security objectives, the reason for the log, "
      "and the results of the ICT risk assessment.",
      COV.OPERATOR, "privacy.retention.CLASSES",
      "Retention is configurable per class.",
      "Deliberately no fixed floor here, unlike the AI Act — a common "
      "misreading is to import the six-month figure. The justification for "
      "whatever you choose is yours to document." " Covenant COV-08 carries the residual."),

    # NIS2
    C(F.NIS2, "Art. 21 — cybersecurity risk-management measures",
      "Essential and important entities must take appropriate technical and "
      "operational measures, including supply chain security and access control.",
      COV.PARTIAL, "security.xcpsec, trustfirewall, core.gateway",
      "Session binding, argument firewall, sandboxing, supply-chain manifest "
      "pinning and graded reachability.",
      "Covers one layer. Governance, training and the risk-management framework "
      "are yours. Transposition varies by member state — read your national "
      "implementation, not the directive."),

    C(F.NIS2, "Art. 23 — incident reporting",
      "Significant incidents must be reported: early warning within 24 hours, "
      "notification within 72 hours.",
      COV.ENABLER, "compliance.incidents, federation revocation",
      "Incident records and a revocation path that contains a compromise.",
      "Classification against the significance threshold and reporting on "
      "deadline are process obligations." " Covenant COV-13 carries the residual."),

    # Colorado — the binding US state AI law most likely to apply
    C(F.COLORADO_AI, "C.R.S. 6-1-1703 — deployer duty of reasonable care",
      "Deployers of high-risk AI must use reasonable care to protect consumers "
      "from algorithmic discrimination in consequential decisions. Effective "
      "30 June 2026 per SB25B-004.",
      COV.ENABLER, "receipts.CallChain, core.gateway audit",
      "Audit records evidence what a system actually did, for whom, under whose "
      "authority.",
      "Discrimination testing, impact assessment and consumer notice are yours. "
      "There is no federal US AI statute — EO 14110 was rescinded in January "
      "2025 — so US obligations sit in state law and sector regulators." " Covenant COV-06 carries the residual."),
]
