"""
compliance — control mapping, incident clocks, residency and the DORA register.

    from compliance import summary, gaps, open_incident, ResidencyPolicy

NOT a compliance certification. Compliance is determined by counsel, and SOC 2
by a licensed CPA firm auditing an organisation over a period of observation.
See compliance/frameworks.py, and read the gap register before relying on any
of it.
"""
from .frameworks import (Framework, Coverage, Control, CONTROLS, controls,
                         gaps, operator_obligations, summary, evidence_index)
from .incidents import (Incident, Obligation, Kind, Severity, classify,
                        open_incident, overdue, timeline)
from .residency import (ResidencyPolicy, ResidencyError, guard_peering,
                        jurisdiction_of, EEA, ADEQUATE, RESTRICTED_OUTBOUND)
from . import register

__all__ = ["Framework", "Coverage", "Control", "CONTROLS", "controls", "gaps",
           "operator_obligations", "summary", "evidence_index",
           "Incident", "Obligation", "Kind", "Severity", "classify",
           "open_incident", "overdue", "timeline",
           "ResidencyPolicy", "ResidencyError", "guard_peering",
           "jurisdiction_of", "EEA", "ADEQUATE", "RESTRICTED_OUTBOUND",
           "register"]
from .reconcile import (Conflict, reconcile_retention, unresolved,
                        summary as retention_summary, apply_ai_act_floor,
                        AI_ACT_LOG_CLASSES)

__all__ = list(globals().get("__all__", [])) + [
    "Conflict", "reconcile_retention", "unresolved", "retention_summary",
    "apply_ai_act_floor", "AI_ACT_LOG_CLASSES"]
