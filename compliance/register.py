"""
compliance.register — the DORA Art. 28(3) register of information.

A financial entity must maintain a register of every contractual arrangement for
ICT services, and must be able to hand it to a competent authority. Federation
makes that harder than usual: each peer is effectively a subcontractor, and a
peer's own peers are a subcontracting chain the entity is still accountable for.

This generates the register from what the node actually knows, rather than from
a spreadsheet somebody maintains by hand and forgets.

Status: draft. The RTS prescribes specific templates and fields; this produces
the facts to populate them, not the submission itself.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from .residency import ResidencyPolicy, jurisdiction_of


def build(peers: list, *, entity: str = "", policy: Optional[ResidencyPolicy] = None,
          critical_functions: Optional[list] = None,
          now: Optional[int] = None) -> dict[str, Any]:
    """
    `peers` is an iterable of federation Peer objects or plain dicts with at
    least `domain`.
    """
    pol = policy or ResidencyPolicy()
    rows = []
    for p in peers:
        domain = getattr(p, "domain", None) or (p.get("domain") if isinstance(p, dict) else "")
        if not domain:
            continue
        node_id = getattr(p, "node_id", "") or (p.get("node_id", "") if isinstance(p, dict) else "")
        trust = getattr(p, "trust", None)
        ok, why = pol.may_peer(domain)
        rows.append({
            "provider": domain,
            "providerId": node_id[:18] + "…" if node_id else "",
            "serviceType": "ICT service — agent traffic routing and verification",
            "jurisdiction": jurisdiction_of(domain),
            "dataLocationPermitted": ok,
            "residencyNote": why,
            "relationship": "subcontractor (federated peer)",
            "trustLevel": getattr(trust, "label", str(trust)) if trust else "unknown",
            "supportsCriticalFunction": bool(critical_functions),
            "substitutable": True,
            "exitMechanism": "de-peer; no data is held by the peer on our behalf "
                             "beyond what was routed to it",
        })
    return {
        "generatedAt": now or int(time.time()),
        "entity": entity or "(set your entity name)",
        "regulation": "DORA (EU) 2022/2554 Art. 28(3)",
        "arrangements": rows,
        "count": len(rows),
        "blockedByResidency": [r["provider"] for r in rows
                               if not r["dataLocationPermitted"]],
        "concentrationNote": (
            "Federation is many-node by design and no single peer is "
            "structurally required, which is the technical answer to Art. 29. "
            "Whether this operator has concentrated in practice is theirs to "
            "assess."),
        "limitations": (
            "Covers federated peers only. ICT arrangements outside XCP — cloud "
            "hosting, identity providers, secret backends, payment rails — must "
            "be added by the operator. The RTS prescribes templates; this "
            "supplies the facts, not the submission."),
    }


__all__ = ["build"]
