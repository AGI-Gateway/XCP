"""
compliance.resilience — close the gaps that are actually measurable.

Three of the residuals in the control mapping were recorded as "organisational"
when they are partly computable, and a gap you can measure should not be left to
a covenant:

  DORA Art. 29      concentration risk — whether an operator depends on one peer
  DORA Art. 24-27   resilience testing — whether the thing survives load
  SOC 2 A1          availability — what state must survive a restart, and how

What remains genuinely organisational stays in `compliance.covenants`. The point
of splitting them is that a covenant is a promise, and a promise is a weaker
control than a measurement.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional


# ── DORA Art. 29: concentration risk ───────────────────────────────────────

@dataclass
class ConcentrationReport:
    total_peers: int
    total_reachable_capability: int
    top_peer: str
    top_peer_share: float
    hhi: float                      # Herfindahl-Hirschman index, 0..1
    single_points: list[str] = field(default_factory=list)
    verdict: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"totalPeers": self.total_peers,
                "totalReachableCapability": self.total_reachable_capability,
                "topPeer": self.top_peer, "topPeerShare": round(self.top_peer_share, 3),
                "hhi": round(self.hhi, 3), "singlePoints": self.single_points,
                "verdict": self.verdict}


def concentration(capability_by_peer: dict[str, int],
                  critical: Optional[Iterable[str]] = None) -> ConcentrationReport:
    """
    Measure dependence on individual peers.

    `capability_by_peer` maps a peer to how much of your reachable capability it
    supplies — connectors, tools, whatever unit you route on. HHI is the standard
    concentration measure: 1.0 means everything comes from one peer.

    A `single point` is a capability only one peer supplies. Those matter more
    than the headline share: losing a peer that supplies 5% of your capability is
    survivable unless that 5% is the only route to something you need.
    """
    total = sum(capability_by_peer.values())
    if total == 0:
        return ConcentrationReport(0, 0, "", 0.0, 0.0, [],
                                   "no reachable capability to assess")
    shares = {p: n / total for p, n in capability_by_peer.items()}
    top = max(shares, key=shares.get)
    hhi = sum(s * s for s in shares.values())
    sp = sorted(critical or [])

    if hhi >= 0.5:
        verdict = (f"CONCENTRATED: {top} supplies {shares[top]:.0%}. DORA Art. 29 "
                   "asks you to assess this; an exit plan for that peer is the "
                   "usual mitigation.")
    elif hhi >= 0.25:
        verdict = f"moderate concentration (HHI {hhi:.2f}); {top} is the largest."
    else:
        verdict = f"well distributed across {len(shares)} peers (HHI {hhi:.2f})."
    if sp:
        verdict += (f" {len(sp)} capabilit{'y is' if len(sp)==1 else 'ies are'} "
                    "supplied by a single peer, which is the sharper risk.")
    return ConcentrationReport(len(shares), total, top, shares[top], hhi, sp, verdict)


def concentration_from_catalog(catalog: Any) -> ConcentrationReport:
    """Measure concentration over a live GlobalCatalog by vendor."""
    from collections import Counter
    counts: Counter = Counter()
    caps: dict[str, set] = {}
    for e in getattr(catalog, "ingested", {}).values():
        if not getattr(e, "routable", False):
            continue
        v = e.vendor or e.host or "unknown"
        counts[v] += 1
        caps.setdefault(e.category, set()).add(v)
    singles = sorted(c for c, vs in caps.items() if len(vs) == 1)
    return concentration(dict(counts), critical=singles)


# ── SOC 2 A1: what must survive a restart ──────────────────────────────────

@dataclass
class StateItem:
    name: str
    where: str
    rpo_seconds: int          # acceptable data loss
    rto_seconds: int          # acceptable time to restore
    loss_impact: str
    backup: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "where": self.where,
                "rpoSeconds": self.rpo_seconds, "rtoSeconds": self.rto_seconds,
                "lossImpact": self.loss_impact, "backup": self.backup}


#: Everything a node holds that matters if the process dies. Stated so an
#: operator can write a real recovery procedure instead of discovering the list
#: during an incident.
STATE: tuple[StateItem, ...] = (
    StateItem("node identity key", "operator secret backend", 0, 3600,
              "CATASTROPHIC: the node loses its identity and every attestation "
              "any peer ever made about it. Unlike a certificate, this cannot be "
              "rotated back.",
              "Back up XCP_NODE_KEY offline before first use. This is the one "
              "item where losing it is unrecoverable."),
    StateItem("sealing key (XCP_SEAL_PRIVATE)", "operator secret backend", 0, 300,
              "Every credential sealed to this wrapper stops opening. Callers "
              "must re-fetch the key and re-seal.",
              "Persist it; XCP_SEAL_PREVIOUS covers the rotation window."),
    StateItem("subject key ring", "operator secret backend", 0, 900,
              "Encrypted personal payloads become unreadable — indistinguishable "
              "from an erasure nobody requested.",
              "Back it up, and ensure deletions propagate to the backup or an "
              "erasure is not an erasure."),
    StateItem("routing ledger", "node storage", 3600, 3600,
              "Unclaimed transport receipts are lost, so the node cannot bill "
              "for that epoch. Payers are unaffected.",
              "Snapshot per epoch before committing."),
    StateItem("session bindings", "in-memory or registry", 604800, 60,
              "Callers re-open sessions. Bindings are capped at 7 days anyway.",
              "None needed; they are designed to be cheap to rebuild."),
    StateItem("discovery catalog", "snapshot + crawl", 86400, 600,
              "Rebuildable from the bundled snapshot and a re-crawl.",
              "None needed."),
)


def recovery_plan() -> dict[str, Any]:
    """The inputs to a DR procedure, with the unrecoverable item named first."""
    items = sorted(STATE, key=lambda s: (s.rto_seconds, -len(s.loss_impact)))
    return {
        "state": [s.to_dict() for s in items],
        "unrecoverable": [s.name for s in STATE if "CATASTROPHIC" in s.loss_impact],
        "worstRtoSeconds": max(s.rto_seconds for s in STATE),
        "note": ("RPO/RTO are targets this design can support, not a guarantee. "
                 "SOC 2 A1 asks whether you have tested recovery — a plan nobody "
                 "has rehearsed is not a control."),
    }


# ── DORA Art. 24-27: resilience testing ────────────────────────────────────

@dataclass
class ResilienceResult:
    scenario: str
    passed: bool
    observed: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"scenario": self.scenario, "passed": self.passed,
                "observed": self.observed, "note": self.note}


def degradation_scenarios() -> list[dict[str, str]]:
    """
    What a node must survive, and what "survive" means for each. Written down so
    resilience testing is repeatable rather than improvised, which is most of
    what DORA Art. 24-25 asks for at this layer.
    """
    return [
        {"scenario": "verifier unreachable",
         "expected": "gateway refuses calls (fail closed), does not route "
                     "unverified traffic, recovers without restart"},
        {"scenario": "upstream MCP server down",
         "expected": "502 to the caller, no retry storm, other upstreams "
                     "unaffected"},
        {"scenario": "flood from one caller",
         "expected": "that caller is throttled; other tiers keep working; the "
                     "global ceiling protects the node"},
        {"scenario": "flood from many rotating identities",
         "expected": "bounded memory — the limiter's LRU must not grow without "
                     "limit, or the defence becomes the vulnerability"},
        {"scenario": "peer serves a poisoned catalog",
         "expected": "ingested entries stay unknown/unverified; nothing "
                     "ingested can raise its own trust class"},
        {"scenario": "peer rotates its certificate mid-session",
         "expected": "peering survives; the binding sequence advances; trust "
                     "and hop counts are preserved"},
        {"scenario": "sealing key lost and regenerated",
         "expected": "wrapper refuses to start rather than silently "
                     "invalidating every sealed credential"},
    ]


__all__ = ["concentration", "concentration_from_catalog", "ConcentrationReport",
           "STATE", "StateItem", "recovery_plan", "degradation_scenarios",
           "ResilienceResult"]
