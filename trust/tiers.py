"""
trust.tiers — the XCP trust lattice.

Agent identity tier × human identity tier resolves to exactly one *mandate
template*: the scopes, payment rails, session TTL and spend ceiling a session is
allowed to carry. This is the self-serve enrolment surface — an organisation
picks (or earns) a tier and gets a deterministic authority envelope, instead of
negotiating bespoke permissions.

    AGENT TIERS (what backs the agent)          HUMAN TIERS (what backs the person)
    A0 FREE      self-asserted keypair          H0 PUBLIC      anonymous, no principal
    A1 REGISTRY  ERC-8004 identity + reputation H1 GENERAL_SSO consumer IdP (Google/MS/Meta)
    A2 COMPANY   a legal entity signs the root  H2 ENTERPRISE  employer IdP + entitlements

Resolution rule
---------------
The effective ceiling is the *weaker leg* — an unbacked agent operating under a
corporate human is still an unbacked agent. One deliberate exception: a
company-backed agent running autonomously (A2 × H0) is NOT capped by the missing
human, because the company itself is the principal. Without that carve-out the
lattice would forbid the most common enterprise case: unattended service agents.

Entitlements
------------
When the human tier is ENTERPRISE, entitlement attributes from the IdP (groups,
cost centre, approval limit) further *narrow* the envelope. They can only
restrict, never widen — an entitlement cannot grant a scope the tier does not
already allow.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Optional


class AgentTier(IntEnum):
    """What stands behind the agent."""
    FREE = 0        # self-asserted, ephemeral keypair
    REGISTRY = 1    # ERC-8004 identity + reputation, ARD catalog entry
    COMPANY = 2     # a legal entity signs the mandate root

    @property
    def label(self) -> str:
        return {0: "A0 · Free", 1: "A1 · Registry", 2: "A2 · Company"}[int(self)]


class HumanTier(IntEnum):
    """What stands behind the person the agent acts for."""
    PUBLIC = 0        # anonymous — no principal
    GENERAL_SSO = 1   # consumer IdP: Google / Microsoft / Meta / Apple
    ENTERPRISE = 2    # employer IdP + entitlement attributes

    @property
    def label(self) -> str:
        return {0: "H0 · Public", 1: "H1 · General SSO", 2: "H2 · Enterprise SSO"}[int(self)]


class Rail(IntEnum):
    """railsBitmap bits — which settlement rails a session may use."""
    X402 = 1 << 0
    AP2 = 1 << 1
    MPP = 1 << 2
    ACP = 1 << 3


HOUR = 3600
DAY = 24 * HOUR
MAX_TTL = 7 * DAY          # protocol cap on a session binding


@dataclass
class MandateTemplate:
    """The authority envelope a lattice cell resolves to."""
    cell: str                       # e.g. "A2xH2"
    name: str                       # human-readable cell name
    scopes: list[str]               # granted scope patterns
    rails: int                      # railsBitmap
    ttl_seconds: int                # session binding lifetime (<= MAX_TTL)
    spend_cap_minor: int            # per-session ceiling, minor units (0 = none)
    settlement: str                 # none | escrow | metered | full
    posture: str                    # observe | enforce
    requires_receipt: bool          # settlement needs proof-of-delivery
    notes: str = ""

    def rails_list(self) -> list[str]:
        return [r.name for r in Rail if self.rails & r]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["railsList"] = self.rails_list()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


# ── the lattice ────────────────────────────────────────────────────────────
# Read bottom-left (least authority) to top-right (most).

# Scope vocabulary aligned with MCP 2026-07-28: these are exactly the scopes
# `trustfirewall.scope_for()` derives from the mandatory Mcp-Method / Mcp-Name
# headers, so the lattice and the firewall speak the same language.
_READ = [
    "mcp:tools/list",
    "mcp:resources/list", "mcp:resources/read",
    "mcp:prompts/*",                 # prompts/get is name-parameterised
    "mcp:completion/complete",
    "mcp:tasks/get", "mcp:tasks/list",
]
_WRITE = _READ + ["mcp:tools/*", "a2a:delegate/*"]
_CHAIN = _WRITE + ["t2t:chain/*"]

_LATTICE: dict[tuple[int, int], MandateTemplate] = {
    # ---- A0 FREE ----------------------------------------------------------
    (AgentTier.FREE, HumanTier.PUBLIC): MandateTemplate(
        cell="A0xH0", name="Sandbox",
        scopes=list(_READ), rails=0, ttl_seconds=1 * HOUR,
        spend_cap_minor=0, settlement="none", posture="enforce",
        requires_receipt=False,
        notes="Read-only, rate-limited front door. No principal to bill or hold liable."),
    (AgentTier.FREE, HumanTier.GENERAL_SSO): MandateTemplate(
        cell="A0xH1", name="Metered",
        scopes=list(_WRITE), rails=int(Rail.X402), ttl_seconds=4 * HOUR,
        spend_cap_minor=500, settlement="metered", posture="enforce",
        requires_receipt=True,
        notes="Cheap writes against a personal cap; the verified human bears liability."),
    (AgentTier.FREE, HumanTier.ENTERPRISE): MandateTemplate(
        cell="A0xH2", name="Shadowed",
        scopes=list(_READ), rails=0, ttl_seconds=1 * HOUR,
        spend_cap_minor=0, settlement="none", posture="observe",
        requires_receipt=False,
        notes="Corporate human but unbacked agent: observe mode, audit-only, no settlement. "
              "Capped by the weaker leg — register the agent to unlock."),

    # ---- A1 REGISTRY ------------------------------------------------------
    (AgentTier.REGISTRY, HumanTier.PUBLIC): MandateTemplate(
        cell="A1xH0", name="Open marketplace",
        scopes=list(_WRITE), rails=int(Rail.X402), ttl_seconds=8 * HOUR,
        spend_cap_minor=2_000, settlement="escrow", posture="enforce",
        requires_receipt=True,
        notes="Reputation-bearing agent with no human principal — escrowed settlement only."),
    (AgentTier.REGISTRY, HumanTier.GENERAL_SSO): MandateTemplate(
        cell="A1xH1", name="Consumer commerce",
        scopes=list(_CHAIN), rails=int(Rail.X402 | Rail.AP2), ttl_seconds=1 * DAY,
        spend_cap_minor=25_000, settlement="metered", posture="enforce",
        requires_receipt=True,
        notes="Personal spend cap tied to a verified individual; marketplace counterparties."),
    (AgentTier.REGISTRY, HumanTier.ENTERPRISE): MandateTemplate(
        cell="A1xH2", name="Delegated corporate",
        scopes=list(_CHAIN), rails=int(Rail.X402 | Rail.AP2 | Rail.MPP), ttl_seconds=1 * DAY,
        spend_cap_minor=250_000, settlement="metered", posture="enforce",
        requires_receipt=True,
        notes="Budget and counterparties narrowed by entitlement attributes from the IdP."),

    # ---- A2 COMPANY -------------------------------------------------------
    (AgentTier.COMPANY, HumanTier.PUBLIC): MandateTemplate(
        cell="A2xH0", name="Service agent",
        scopes=list(_CHAIN), rails=int(Rail.X402 | Rail.AP2), ttl_seconds=1 * DAY,
        spend_cap_minor=100_000, settlement="metered", posture="enforce",
        requires_receipt=True,
        notes="Autonomous under the company's own liability — the company IS the principal. "
              "Deliberately NOT capped by the absent human."),
    (AgentTier.COMPANY, HumanTier.GENERAL_SSO): MandateTemplate(
        cell="A2xH1", name="Professional",
        scopes=list(_CHAIN), rails=int(Rail.X402 | Rail.AP2 | Rail.MPP), ttl_seconds=1 * DAY,
        spend_cap_minor=500_000, settlement="metered", posture="enforce",
        requires_receipt=True,
        notes="Company agent acting for one individual; contract-scoped."),
    (AgentTier.COMPANY, HumanTier.ENTERPRISE): MandateTemplate(
        cell="A2xH2", name="Full settlement",
        scopes=list(_CHAIN) + ["pay:*"],
        rails=int(Rail.X402 | Rail.AP2 | Rail.MPP | Rail.ACP), ttl_seconds=MAX_TTL,
        spend_cap_minor=0, settlement="full", posture="enforce",
        requires_receipt=True,
        notes="Enterprise ↔ enterprise. Entitlement-bound budget, all rails, complete audit. "
              "spend_cap 0 = no protocol cap; the entitlement supplies the real limit."),
}


class TierError(Exception):
    pass


@dataclass
class Entitlements:
    """Attributes asserted by an enterprise IdP. These NARROW the envelope."""
    groups: list[str] = field(default_factory=list)
    cost_center: str = ""
    approval_limit_minor: Optional[int] = None    # hard budget from the employer
    allowed_scopes: Optional[list[str]] = None    # if set, intersect with the tier's
    denied_scopes: list[str] = field(default_factory=list)


def resolve(agent: AgentTier, human: HumanTier,
            entitlements: Optional[Entitlements] = None) -> MandateTemplate:
    """
    Resolve a lattice cell to its mandate template, then apply entitlements.

        tpl = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE,
                      Entitlements(approval_limit_minor=50_000))
    """
    key = (AgentTier(agent), HumanTier(human))
    if key not in _LATTICE:
        raise TierError(f"no lattice cell for {key}")
    base = _LATTICE[key]
    # copy so callers can't mutate the table
    tpl = MandateTemplate(**{k: (list(v) if isinstance(v, list) else v)
                             for k, v in asdict(base).items()})
    if entitlements:
        tpl = _apply_entitlements(tpl, entitlements)
    if tpl.ttl_seconds > MAX_TTL:
        tpl.ttl_seconds = MAX_TTL
    return tpl


def _apply_entitlements(tpl: MandateTemplate, ent: Entitlements) -> MandateTemplate:
    """Entitlements may only restrict. They can never widen the tier envelope."""
    if ent.allowed_scopes is not None:
        # intersection by exact match or prefix coverage
        tpl.scopes = [s for s in tpl.scopes
                      if any(_covers(a, s) or _covers(s, a) for a in ent.allowed_scopes)]
    if ent.denied_scopes:
        tpl.scopes = [s for s in tpl.scopes
                      if not any(_covers(d, s) for d in ent.denied_scopes)]
    if ent.approval_limit_minor is not None:
        if tpl.spend_cap_minor == 0:
            tpl.spend_cap_minor = ent.approval_limit_minor
        else:
            tpl.spend_cap_minor = min(tpl.spend_cap_minor, ent.approval_limit_minor)
        if tpl.spend_cap_minor == 0:
            tpl.settlement = "none"
            tpl.rails = 0
    if ent.cost_center:
        tpl.notes = (tpl.notes + f" Cost centre: {ent.cost_center}.").strip()
    return tpl


def _covers(granted: str, requested: str) -> bool:
    """Single trailing-wildcard prefix coverage, matching the gateway's rule."""
    if granted.endswith("*"):
        return requested.startswith(granted[:-1])
    return granted == requested


def next_upgrade(agent: AgentTier, human: HumanTier) -> Optional[str]:
    """
    What the operator should do next to gain authority. Powers the self-serve
    'upgrade path' in the CLI and console.
    """
    if agent < AgentTier.COMPANY:
        nxt = AgentTier(int(agent) + 1)
        how = ("Register the agent in the ERC-8004 identity registry and publish an "
               "ARD catalog entry." if nxt == AgentTier.REGISTRY else
               "Have a legal entity sign the agent's mandate root (domain + org key).")
        return f"Agent {agent.label} → {nxt.label}: {how}"
    if human < HumanTier.ENTERPRISE:
        nxt = HumanTier(int(human) + 1)
        how = ("Add a consumer SSO login so a verified human principal exists."
               if nxt == HumanTier.GENERAL_SSO else
               "Connect your enterprise IdP (SAML/OIDC) and map entitlement attributes.")
        return f"Human {human.label} → {nxt.label}: {how}"
    return None


def lattice_table() -> list[dict[str, Any]]:
    """The whole lattice, for docs/UI rendering."""
    out = []
    for a in AgentTier:
        for h in HumanTier:
            t = _LATTICE[(a, h)]
            out.append({"agent": a.label, "human": h.label, **t.to_dict()})
    return out


def session_binding(agent: AgentTier, human: HumanTier, footprint: str,
                    agent_id: int, entitlements: Optional[Entitlements] = None
                    ) -> dict[str, Any]:
    """
    Render a lattice decision into the fields an XCP Session Registry binding
    carries, so the tier system plugs straight into the existing gateway.
    """
    tpl = resolve(agent, human, entitlements)
    return {
        "agentId": agent_id,
        "certFootprint": footprint,
        "railsBitmap": tpl.rails,
        "ttlSeconds": tpl.ttl_seconds,
        "posture": tpl.posture,
        "scopes": tpl.scopes,
        "spendCapMinor": tpl.spend_cap_minor,
        "settlement": tpl.settlement,
        "requiresReceipt": tpl.requires_receipt,
        "tier": tpl.cell,
        "tierName": tpl.name,
    }


__all__ = [
    "AgentTier", "HumanTier", "Rail", "MandateTemplate", "Entitlements",
    "resolve", "next_upgrade", "lattice_table", "session_binding",
    "TierError", "MAX_TTL",
]
