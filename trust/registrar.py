"""
trust.registrar — who vouches for an agent, and how much that is worth.

THE PROBLEM THIS FIXES
----------------------
XCP's trust lattice has always said that A0 means "self-asserted keypair" and
A2 means "a legal entity signs the root". That is a statement about WHO VOUCHED,
and it never actually required a blockchain. The implementation did, though:
`session/open` refused any request without a non-zero ERC-8004 `agentId`, and
the production profile refused to start without a verifier. So the only
chain-free path was the development profile, which self-registers anything and
is therefore not a trust layer at all.

The practical effect was an adoption wall out of proportion to the design.
Every organisation already has a certificate authority and an identity
provider. Almost none has an on-chain agent registry. Requiring one to reach
*any* production tier meant the lattice's value could only be realised after a
substrate nobody had deployed.

A registrar is the thing that vouches for an agent when a session opens. The
chain is one registrar. It is no longer the premise.

WHAT EACH REGISTRAR CAN JUSTIFY
-------------------------------
The important property is that this does NOT make tiers cheaper. Each registrar
declares the highest agent tier it can honestly support, and the lattice's
meaning is unchanged:

    none    A0   Self-asserted. The agent presents a key and nothing else
                 corroborates it. This is exactly what A0 has always meant, so
                 it is not a downgrade -- it is A0 finally being reachable
                 without pretending to be something else. Development only:
                 a node that accepts self-assertion from strangers is an open
                 relay with good logging.

    mtls    A1   The operator's own CA signed this agent's certificate. Someone
                 with a key management process decided this workload exists and
                 may hold an identity. That is materially stronger than
                 self-assertion and materially weaker than a legal entity
                 signing a public root, which is why it lands at A1.

    oidc    A1   The operator's identity provider will attest this workload.
                 Same reasoning as mtls: a real issuance process, scoped to one
                 organisation's say-so.

    chain   A2   An ERC-8004 registry entry backed by an identity that can be
                 checked by someone who does not trust the operator. This is
                 the only registrar that means anything to a peer in a
                 different organisation, which is precisely what A2 claims.

WHY A1 IS THE INTERESTING NUMBER
--------------------------------
A1xH2 -- an internal CA for the agent, an enterprise IdP for the human -- is
"Delegated corporate": chain scopes, three payment rails, a 250,000 minor-unit
ceiling, metered settlement with receipts, full enforcement. That is a
thoroughly capable production deployment, and it needs no blockchain at all.

So the honest summary is: the chain buys A2 and cross-organisational
verifiability. Everything up to A1xH2 runs on the PKI and IdP you already have.

RAISING THE CEILING IS POSSIBLE AND DELIBERATELY AWKWARD
--------------------------------------------------------
An operator can raise a registrar's ceiling, because there are real deployments
where an internal CA genuinely is a legal entity signing -- a bank's own PKI
vouching for its own agents inside its own federation. `XCP_REGISTRAR_CEILING`
does it, `ceiling_is_raised()` reports it, and the node record publishes it, so
a peer can see the claim and decide what it is worth. What an operator cannot
do is raise it quietly: this is a federated system, and a node asserting A2 on
the strength of its own CA is making a claim about itself that its peers are
entitled to discount.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from .tiers import AgentTier

__all__ = ["Registrar", "Attestation", "RegistrarError", "RegistrarConfig",
           "CEILINGS", "from_env", "describe"]


class RegistrarError(Exception):
    """A registrar that cannot do what it was configured to do."""


class Registrar(str, Enum):
    NONE = "none"
    MTLS = "mtls"
    OIDC = "oidc"
    CHAIN = "chain"


#: The highest agent tier each registrar can justify without an operator
#: deliberately overriding it. See the module docstring for the reasoning.
CEILINGS: dict[Registrar, AgentTier] = {
    Registrar.NONE: AgentTier.FREE,
    Registrar.MTLS: AgentTier.REGISTRY,
    Registrar.OIDC: AgentTier.REGISTRY,
    Registrar.CHAIN: AgentTier.COMPANY,
}

#: Registrars that may be used in the production profile. `none` is absent on
#: purpose: self-registration is not a trust decision, it is the absence of one.
PRODUCTION_SAFE = frozenset({Registrar.MTLS, Registrar.OIDC, Registrar.CHAIN})


@dataclass(frozen=True)
class Attestation:
    """
    What a registrar established about an agent when its session opened.

    `subject` is a stable identifier inside the registrar's own namespace -- a
    certificate subject, an OIDC `sub`, or the decimal agent id for a chain
    registry. It is NOT globally unique across registrars, and nothing should
    treat it as though it were: two organisations can both have a workload
    called `svc-reconciliation`, and the thing that distinguishes them is which
    node attested it.

    `agent_id` is 0 for every registrar that does not issue numeric identifiers.
    That is why the wire format tolerates it: the footprint is the identity at
    these tiers, which is what "self-asserted keypair" and "the CA vouched for
    this certificate" both actually mean.
    """
    registrar: Registrar
    subject: str
    footprint: str
    agent_id: int = 0
    #: The highest tier this attestation supports. Never above the registrar's
    #: ceiling; the gateway takes min() of this and whatever the agent claims.
    agent_tier: AgentTier = AgentTier.FREE
    reason: str = ""

    @property
    def ok(self) -> bool:
        return not self.reason

    def to_dict(self) -> dict[str, Any]:
        return {"registrar": self.registrar.value, "subject": self.subject,
                "footprint": self.footprint, "agentId": self.agent_id,
                "agentTier": int(self.agent_tier), "reason": self.reason or None}

    @classmethod
    def refused(cls, registrar: "Registrar", reason: str) -> "Attestation":
        return cls(registrar=registrar, subject="", footprint="",
                   agent_tier=AgentTier.FREE, reason=reason)


@dataclass(frozen=True)
class RegistrarConfig:
    kind: Registrar
    ceiling: AgentTier
    #: Where the registrar's authority comes from, for the node record. A CA
    #: bundle path, an OIDC issuer URL, or a verifier URL.
    authority: str = ""
    #: True when the operator raised the ceiling above this registrar's
    #: default. Published, because a peer is entitled to discount it.
    raised: bool = False

    def permits_production(self) -> tuple[bool, str]:
        if self.kind not in PRODUCTION_SAFE:
            return False, (
                f"registrar {self.kind.value!r} accepts self-asserted "
                f"identities, which is not a trust decision but the absence of "
                f"one. Set XCP_REGISTRAR to mtls, oidc or chain, or run the "
                f"development profile deliberately.")
        if self.kind in (Registrar.MTLS, Registrar.OIDC) and not self.authority:
            return False, (
                f"registrar {self.kind.value!r} has no authority configured, "
                f"so nothing would actually be checked. Set "
                f"{'XCP_PEER_CA_BUNDLE' if self.kind is Registrar.MTLS else 'XCP_OIDC_ISSUER'}.")
        if self.kind is Registrar.CHAIN and not self.authority:
            return False, ("registrar 'chain' needs XCP_VERIFY_URL; without a "
                           "verifier there is no registry to consult.")
        return True, ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value,
                "agentCeiling": int(self.ceiling),
                "ceilingRaised": self.raised,
                # The authority is named, never its contents: an OIDC issuer
                # URL is public, a CA bundle path is not interesting, and
                # neither is a secret. A peer needs to know WHAT vouches, not
                # where the file lives.
                "authorityConfigured": bool(self.authority)}


def _tier_from_name(name: str) -> Optional[AgentTier]:
    n = name.strip().upper()
    for t in AgentTier:
        if n in (t.name, f"A{int(t)}", str(int(t))):
            return t
    return None


def from_env(env: Optional[dict[str, str]] = None) -> RegistrarConfig:
    """
    Resolve the registrar from configuration.

    Defaults to `none`, which the production profile then refuses. That is the
    right default for a project someone has just cloned: it runs, it is honest
    about being a development posture, and it will not start in production
    until the operator has said what vouches for their agents.
    """
    e = env if env is not None else os.environ
    raw = (e.get("XCP_REGISTRAR") or "").strip().lower()

    if not raw:
        # Inferred, so an operator who configured a verifier does not also have
        # to name the registrar. Explicit configuration always wins.
        raw = "chain" if e.get("XCP_VERIFY_URL") else "none"

    try:
        kind = Registrar(raw)
    except ValueError:
        raise RegistrarError(
            f"XCP_REGISTRAR={raw!r} is not one of "
            f"{sorted(r.value for r in Registrar)}")

    authority = {
        Registrar.CHAIN: e.get("XCP_VERIFY_URL", ""),
        Registrar.MTLS: e.get("XCP_PEER_CA_BUNDLE", "") or e.get("XCP_CLIENT_CA_BUNDLE", ""),
        Registrar.OIDC: e.get("XCP_OIDC_ISSUER", ""),
        Registrar.NONE: "",
    }[kind]

    default_ceiling = CEILINGS[kind]
    ceiling, raised = default_ceiling, False
    want = (e.get("XCP_REGISTRAR_CEILING") or "").strip()
    if want:
        t = _tier_from_name(want)
        if t is None:
            raise RegistrarError(
                f"XCP_REGISTRAR_CEILING={want!r} is not an agent tier; use "
                f"A0, A1 or A2")
        if int(t) > int(default_ceiling):
            # Permitted, and recorded. See the module docstring: there are real
            # deployments where an internal CA is a legal entity signing, and
            # the system's answer to that is publication rather than refusal.
            ceiling, raised = t, True
        else:
            # Lowering is always fine and needs no announcement: an operator
            # choosing to trust their own registrar less is not a claim anyone
            # else has to evaluate.
            ceiling = t

    return RegistrarConfig(kind=kind, ceiling=ceiling, authority=authority,
                           raised=raised)


def describe(cfg: RegistrarConfig) -> str:
    """One line for the startup banner, so the posture is visible in logs."""
    base = f"registrar={cfg.kind.value} agent-ceiling=A{int(cfg.ceiling)}"
    if cfg.raised:
        base += (f" (RAISED above the default A{int(CEILINGS[cfg.kind])} for "
                 f"this registrar; peers may discount it)")
    if cfg.kind is Registrar.NONE:
        base += " — self-asserted identities; development only"
    return base
