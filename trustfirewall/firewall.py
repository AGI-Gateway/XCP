"""
trustfirewall.firewall — the Trust Firewall.

A firewall decides whether a packet may pass. A *trust* firewall decides whether
a call may pass, using identity and authority rather than IP and port — and it
does it from headers, at the speed the rest of your edge already runs.

MCP 2026-07-28 made this possible by mandating two routing headers,
`Mcp-Method` and `Mcp-Name`, so infrastructure can act on a request without
opening the JSON body. XCP's scope grammar (`mcp:tools/<tool>`) already had the
same shape, so the translation is direct:

    Mcp-Method: tools/call
    Mcp-Name:   search              →   scope  mcp:tools/search
    XCP-Request-Credential: …           verify statelessly, check scope, decide

THE POINT: CONSUMING THE WHOLE CORPUS SAFELY
--------------------------------------------
There are tens of thousands of reachable MCP servers, and a large share of them
are unauthenticated. The instinct is to allowlist a handful and ignore the rest.
That is safe and useless.

The Trust Firewall takes the other route: **the whole corpus is reachable, and
the terms of engagement vary.** Two axes decide those terms:

    what backs the CALLER   (the trust lattice: agent tier × human tier)
    what backs the SERVER   (its trust class: unknown → probed → attested → contracted)

Their intersection yields *graded reachability* — allowed or not, in which
posture, with which scope family, whether settlement may occur, and what
obligations the caller inherits (sandbox the execution, quarantine the output,
require a delivery receipt). An unknown server is not blocked; it is reachable
in observe mode, read-only, sandboxed, with its output treated as untrusted
content. That is how an organisation consumes 20k+ servers without pretending
they are all trustworthy.

WHAT THIS IS NOT
----------------
Since MCP 2026-07-28, any WAF or API gateway can route, throttle and meter per
tool from those same two headers. That part is commodity and getting more so.
The Trust Firewall is not competing there. What it adds is the part a WAF
structurally cannot do: bind the call to a verified agent identity, check it
against a signed mandate, grade it against the counterparty's trust class, and
carry a spend ceiling and a receipt obligation into settlement.

Status: XCP and ERC-8004x are draft proposals. MCP is an independent
specification; this targets the 2026-07-28 revision.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Mapping, Optional

from .stateless import (McpRequest, RequestCredential, verify as verify_cred,
                        scope_for, MCP_SPEC_TARGET)


class ServerClass(IntEnum):
    """What backs the *server* on the other end. Ascending trust."""
    UNKNOWN = 0      # discovered in the corpus; never probed
    PROBED = 1       # passed the safety gate: auth required, no SSRF, clean tool metadata
    ATTESTED = 2     # publisher-signed, digest-pinned manifest (supply chain verified)
    CONTRACTED = 3   # a legal entity stands behind it (agreement + org key)

    @property
    def label(self) -> str:
        return {0: "unknown", 1: "probed", 2: "attested", 3: "contracted"}[int(self)]


class Effect(IntEnum):
    DENY = 0
    OBSERVE = 1      # allowed, logged, but nothing binding — no settlement
    ALLOW = 2


# Scope families that only read. Everything else can mutate or spend.
_READ_METHODS = {"tools/list", "resources/list", "resources/read",
                 "prompts/list", "prompts/get", "completion/complete",
                 "tasks/get", "tasks/list"}


def is_read_only(mcp_method: str) -> bool:
    return (mcp_method or "").strip() in _READ_METHODS


@dataclass
class Obligations:
    """What the caller must do because of *who* they are talking to."""
    sandbox_execution: bool = False     # run results/tools under xcpsec.sandbox
    quarantine_output: bool = False     # wrap in an untrusted-content boundary
    require_receipt: bool = False       # settlement needs proof-of-delivery
    scan_arguments: bool = True         # argument firewall before forwarding
    max_scope: str = "full"             # "read" | "full"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sandboxExecution": self.sandbox_execution,
            "quarantineOutput": self.quarantine_output,
            "requireReceipt": self.require_receipt,
            "scanArguments": self.scan_arguments,
            "maxScope": self.max_scope,
        }


@dataclass
class Decision:
    effect: Effect
    scope: str
    reason: str = ""
    server_class: ServerClass = ServerClass.UNKNOWN
    tier: str = ""
    obligations: Obligations = field(default_factory=Obligations)
    settlement: str = "none"            # none | escrow | metered | full
    spend_cap_minor: int = 0
    warnings: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)   # audit trail of what ran

    @property
    def allowed(self) -> bool:
        return self.effect != Effect.DENY

    @property
    def binding(self) -> bool:
        """True when the call may have real-world effect (not observe-only)."""
        return self.effect == Effect.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect.name.lower(),
            "scope": self.scope,
            "reason": self.reason,
            "serverClass": self.server_class.label,
            "tier": self.tier,
            "settlement": self.settlement,
            "spendCapMinor": self.spend_cap_minor,
            "obligations": self.obligations.to_dict(),
            "warnings": self.warnings,
            "checks": self.checks,
        }


# ── graded reachability: caller tier × server class ────────────────────────

def reachability(agent_tier: int, server_class: ServerClass,
                 read_only: bool) -> tuple[Effect, str, Obligations, str]:
    """
    The heart of the firewall. Returns (effect, settlement, obligations, note).

    Design rules, stated so they can be argued with:

    · An UNKNOWN server is never blocked outright — it is reachable in OBSERVE,
      read-only, sandboxed, with output quarantined. Blocking the unvetted
      majority of the corpus is what makes people bypass the gateway.
    · Nothing binding happens against an UNKNOWN server, at any caller tier.
      Reachability is not endorsement.
    · Writes require the server to be at least PROBED, and the caller to be at
      least REGISTRY (A1). A free agent may read the world; it may not change it.
    · Settlement requires ATTESTED or better *and* a caller who can be held to
      account. Money never moves toward an anonymous counterparty.
    · Output from anything below CONTRACTED is treated as untrusted content,
      because a well-behaved server can still return a prompt injection.
    """
    ob = Obligations()

    # Untrusted counterparty: always quarantine what comes back.
    ob.quarantine_output = server_class < ServerClass.CONTRACTED
    ob.sandbox_execution = server_class <= ServerClass.PROBED

    # --- UNKNOWN: reachable, but nothing counts ---
    if server_class == ServerClass.UNKNOWN:
        if not read_only:
            return (Effect.DENY, "none", ob,
                    "unvetted server: mutating calls refused until it passes the safety gate")
        ob.max_scope = "read"
        return (Effect.OBSERVE, "none", ob,
                "unvetted server: read-only, observed, output quarantined")

    # --- PROBED: passed the safety gate ---
    if server_class == ServerClass.PROBED:
        if read_only:
            return (Effect.ALLOW, "none", ob, "probed server: reads permitted")
        if agent_tier < 1:                      # A0 FREE
            ob.max_scope = "read"
            return (Effect.DENY, "none", ob,
                    "free-tier agent may not mutate state; register the agent to unlock writes")
        ob.require_receipt = True
        return (Effect.ALLOW, "escrow", ob,
                "probed server: writes permitted, settlement escrowed")

    # --- ATTESTED: signed, digest-pinned manifest ---
    if server_class == ServerClass.ATTESTED:
        if read_only:
            return (Effect.ALLOW, "none", ob, "attested server: reads permitted")
        if agent_tier < 1:
            ob.max_scope = "read"
            return (Effect.DENY, "none", ob, "free-tier agent may not mutate state")
        ob.require_receipt = True
        settlement = "metered" if agent_tier >= 1 else "escrow"
        return (Effect.ALLOW, settlement, ob,
                "attested server: metered settlement against a pinned manifest")

    # --- CONTRACTED: a legal entity stands behind it ---
    if read_only:
        return (Effect.ALLOW, "none", ob, "contracted server: reads permitted")
    if agent_tier < 1:
        ob.max_scope = "read"
        return (Effect.DENY, "none", ob, "free-tier agent may not mutate state")
    ob.require_receipt = True
    settlement = "full" if agent_tier >= 2 else "metered"
    return (Effect.ALLOW, settlement, ob,
            "contracted server: full settlement available to company-backed callers")


# ── the firewall ───────────────────────────────────────────────────────────

@dataclass
class TrustFirewall:
    """
    Stateless decision engine. One instance per gateway process; it holds no
    per-caller state, so it scales the same way the MCP servers behind it now do.

        fw = TrustFirewall()
        fw.classify("api.acme.example", ServerClass.ATTESTED)
        d = fw.decide(request_headers, body, server_host="api.acme.example")
        if not d.allowed: reject(d.reason)
    """
    posture: str = "enforce"                       # enforce | observe
    max_credential_ttl: int = 300
    _classes: dict[str, ServerClass] = field(default_factory=dict)
    _mandates: dict[str, list[str]] = field(default_factory=dict)   # tier → scopes

    # ---- corpus classification ----
    def classify(self, server_host: str, klass: ServerClass) -> None:
        self._classes[server_host.lower()] = klass

    def classify_many(self, mapping: Mapping[str, ServerClass]) -> None:
        for host, k in mapping.items():
            self.classify(host, k)

    def class_of(self, server_host: str) -> ServerClass:
        """Unknown by default — the corpus is guilty until probed."""
        return self._classes.get((server_host or "").lower(), ServerClass.UNKNOWN)

    # ---- mandate scopes per tier (usually sourced from trust.tiers) ----
    def set_tier_scopes(self, tier: str, scopes: list[str]) -> None:
        self._mandates[tier] = list(scopes)

    def load_lattice(self) -> None:
        """Populate tier → scopes from the trust lattice, if available."""
        try:
            from trust.tiers import lattice_table
            for row in lattice_table():
                self._mandates[row["cell"]] = list(row["scopes"])
        except Exception:
            pass

    @staticmethod
    def _covers(granted: str, requested: str) -> bool:
        if granted.endswith("*"):
            return requested.startswith(granted[:-1])
        return granted == requested

    def scope_granted(self, tier: str, scope: str) -> bool:
        granted = self._mandates.get(tier)
        if granted is None:
            return True                     # no policy loaded → defer to reachability
        return any(self._covers(g, scope) for g in granted)

    # ---- the decision ----
    def decide(self, headers: Mapping[str, str], body: bytes = b"",
               server_host: str = "", now: Optional[int] = None) -> Decision:
        """
        Header-first decision. The body is only hashed (for the call binding),
        never parsed, so this runs at edge speed. Deep argument inspection is a
        separate, optional stage — see `xcpsec.argfirewall`.
        """
        req = McpRequest.from_headers(headers, body)
        scope = req.scope
        checks: list[str] = []
        warnings: list[str] = list(req.legacy_signals())
        klass = self.class_of(server_host)
        checks.append(f"headers:{req.method or '∅'}/{req.name or '∅'}")
        checks.append(f"server_class:{klass.label}")

        if not req.method:
            return Decision(Effect.DENY, scope,
                            f"missing Mcp-Method header (mandatory in MCP {MCP_SPEC_TARGET})",
                            klass, "", warnings=warnings, checks=checks)

        # 1. credential — stateless, no session lookup
        try:
            cred = req.credential()
        except Exception as e:
            return Decision(Effect.DENY, scope, f"unreadable credential: {e}",
                            klass, "", warnings=warnings, checks=checks)

        if cred is None:
            checks.append("credential:absent")
            # Anonymous: only ever observe, only ever reads, never binding.
            if self.posture == "observe":
                ob = Obligations(sandbox_execution=True, quarantine_output=True,
                                 max_scope="read")
                return Decision(Effect.OBSERVE, scope,
                                "no credential; gateway in observe posture",
                                klass, "", ob, warnings=warnings, checks=checks)
            return Decision(Effect.DENY, scope,
                            "no XCP-Request-Credential — anonymous calls are refused",
                            klass, "", warnings=warnings, checks=checks)

        problems = verify_cred(cred, mcp_method=req.method, mcp_name=req.name,
                               body=body, now=now,
                               max_ttl=self.max_credential_ttl)
        checks.append(f"credential:{'valid' if not problems else 'invalid'}")
        if problems:
            if self.posture == "observe":
                warnings.extend(problems)
                ob = Obligations(sandbox_execution=True, quarantine_output=True,
                                 max_scope="read")
                return Decision(Effect.OBSERVE, scope,
                                f"credential invalid ({problems[0]}); observed",
                                klass, cred.tier, ob, warnings=warnings, checks=checks)
            return Decision(Effect.DENY, scope, problems[0], klass, cred.tier,
                            warnings=warnings, checks=checks)

        # 2. tier → reachability against this server's class
        agent_tier = _agent_tier_of(cred.tier)
        ro = is_read_only(req.method)
        effect, settlement, ob, note = reachability(agent_tier, klass, ro)
        checks.append(f"reachability:{effect.name.lower()}")

        # 3. mandate scope coverage
        if effect != Effect.DENY and not self.scope_granted(cred.tier, scope):
            return Decision(Effect.DENY, scope,
                            f"scope {scope} is not granted at tier {cred.tier}",
                            klass, cred.tier, ob, warnings=warnings, checks=checks)
        checks.append("scope:granted")

        # 4. read-only obligation actually constrains the scope family
        if ob.max_scope == "read" and not ro:
            return Decision(Effect.DENY, scope,
                            "call would mutate state but only reads are permitted here",
                            klass, cred.tier, ob, warnings=warnings, checks=checks)

        # 5. gateway posture can downgrade, never upgrade
        if self.posture == "observe" and effect == Effect.ALLOW:
            effect = Effect.OBSERVE
            note += " (downgraded: gateway in observe posture)"
            settlement = "none"

        return Decision(effect, scope, note, klass, cred.tier, ob, settlement,
                        cred.spend_cap_minor if settlement != "none" else 0,
                        warnings, checks)


def _agent_tier_of(cell: str) -> int:
    """Extract the agent leg from a lattice cell like 'A2xH1' → 2."""
    try:
        if cell and cell[0] == "A":
            return int(cell[1])
    except (ValueError, IndexError):
        pass
    return 0


def corpus_matrix() -> list[dict[str, Any]]:
    """
    The full reachability matrix, for docs and operator review: every caller
    tier against every server class, for reads and for writes.
    """
    rows = []
    for a in (0, 1, 2):
        for k in ServerClass:
            for ro in (True, False):
                effect, settlement, ob, note = reachability(a, k, ro)
                rows.append({
                    "agentTier": f"A{a}",
                    "serverClass": k.label,
                    "operation": "read" if ro else "write",
                    "effect": effect.name.lower(),
                    "settlement": settlement,
                    "sandbox": ob.sandbox_execution,
                    "quarantine": ob.quarantine_output,
                    "receipt": ob.require_receipt,
                    "note": note,
                })
    return rows


__all__ = ["TrustFirewall", "Decision", "Effect", "ServerClass", "Obligations",
           "reachability", "corpus_matrix", "is_read_only"]
