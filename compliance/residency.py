"""
compliance.residency — refuse the transfer, don't just document it.

Federation moves data across borders by design: peering with a node is a
decision to let another jurisdiction process your traffic. GDPR Ch. V restricts
that, DORA Art. 30(2)(a) requires an operator to know where their data is
processed, and PIPL Art. 38 requires an assessment before data leaves China.

A data map that *records* transfers after they happen satisfies none of these.
This makes residency a precondition of peering, so an impermissible transfer is
refused rather than discovered in an audit.

    policy = ResidencyPolicy(allowed={"EEA", "UK"})
    ok, why = policy.may_peer("node.example.de")   # -> True
    ok, why = policy.may_peer("node.example.cn")   # -> False, with the reason

Jurisdiction is inferred from the domain, which is a heuristic and nothing more:
a .de domain can be hosted anywhere. For anything that matters, set the
jurisdiction explicitly from the peer's node record or your contract with them.

Status: draft. Adequacy decisions change; this list is a starting point and must
be checked against the current position.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

#: EEA members plus jurisdictions with a European Commission adequacy decision.
#: Adequacy is reviewed and can be withdrawn — verify before relying on it.
EEA = {
    "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "de", "gr",
    "hu", "ie", "it", "lv", "lt", "lu", "mt", "nl", "pl", "pt", "ro", "sk",
    "si", "es", "se", "is", "li", "no", "eu",
}
ADEQUATE = {
    "uk": "UK adequacy decision (reviewed periodically)",
    "ch": "Switzerland adequacy decision",
    "jp": "Japan adequacy decision",
    "kr": "South Korea adequacy decision",
    "nz": "New Zealand adequacy decision",
    "ca": "Canada — commercial organisations only (PIPEDA)",
    "il": "Israel adequacy decision",
    "uy": "Uruguay adequacy decision",
    "ar": "Argentina adequacy decision",
}
#: Jurisdictions with their own outbound restrictions worth flagging.
RESTRICTED_OUTBOUND = {
    "cn": "PIPL Art. 38-40: security assessment or certification required "
          "before personal data leaves China",
    "ru": "Data localisation requirements apply",
    "in": "DPDP Act: government may restrict transfers to notified countries",
}

REGIONS = {
    "EEA": EEA,
    "ADEQUATE": set(ADEQUATE),
    "UK": {"uk"},
    "US": {"us"},
}


class ResidencyError(Exception):
    pass


def tld_of(domain: str) -> str:
    parts = (domain or "").strip().lower().rstrip(".").split(".")
    return parts[-1] if parts else ""


def jurisdiction_of(domain: str) -> str:
    """
    Best-effort jurisdiction from the domain. A heuristic: .de can be hosted in
    Ohio. Override explicitly wherever the answer matters.
    """
    tld = tld_of(domain)
    if tld in EEA:
        return tld.upper()
    if tld in ADEQUATE:
        return tld.upper()
    if tld in RESTRICTED_OUTBOUND:
        return tld.upper()
    if tld in ("com", "org", "net", "io", "dev", "ai", "app"):
        return "UNKNOWN"
    return tld.upper() if tld else "UNKNOWN"


@dataclass
class ResidencyPolicy:
    """
    Where this operator permits data to be processed.

    `allow_unknown` defaults to False: a generic TLD tells you nothing about
    where a peer actually runs, and defaulting to permit would make the control
    decorative.
    """
    allowed: set = field(default_factory=lambda: {"EEA", "ADEQUATE"})
    explicit: dict = field(default_factory=dict)   # domain -> jurisdiction
    allow_unknown: bool = False
    reason_required: bool = True

    def _permitted_tlds(self) -> set:
        out: set = set()
        for r in self.allowed:
            out |= REGIONS.get(r, {r.lower()})
        return out

    def may_peer(self, domain: str,
                 declared_jurisdiction: str = "") -> tuple[bool, str]:
        j = (declared_jurisdiction or self.explicit.get(domain.lower(), "")
             or jurisdiction_of(domain))
        tld = j.lower()

        if j == "UNKNOWN":
            if self.allow_unknown:
                return True, ("jurisdiction unknown and unknown transfers are "
                              "permitted by policy — record the basis")
            return False, (
                f"cannot determine where {domain} processes data. A generic TLD "
                "is not evidence of location. Set the jurisdiction explicitly "
                "from the peer's node record or your contract, or set "
                "allow_unknown with a documented basis.")

        if tld in RESTRICTED_OUTBOUND and tld not in self._permitted_tlds():
            return False, f"{j}: {RESTRICTED_OUTBOUND[tld]}"

        if tld in self._permitted_tlds():
            note = ADEQUATE.get(tld, "")
            return True, (f"{j} permitted" + (f" — {note}" if note else ""))

        return False, (
            f"{j} is outside the permitted regions {sorted(self.allowed)}. "
            "Transferring personal data there needs an Art. 46 safeguard "
            "(SCCs plus a transfer impact assessment) and a DORA Art. 30(2)(a) "
            "record of the processing location.")

    def assess(self, domains: list) -> dict[str, Any]:
        rows = []
        for d in domains:
            ok, why = self.may_peer(d)
            rows.append({"domain": d, "jurisdiction": jurisdiction_of(d),
                         "permitted": ok, "reason": why})
        return {"policy": sorted(self.allowed),
                "allowUnknown": self.allow_unknown,
                "peers": rows,
                "blocked": [r["domain"] for r in rows if not r["permitted"]],
                "note": ("Jurisdiction inferred from the domain unless declared. "
                         "Adequacy decisions change; verify before relying on "
                         "this.")}


def guard_peering(policy: ResidencyPolicy, domain: str,
                  declared_jurisdiction: str = "") -> None:
    """Raise rather than return, for use directly in a peering path."""
    ok, why = policy.may_peer(domain, declared_jurisdiction)
    if not ok:
        raise ResidencyError(f"residency policy refuses {domain}: {why}")


__all__ = ["ResidencyPolicy", "ResidencyError", "guard_peering",
           "jurisdiction_of", "tld_of", "EEA", "ADEQUATE",
           "RESTRICTED_OUTBOUND", "REGIONS"]
