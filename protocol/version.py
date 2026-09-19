"""
protocol.version — one source of truth for what an implementation speaks.

THE PROBLEM
-----------
This codebase had eight independent version constants and no way for two parties
to discover what they had in common. It has already shipped breaking wire
changes — `slyTrustTier` became `xcpTrustTier`, `_sly` became `_xcp`, and node
identity stopped being the certificate footprint — with no compatibility path.
In a single repository that is untidy. In a federation it is fatal: two nodes on
different versions fail in ways neither can diagnose, and the usual outcome is
that everybody pins to whatever the reference implementation happened to be
doing on the day they integrated.

WHAT NEGOTIATION HAS TO DO
--------------------------
Three things, and a version number alone does only the first:

  1. **Agree a wire version.** The caller advertises what it accepts, the
     responder picks the highest it also supports, and says which it chose.
  2. **Advertise capabilities.** A version is too coarse. Two nodes can both
     speak 0.2 while one settles payments and the other does not, so features
     are negotiated separately from the version.
  3. **Retire things on a clock.** A breaking change with no removal date is
     either never removed or removed by surprise. Every deprecation here carries
     a replacement and a date, and readers accept the old form until then.

FAIL LOUD, NOT SILENT
---------------------
When there is no common version the request is refused with the list of versions
this implementation supports. Guessing — treating an unknown version as the
current one — is how a peer ends up silently misinterpreting a field that
changed meaning.

Status: XCP and ERC-8004x are draft proposals. Versions below 1.0 may break; the
point of this module is that they break *visibly*.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

# ── the single source of truth ─────────────────────────────────────────────

#: Wire versions this implementation can speak, oldest first.
#:   0.1  original draft: stateful MCP, pre-rename field names
#:   0.2  MCP 2026-07-28 stateless core, xcp* field names, stable node identity
SUPPORTED: tuple[str, ...] = ("0.1", "0.2")
CURRENT: str = "0.2"
MINIMUM: str = "0.1"

# Headers. Deliberately mirrors the shape of MCP 2026-07-28's routing headers so
# infrastructure can act on them without opening the body.
H_VERSION = "xcp-version"                  # the version a message is written in
H_ACCEPT = "xcp-accept-versions"           # comma-separated, what the caller accepts
H_FEATURES = "xcp-features"                # comma-separated capabilities


class Feature(str, Enum):
    """
    Capabilities negotiated independently of the version, because two
    implementations can share a version and still not do the same things.
    """
    SESSION = "session"              # session binding + verification
    MANDATE = "mandate"              # per-call scope gating
    STATELESS = "stateless"          # MCP 2026-07-28 per-request credentials
    RECEIPTS = "receipts"            # proof-of-delivery
    TRANSPORT = "transport"          # paid routing with epoch commitments
    FEDERATION = "federation"        # node records, peering, attestations
    SEALED_CREDENTIALS = "sealed"    # credentials the gateway cannot read
    ABUSE_CONTROLS = "limits"        # rate limiting and quotas
    WRAPPERS = "wrappers"            # OpenAPI-to-MCP generation
    CHAIN = "chain"                  # on-chain anchoring (optional everywhere)


#: What this build actually implements. Not aspirational — advertising a feature
#: you do not have is worse than advertising none, because a peer will rely on it.
IMPLEMENTED: frozenset[Feature] = frozenset({
    Feature.SESSION, Feature.MANDATE, Feature.STATELESS, Feature.RECEIPTS,
    Feature.TRANSPORT, Feature.FEDERATION, Feature.SEALED_CREDENTIALS,
    Feature.ABUSE_CONTROLS, Feature.WRAPPERS,
})


class VersionError(Exception):
    pass


def _key(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in v.strip().split("-")[0].split("."))
    except ValueError:
        raise VersionError(f"malformed version {v!r}")


def is_supported(v: str) -> bool:
    return v.strip() in SUPPORTED


def parse_accept(header: str) -> list[str]:
    """Parse an `XCP-Accept-Versions` header. Unknown entries are kept, not
    dropped, so the error message can show what the peer actually asked for."""
    return [p.strip() for p in (header or "").split(",") if p.strip()]


# ── negotiation ────────────────────────────────────────────────────────────

@dataclass
class Negotiated:
    version: str
    features: frozenset[Feature]
    downgraded: bool = False       # agreed below this build's CURRENT
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version,
                "features": sorted(f.value for f in self.features),
                "downgraded": self.downgraded, "note": self.note}


def negotiate(client_accepts: Iterable[str],
              server_supports: Iterable[str] = SUPPORTED,
              client_features: Optional[Iterable[str]] = None,
              server_features: Iterable[Feature] = IMPLEMENTED) -> Negotiated:
    """
    Pick the highest version both sides accept, and intersect capabilities.

    Raises rather than guessing: an unknown version silently treated as the
    current one is how a peer ends up misreading a field that changed meaning.
    """
    accepts = [v for v in client_accepts if v]
    if not accepts:
        # A caller that says nothing gets the oldest version this build speaks,
        # not the newest. Assuming a silent peer is current is optimistic in the
        # direction that breaks things.
        common = [MINIMUM] if MINIMUM in server_supports else list(server_supports)[:1]
    else:
        supported = set(server_supports)
        common = [v for v in accepts if v in supported]
    if not common:
        raise VersionError(
            f"no common protocol version: caller accepts {sorted(accepts)}, "
            f"this implementation supports {sorted(server_supports)}")
    chosen = max(common, key=_key)

    if client_features is None:
        feats = frozenset(server_features)
    else:
        want = set()
        for f in client_features:
            try:
                want.add(Feature(str(f).strip()))
            except ValueError:
                continue                    # unknown feature names are ignored
        feats = frozenset(want) & frozenset(server_features)

    downgraded = _key(chosen) < _key(CURRENT)
    return Negotiated(
        version=chosen, features=feats, downgraded=downgraded,
        note=(f"agreed {chosen}; this build prefers {CURRENT}" if downgraded else ""))


def response_headers(n: Negotiated) -> dict[str, str]:
    return {"XCP-Version": n.version,
            "XCP-Features": ",".join(sorted(f.value for f in n.features))}


def request_headers(accepts: Iterable[str] = SUPPORTED,
                    features: Iterable[Feature] = IMPLEMENTED) -> dict[str, str]:
    return {"XCP-Version": CURRENT,
            "XCP-Accept-Versions": ",".join(accepts),
            "XCP-Features": ",".join(sorted(f.value for f in features))}


# ── deprecation, on a clock ────────────────────────────────────────────────

@dataclass(frozen=True)
class Deprecation:
    """
    A retired name with a replacement and a date. A breaking change without a
    removal date is either never removed or removed by surprise.
    """
    old: str
    new: str
    since: str                 # version that introduced the replacement
    remove_after: str          # ISO date; readers accept `old` until then
    note: str = ""

    def expired(self, today: Optional[str] = None) -> bool:
        t = today or time.strftime("%Y-%m-%d")
        return t > self.remove_after


#: Everything this project has renamed or retired on the wire. Readers consult
#: this rather than hard-coding the old names in a dozen places.
DEPRECATIONS: tuple[Deprecation, ...] = (
    Deprecation("slyTrustTier", "xcpTrustTier", since="0.2",
                remove_after="2027-03-01",
                note="ARD catalog trust metadata; renamed when the project "
                     "brand was removed"),
    Deprecation("_sly", "_xcp", since="0.2", remove_after="2027-03-01",
                note="MCP Registry manifest block"),
    Deprecation("Mcp-Session-Id", "", since="0.2", remove_after="2027-07-28",
                note="removed by MCP 2026-07-28; identity is now a per-request "
                     "credential. Presence is a warning, not a failure"),
    Deprecation("node_id-as-cert-footprint", "bindings", since="0.2",
                remove_after="2027-01-01",
                note="node identity is a long-lived key with the certificate "
                     "bound underneath, so renewals do not orphan peers"),
)

_BY_OLD = {d.old: d for d in DEPRECATIONS}


def read_compat(doc: dict[str, Any], field_name: str,
                default: Any = None) -> tuple[Any, Optional[str]]:
    """
    Read a field, accepting its deprecated spelling until the removal date.

    Returns (value, warning). This is the concrete pattern for a rename: the
    reader keeps working across the transition and says so, instead of silently
    returning `default` and letting a peer look broken.
    """
    if field_name in doc:
        return doc[field_name], None
    for d in DEPRECATIONS:
        if d.new == field_name and d.old in doc:
            if d.expired():
                return default, (f"{d.old!r} was removed after {d.remove_after}; "
                                 f"use {d.new!r}")
            return doc[d.old], (f"{d.old!r} is deprecated since {d.since}, "
                                f"use {d.new!r} (accepted until {d.remove_after})")
    return default, None


def deprecation_warnings(doc: dict[str, Any]) -> list[str]:
    """Every deprecated key present in a document, with its replacement."""
    out = []
    for k in doc:
        d = _BY_OLD.get(k)
        if d:
            out.append(f"{d.old!r} is deprecated since {d.since}"
                       + (f", use {d.new!r}" if d.new else " and has no replacement")
                       + f" (removal after {d.remove_after})")
    return out


# ── advertisement ──────────────────────────────────────────────────────────

def advertisement() -> dict[str, Any]:
    """
    What this implementation publishes about itself — in `/health`, in a node
    record, and anywhere a peer needs to decide whether it can talk to us before
    it tries.
    """
    return {
        "protocolVersions": list(SUPPORTED),
        "protocolCurrent": CURRENT,
        "features": sorted(f.value for f in IMPLEMENTED),
        "deprecations": [
            {"old": d.old, "new": d.new, "since": d.since,
             "removeAfter": d.remove_after} for d in DEPRECATIONS],
    }


def compatible_with(peer: dict[str, Any]) -> tuple[bool, str]:
    """
    Can we federate with this peer at all? Checked before peering rather than on
    the first failed call, so an incompatibility is a clear refusal instead of a
    mysterious error later.
    """
    versions = peer.get("protocolVersions") or (
        [peer["protocolCurrent"]] if peer.get("protocolCurrent") else [])
    if not versions:
        return False, "peer advertises no protocol version"
    try:
        n = negotiate(versions)
    except VersionError as e:
        return False, str(e)
    return True, (n.note or f"agreed {n.version}")


__all__ = [
    "SUPPORTED", "CURRENT", "MINIMUM", "Feature", "IMPLEMENTED",
    "H_VERSION", "H_ACCEPT", "H_FEATURES",
    "negotiate", "Negotiated", "VersionError", "is_supported", "parse_accept",
    "request_headers", "response_headers",
    "Deprecation", "DEPRECATIONS", "read_compat", "deprecation_warnings",
    "advertisement", "compatible_with",
]
