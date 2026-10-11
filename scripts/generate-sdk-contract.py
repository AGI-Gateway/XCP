#!/usr/bin/env python3
"""
generate-sdk-contract.py — emit the one contract every XCP SDK is built against.

WHY GENERATE RATHER THAN WRITE
------------------------------
This project is about to have SDKs in five languages, each implementing the same
protocol surface. Hand-writing five interpretations of that surface produces
five implementations that are each individually plausible and collectively
inconsistent, and the inconsistency does not show up as a failing test. It shows
up as one node authenticating a session another refuses -- which has already
happened here once, between the Python and Node gateways, over a trailing space.

So the surface is described once, mechanically, from the Python implementation
that the conformance suite already certifies:

    protocol/version.py     versions, features, headers, deprecations
    protocol/identity.py    the XCP-Agent-Identity parser
    trust/tiers.py          the nine lattice cells and their envelopes
    trustfirewall/stateless.py   scope derivation, binding digests
    federation/delegation.py     tier narrowing and the widens() predicate
    ops/config.py           every setting, which are unsafe, which are secret
    conformance/suite.py    the levelled checks
    core/gateway/…          the endpoint table, read from the decorators

Two outputs:

  sdk/contract/descriptor.json
      What the protocol is. Machine-readable, so a code generator or a reviewer
      can diff it between releases instead of reading five SDKs.

  sdk/vectors/*.json
      What agreement means. Input/output pairs for the pure functions every SDK
      must reproduce exactly. These run offline -- no server, no network, no
      container -- so the cost of checking a fifth language is a test runner,
      not a CI environment.

The division matters. The existing differential harness
(security/analysis/differential.py) boots two live gateways and compares status
codes, which is strong evidence and does not scale: five languages would mean
five servers in CI. Vectors cover the parsing and policy arithmetic, which is
where implementations actually diverge; the live suites stay for the behaviour
only a running node has.

CHECKED IN, AND CHECKED
-----------------------
The outputs are committed. CI regenerates them and fails on any diff, exactly as
it already does for the contract ABIs:

    python scripts/generate-sdk-contract.py
    git diff --exit-code sdk/

That way the vectors cannot drift from the implementation they were generated
from, and an intentional protocol change has to appear in a reviewable diff.

    python scripts/generate-sdk-contract.py [--check]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OUT_CONTRACT = ROOT / "sdk" / "contract"
OUT_VECTORS = ROOT / "sdk" / "vectors"

# Whitespace classes that a host language's trim() might remove and RFC 9110's
# OWS does not. Every one of these is a vector, because every one of them is a
# way for two SDKs to disagree about the same bytes. See protocol/identity.py.
NON_OWS_WHITESPACE = [
    ("LF", "\u000a"), ("CR", "\u000d"), ("VT", "\u000b"), ("FF", "\u000c"),
    ("NEL", "\u0085"), ("NBSP", " "), ("OGHAM_SPACE", " "),
    ("EN_QUAD", " "), ("NARROW_NBSP", " "),
    ("IDEOGRAPHIC_SPACE", "　"), ("ZWSP", "​"),
]

FOOTPRINT = "0x" + "ab" * 32


def _write(path: Path, payload: Any) -> str:
    """Write deterministic JSON. Sorted keys and a trailing newline, so a
    regenerate-and-diff check reports real changes and not key ordering."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path.write_text(text)
    return text


# ──────────────────────────────────────────────────────────────────────────
# descriptor
# ──────────────────────────────────────────────────────────────────────────

def endpoint_table() -> list[dict[str, str]]:
    """
    Read the endpoint table off the gateway's decorators.

    Derived rather than hand-listed: a hand-kept list of endpoints is a list
    that is wrong one commit after someone adds an endpoint, and an SDK built
    from it silently lacks a method.
    """
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    out = []
    for m in re.finditer(r'^@app\.(get|post)\("([^"]+)"\)\s*\n'
                         r'(?:async\s+)?def\s+(\w+)', src, re.M):
        method, path, fn = m.group(1).upper(), m.group(2), m.group(3)
        out.append({"method": method, "path": path, "handler": fn,
                    "group": _group_for(path)})
    return sorted(out, key=lambda e: (e["group"], e["path"]))


def _group_for(path: str) -> str:
    if path.startswith("/v1/session"):
        return "session"
    if path.startswith("/v1/a2t"):
        return "a2t"
    if path.startswith("/v1/a2a"):
        return "a2a"
    if path.startswith("/v1/t2t"):
        return "t2t"
    if path.startswith("/v1/tool"):
        return "relay"
    if path.startswith("/v1/federation"):
        return "federation"
    if path.startswith("/admin"):
        return "admin"
    return "discovery"


def conformance_checks() -> list[dict[str, str]]:
    from conformance.suite import CHECKS
    return sorted(
        [{"id": cid, "title": title, "profile": prof.value, "level": lvl.value}
         for cid, title, prof, lvl, _fn in CHECKS],
        key=lambda c: c["id"])


def lattice() -> list[dict[str, Any]]:
    from trust.tiers import AgentTier, HumanTier, resolve
    out = []
    for a in AgentTier:
        for h in HumanTier:
            t = resolve(a, h)
            d = t.to_dict()
            d["agentTier"], d["humanTier"] = int(a), int(h)
            out.append(d)
    return sorted(out, key=lambda c: c["cell"])


def settings() -> list[dict[str, Any]]:
    from ops.config import SETTINGS
    return sorted((s.to_dict() for s in SETTINGS), key=lambda s: s["name"])


def descriptor() -> dict[str, Any]:
    from protocol import advertisement
    from protocol.identity import (HEADER, SEP, FIELDS, OWS,
                                   REASON_MALFORMED, REASON_NON_CANONICAL)
    from protocol.version import H_VERSION, H_ACCEPT, H_FEATURES
    from trust.tiers import MAX_TTL
    from federation.routing import CROSS_SITE_COST
    from federation.cluster import MIN_LEAVES

    adv = advertisement()
    return {
        "$comment": (
            "Generated by scripts/generate-sdk-contract.py. Do not edit. "
            "Every field is read from the Python implementation the "
            "conformance suite certifies; see that script's docstring."),
        "generator": "scripts/generate-sdk-contract.py",
        "protocol": {
            "versions": adv["protocolVersions"],
            "current": adv["protocolCurrent"],
            "features": adv["features"],
            "deprecations": adv["deprecations"],
        },
        "headers": {
            "identity": {
                "name": HEADER,
                "separator": SEP,
                "fields": FIELDS,
                "ows": list(OWS),
                "owsRule": (
                    "RFC 9110 5.5: OWS = *( SP / HTAB ). Strip exactly these "
                    "two characters from both ends. Do NOT use the host "
                    "language's trim(): see sdk/vectors/identity_header.json "
                    "for the eleven codepoints where they disagree."),
                "footprintRule": (
                    "Taken verbatim. Not lowercased, not 0X-normalised, not "
                    "length-checked. It is compared byte-for-byte against a "
                    "registered binding."),
                "integerRule": (
                    "Fields 1 and 2 must be canonical decimal digits. Reject "
                    "'+1', ' 1' and '1_0' even where the language's integer "
                    "parser accepts them."),
                "reasons": {
                    "malformed": REASON_MALFORMED,
                    "nonCanonical": REASON_NON_CANONICAL,
                },
            },
            "version": H_VERSION,
            "acceptVersions": H_ACCEPT,
            "features": H_FEATURES,
            "mandate": "xcp-mandate",
            "mcpMethod": "mcp-method",
            "mcpName": "mcp-name",
        },
        "endpoints": endpoint_table(),
        "lattice": {
            "cells": lattice(),
            "maxTtlSeconds": MAX_TTL,
            "ceilingRule": (
                "The ceiling is the weaker leg, resolved per leg with min(). "
                "A2xH0 is the one deliberate exception: a company-backed agent "
                "is not capped by an absent human, because the company is "
                "itself the principal."),
            "entitlementRule": "Entitlements may only restrict the envelope.",
        },
        "federation": {
            "crossSiteCost": CROSS_SITE_COST,
            "minMerkleLeaves": MIN_LEAVES,
            "localityRule": (
                "Locality is a cost: an off-site peer is priced at "
                "crossSiteCost and can still win. Residency is a constraint: a "
                "site outside permittedSites is inadmissible at any price."),
            "narrowingRule": (
                "Authority narrows at a boundary and never widens. The "
                "destination computes its own ceiling and takes the per-leg "
                "minimum; a ticket that would widen is refused, not clamped."),
        },
        "conformance": conformance_checks(),
        "configuration": {
            "settings": settings(),
            "precedence": [
                "explicit argument passed to the SDK constructor",
                "environment variable",
                "xcp.toml in the working directory",
                "the setting's documented default",
            ],
        },
    }


# ──────────────────────────────────────────────────────────────────────────
# vectors
# ──────────────────────────────────────────────────────────────────────────

def vectors_identity_header() -> dict[str, Any]:
    """
    The parser, including every codepoint where host-language trim() functions
    disagree with RFC 9110. An SDK that uses its standard library's trim will
    fail these, which is the entire point of shipping them.
    """
    from protocol.identity import try_parse

    raw: list[tuple[str, Any]] = [
        ("empty", ""),
        ("canonical", f"42001;8453;{FOOTPRINT}"),
        ("leading SP", f" 42001;8453;{FOOTPRINT}"),
        ("trailing SP", f"42001;8453;{FOOTPRINT} "),
        ("leading HTAB", f"\t42001;8453;{FOOTPRINT}"),
        ("trailing HTAB", f"42001;8453;{FOOTPRINT}\t"),
        ("both OWS", f" \t42001;8453;{FOOTPRINT}\t "),
        ("inner SP before chain", f"42001; 8453;{FOOTPRINT}"),
        ("inner SP after agent", f"42001 ;8453;{FOOTPRINT}"),
        ("two fields", "42001;8453"),
        ("four fields", f"42001;8453;{FOOTPRINT};x"),
        ("one field", "42001"),
        ("empty footprint", "42001;8453;"),
        ("negative agent", f"-1;8453;{FOOTPRINT}"),
        ("plus-prefixed agent", f"+42001;8453;{FOOTPRINT}"),
        ("underscored agent", f"42_001;8453;{FOOTPRINT}"),
        ("non-numeric agent", f"abc;8453;{FOOTPRINT}"),
        ("huge agent", f"{'9' * 40};8453;{FOOTPRINT}"),
        ("zero agent", f"0;0;{FOOTPRINT}"),
        ("footprint uppercased", f"42001;8453;{FOOTPRINT.upper()}"),
        ("footprint 0X prefix", f"42001;8453;0X{FOOTPRINT[2:]}"),
        ("short footprint", "42001;8453;0xab"),
        ("footprint without 0x", f"42001;8453;{FOOTPRINT[2:]}"),
    ]
    for name, ch in NON_OWS_WHITESPACE:
        raw.append((f"trailing {name} is NOT OWS", f"42001;8453;{FOOTPRINT}{ch}"))
        raw.append((f"leading {name} is NOT OWS", f"{ch}42001;8453;{FOOTPRINT}"))

    cases = []
    for name, header in raw:
        ident, reason = try_parse(header)
        cases.append({
            "name": name,
            "header": header,
            "ok": ident is not None,
            # Emitted as DECIMAL STRINGS, not JSON numbers.
            #
            # Found by the TypeScript port. A JSON number cannot carry an
            # integer beyond 2^53: the 40-digit agent id below came back from
            # JSON.parse as 1e+40, so the vector could not be reproduced by any
            # language whose JSON parser uses doubles -- which is most of them.
            # The port was correct (BigInt preserves the value) and the vector
            # file was the thing that was wrong.
            #
            # Agent ids are uint256 on chain, so this is not a hypothetical
            # range. A runner compares these as strings and parses them with
            # whatever big-integer type its language has.
            "agentId": str(ident.agent_id) if ident else None,
            "chainId": str(ident.chain_id) if ident else None,
            "footprint": ident.footprint if ident else None,
            "reason": reason or None,
        })
    return {
        "$comment": (
            "XCP-Agent-Identity parse vectors. `header` is the exact field "
            "value as received. Implementations must strip ONLY SP and HTAB; "
            "the 'is NOT OWS' cases fail for any SDK that calls its "
            "language's trim(). `agentId` and `chainId` are DECIMAL STRINGS "
            "rather than JSON numbers: these are uint256 values on chain, a "
            "JSON number cannot carry one past 2^53, and a 40-digit id came "
            "back from JavaScript's JSON.parse as 1e+40. Parse them with your "
            "language's big-integer type. Note that an empty footprint parses "
            "successfully -- whether it matches a binding is a question for "
            "the session registry, not the parser, and an SDK must not "
            "second-guess that here."),
        "function": "parseAgentIdentity",
        "cases": cases,
    }


def vectors_scope() -> dict[str, Any]:
    from trustfirewall.stateless import scope_for
    pairs = [
        ("tools/call", "search"), ("tools/call", ""), ("tools/list", ""),
        ("tools/list", "ignored"), ("resources/read", "file://x"),
        ("resources/list", ""), ("prompts/get", "greet"), ("prompts/get", ""),
        ("prompts/list", ""), ("completion/complete", ""),
        ("tasks/get", ""), ("tasks/list", ""), ("", ""), ("", "search"),
        ("unknown/method", ""), ("unknown", ""), ("tools", ""),
        ("tools/call", " search "), ("TOOLS/CALL", "search"),
        ("tools/call/extra", "x"), ("/", ""), ("a/b/c", ""),
    ]
    return {
        "$comment": (
            "Scope derivation from the mandatory MCP 2026-07-28 routing "
            "headers, with no reference to the body. The mapping is total: an "
            "unrecognised method still yields a scope string, so an unknown "
            "call is denied by default rather than allowed because no rule "
            "matched. "
            "Two results look like bugs and are not, so do not 'fix' either in "
            "a port. (1) The method is NOT lowercased: 'TOOLS/CALL' yields "
            "'mcp:TOOLS/CALL', which no 'mcp:tools/*' mandate matches, so an "
            "uppercase method is denied -- normalising it would turn a refusal "
            "into an allow. (2) This function STRIPS the name, so ' search ' "
            "yields 'mcp:tools/search', while bindDigest REFUSES the same "
            "value as non-canonical. The asymmetry is deliberate on the "
            "binding side and tracked as a defect on this side; see "
            "bind_digest.json. An SDK reproduces both as given rather than "
            "making them agree."),
        "function": "scopeFor",
        "cases": [{"mcpMethod": m, "mcpName": n, "scope": scope_for(m, n)}
                  for m, n in pairs],
    }


def vectors_bind_digest() -> dict[str, Any]:
    from trustfirewall.stateless import bind_digest, NonCanonicalHeader
    cases = []
    for method, name, body in [
        ("tools/call", "search", b""),
        ("tools/call", "search", b'{"q":"x"}'),
        ("tools/call", "search", b'{"q":"y"}'),
        ("tools/call", "other", b'{"q":"x"}'),
        ("tools/list", "", b""),
        ("tools/call", "search ", b""),
        ("tools/call", " search", b""),
        ("tools/call ", "search", b""),
        ("tools/call", "sea rch", b""),
    ]:
        try:
            cases.append({"mcpMethod": method, "mcpName": name,
                          "bodyUtf8": body.decode(), "ok": True,
                          "digest": bind_digest(method, name, body)})
        except NonCanonicalHeader as e:
            cases.append({"mcpMethod": method, "mcpName": name,
                          "bodyUtf8": body.decode(), "ok": False,
                          "digest": None, "reason": str(e)})
    return {
        "$comment": (
            "Binding digests. A non-canonical routing field is REFUSED, not "
            "normalised: stripping made 'search' and 'search ' produce the "
            "same digest, which is a parser differential in its most "
            "dangerous shape. Inner whitespace is a value, not OWS, so "
            "'sea rch' is a legitimate name and digests fine."),
        "function": "bindDigest",
        "cases": cases,
    }


def vectors_tier() -> dict[str, Any]:
    from federation.delegation import (canonical_tier, narrow_tier, widens,
                                       parse_tier, format_tier,
                                       DelegationError)
    canon, narrow, wide = [], [], []

    for cell in ["A2xH2", "a2xh2", "A2XH2", "A0xH0", "A1xH2", " A2xH2 ",
                 "A2×H2", "A3xH0", "AxH", "", "A2H2", "A2xH9"]:
        try:
            canon.append({"input": cell, "ok": True,
                          "canonical": canonical_tier(cell)})
        except Exception as e:
            canon.append({"input": cell, "ok": False, "canonical": None,
                          "reason": type(e).__name__})

    for asserted, ceiling in [
        ("A2xH2", "A2xH2"), ("A2xH2", "A1xH2"), ("A2xH2", "A0xH0"),
        ("A0xH0", "A2xH2"), ("A1xH1", "A2xH0"), ("A2xH0", "A1xH2"),
        ("A0xH2", "A2xH1"), ("A1xH2", "A1xH1"),
    ]:
        try:
            narrow.append({"asserted": asserted, "ceiling": ceiling,
                           "ok": True,
                           "effective": narrow_tier(asserted, ceiling)})
        except DelegationError as e:
            narrow.append({"asserted": asserted, "ceiling": ceiling,
                           "ok": False, "effective": None, "reason": str(e)})

    for asserted, effective in [
        ("A2xH2", "A2xH2"), ("A1xH1", "A2xH1"), ("A1xH1", "A1xH2"),
        ("A2xH2", "A1xH2"), ("A0xH0", "A0xH0"), ("A0xH0", "A2xH2"),
    ]:
        wide.append({"asserted": asserted, "effective": effective,
                     "widens": widens(asserted, effective)})

    return {
        "$comment": (
            "Tier arithmetic. Narrowing is per leg with min(); widens() is the "
            "guard that refuses a ticket granting more than the origin held, "
            "and it mirrors the predicate guarding the OAuth bridge. Note "
            "canonical_tier accepts case variants but the canonical form is "
            "'A2xH2' with a lowercase x -- an SDK that upper-cases the whole "
            "cell produces 'A2XH2' and will not match the lattice."),
        "functions": ["canonicalTier", "narrowTier", "widens"],
        "canonicalTier": canon,
        "narrowTier": narrow,
        "widens": wide,
        "roundTrip": [
            {"cell": format_tier(a, h), "agent": a, "human": h}
            for a in range(3) for h in range(3)
        ],
        "parseTier": [
            {"cell": c, "agent": parse_tier(c)[0], "human": parse_tier(c)[1]}
            for c in ["A0xH0", "A1xH1", "A2xH2", "A2xH0", "A0xH2"]
        ],
    }


def vectors_negotiate() -> dict[str, Any]:
    from protocol.version import negotiate, parse_accept, VersionError, SUPPORTED
    cases = []
    for name, accepts in [
        ("silent caller gets the minimum", ""),
        ("exact current", "0.2"),
        ("both, picks highest", "0.1,0.2"),
        ("reversed order, still highest", "0.2,0.1"),
        ("whitespace around entries", " 0.1 , 0.2 "),
        ("unknown only", "9.9"),
        ("unknown plus known", "9.9,0.1"),
        ("malformed entry ignored among known", "junk,0.2"),
        ("only malformed", "junk"),
    ]:
        parsed = parse_accept(accepts)
        try:
            n = negotiate(parsed)
            cases.append({"name": name, "acceptHeader": accepts,
                          "parsed": parsed, "ok": True,
                          "version": n.version, "downgraded": n.downgraded})
        except VersionError as e:
            cases.append({"name": name, "acceptHeader": accepts,
                          "parsed": parsed, "ok": False, "version": None,
                          "downgraded": None, "reason": str(e)})
    return {
        "$comment": (
            "Version negotiation. A caller that advertises nothing gets the "
            "OLDEST version this build speaks, not the newest: assuming a "
            "silent peer is current is optimistic in the direction that "
            "breaks things. No common version is a refusal carrying the "
            "supported list, never a guess."),
        "function": "negotiate",
        "supported": list(SUPPORTED),
        "cases": cases,
    }


def vectors_lattice() -> dict[str, Any]:
    from trust.tiers import AgentTier, HumanTier, resolve, Entitlements
    base = [{"cell": resolve(a, h).cell, "agentTier": int(a),
             "humanTier": int(h), "envelope": resolve(a, h).to_dict()}
            for a in AgentTier for h in HumanTier]

    # Entitlements may only restrict. These vectors exist so no SDK
    # "helpfully" applies an IdP's higher approval limit as an increase.
    narrowing = []
    for name, ent in [
        ("lower approval limit wins",
         Entitlements(approval_limit_minor=1_000)),
        ("higher approval limit is ignored",
         Entitlements(approval_limit_minor=10_000_000)),
        ("allowed_scopes intersects",
         Entitlements(allowed_scopes=["mcp:tools/list"])),
        ("denied_scopes subtracts",
         Entitlements(denied_scopes=["mcp:tools/*"])),
        ("empty entitlements change nothing", Entitlements()),
    ]:
        t = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE, ent)
        narrowing.append({"name": name, "cell": "A2xH2",
                          "entitlements": {
                              "groups": ent.groups,
                              "costCenter": ent.cost_center,
                              "approvalLimitMinor": ent.approval_limit_minor,
                              "allowedScopes": ent.allowed_scopes,
                              "deniedScopes": ent.denied_scopes},
                          "envelope": t.to_dict()})

    return {
        "$comment": (
            "The nine envelopes, and what entitlements do to them. "
            "spendCapMinor 0 means no PROTOCOL cap, not an unlimited one: at "
            "A2xH2 the entitlement supplies the real limit. An SDK must not "
            "render 0 as 'unlimited' in a consent prompt."),
        "function": "resolve",
        "cells": base,
        "entitlementNarrowing": narrowing,
    }


VECTOR_FILES = {
    "identity_header.json": vectors_identity_header,
    "scope.json": vectors_scope,
    "bind_digest.json": vectors_bind_digest,
    "tier.json": vectors_tier,
    "negotiate.json": vectors_negotiate,
    "lattice.json": vectors_lattice,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed output differs (for CI)")
    args = ap.parse_args()

    written: dict[Path, str] = {}
    before: dict[Path, str] = {}

    targets: list[tuple[Path, Any]] = [
        (OUT_CONTRACT / "descriptor.json", descriptor),
        *[(OUT_VECTORS / name, fn) for name, fn in sorted(VECTOR_FILES.items())],
    ]

    for path, build in targets:
        before[path] = path.read_text() if path.exists() else ""
        written[path] = _write(path, build())

    changed = [p for p in written if written[p] != before[p]]

    total_cases = 0
    for name in VECTOR_FILES:
        d = json.loads((OUT_VECTORS / name).read_text())
        n = sum(len(v) for k, v in d.items()
                if isinstance(v, list) and k != "supported")
        total_cases += n
        print(f"  {name:24} {n:4} cases")

    desc = json.loads((OUT_CONTRACT / "descriptor.json").read_text())
    print(f"  {'descriptor.json':24} "
          f"{len(desc['endpoints'])} endpoints, "
          f"{len(desc['lattice']['cells'])} cells, "
          f"{len(desc['conformance'])} checks, "
          f"{len(desc['configuration']['settings'])} settings")
    print(f"\n  {total_cases} vectors every SDK must reproduce")

    if args.check and changed:
        print("\nThe committed SDK contract is stale. Regenerate it:", file=sys.stderr)
        print("    python scripts/generate-sdk-contract.py", file=sys.stderr)
        for p in changed:
            print(f"  changed: {p.relative_to(ROOT)}", file=sys.stderr)
        return 1
    if changed and not args.check:
        for p in changed:
            print(f"  updated {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
