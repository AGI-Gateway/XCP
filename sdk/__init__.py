"""
sdk — the protocol contract, and the runner that holds every SDK to it.

WHAT IS IN HERE
---------------
`contract/descriptor.json` describes the protocol surface. `vectors/*.json` are
input/output pairs for the pure functions every XCP SDK must reproduce exactly:
the XCP-Agent-Identity parser, scope derivation, binding digests, tier
narrowing, version negotiation and the lattice envelopes. Both are generated
from the Python implementation by `scripts/generate-sdk-contract.py` and
committed, with CI failing on any drift.

WHY VECTORS AND NOT JUST TESTS
------------------------------
Each language's test suite proves that implementation self-consistent. It cannot
prove two implementations agree, and agreement is the whole value of a protocol.
This repository has already shipped a disagreement between its Python and Node
gateways -- the same header, 401 on one and 403 on the other, over a trailing
space -- and found it by differential analysis rather than by either test suite.

Vectors are the cheap half of that analysis. They need no server, no network and
no container, so adding a fifth language costs a test runner rather than a CI
environment. The live differential harness in `security/analysis/` stays for the
behaviour only a running node has.

An SDK in any language is "conformant to the contract" when it reproduces every
vector. That is a weaker claim than passing the conformance suite, and a
different one: the suite checks what a node does, the vectors check that two
implementations read the same bytes the same way.

USING IT FROM PYTHON
--------------------
    from sdk import load_vectors, check_python

    report = check_python()
    print(report.summary())
    raise SystemExit(0 if report.ok else 1)

USING IT FROM ANY OTHER LANGUAGE
--------------------------------
Read the JSON. Every case is plain JSON scalars with no language-specific
encoding, and every expected value is stated literally rather than as a rule to
re-derive. A port that needs to interpret a vector has already lost the
property the vectors exist to provide.

    python -m sdk            # run the Python port against the vectors
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

HERE = Path(__file__).resolve().parent
CONTRACT_DIR = HERE / "contract"
VECTORS_DIR = HERE / "vectors"

__all__ = ["load_contract", "load_vectors", "vector_names", "Report",
           "check_python"]


def load_contract() -> dict[str, Any]:
    """The protocol descriptor: versions, headers, endpoints, lattice, config."""
    return json.loads((CONTRACT_DIR / "descriptor.json").read_text())


def vector_names() -> list[str]:
    return sorted(p.name for p in VECTORS_DIR.glob("*.json"))


def load_vectors(name: str) -> dict[str, Any]:
    """
    Load one vector file by name, with or without the .json suffix.

        load_vectors("identity_header")
    """
    fn = name if name.endswith(".json") else f"{name}.json"
    path = VECTORS_DIR / fn
    if not path.exists():
        raise FileNotFoundError(
            f"no vector file {fn!r}; available: {', '.join(vector_names())}")
    return json.loads(path.read_text())


# ──────────────────────────────────────────────────────────────────────────
# the runner
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class Failure:
    vector: str
    case: str
    field: str
    expected: Any
    actual: Any

    def __str__(self) -> str:
        return (f"{self.vector} / {self.case} / {self.field}: "
                f"expected {self.expected!r}, got {self.actual!r}")


@dataclass
class Report:
    passed: int = 0
    failures: list[Failure] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def summary(self) -> str:
        lines = [f"{self.passed} vectors reproduced, "
                 f"{len(self.failures)} disagreed"]
        if self.skipped:
            lines.append(f"{len(self.skipped)} skipped: "
                         f"{', '.join(self.skipped)}")
        for f in self.failures:
            lines.append(f"  FAIL {f}")
        return "\n".join(lines)


def _cmp(rep: Report, vector: str, case: str, fld: str,
         expected: Any, actual: Any) -> None:
    if expected == actual:
        rep.passed += 1
    else:
        rep.failures.append(Failure(vector, case, fld, expected, actual))


def check_python(rep: Optional[Report] = None) -> Report:
    """
    Run the Python implementation against every vector.

    This is not circular even though the vectors were generated from this
    implementation: it catches the case where the committed vectors are stale
    relative to the code, which is the same failure the CI
    regenerate-and-diff check covers from the other direction. Its real
    purpose is to be the reference a port is read against -- an SDK author
    writing the Go runner copies this file's structure.
    """
    rep = rep or Report()
    rep = _check_identity(rep)
    rep = _check_scope(rep)
    rep = _check_bind_digest(rep)
    rep = _check_tier(rep)
    rep = _check_negotiate(rep)
    rep = _check_lattice(rep)
    return rep


def _check_identity(rep: Report) -> Report:
    from protocol.identity import try_parse
    v = load_vectors("identity_header")
    for c in v["cases"]:
        ident, reason = try_parse(c["header"])
        _cmp(rep, "identity_header", c["name"], "ok", c["ok"], ident is not None)
        if c["ok"]:
            if ident is None:
                continue
            # Compared as decimal strings, because that is how the vectors
            # carry them: a JSON number cannot represent a uint256 agent id.
            # See the vector file's $comment.
            _cmp(rep, "identity_header", c["name"], "agentId",
                 c["agentId"], str(ident.agent_id))
            _cmp(rep, "identity_header", c["name"], "chainId",
                 c["chainId"], str(ident.chain_id))
            _cmp(rep, "identity_header", c["name"], "footprint",
                 c["footprint"], ident.footprint)
        else:
            _cmp(rep, "identity_header", c["name"], "reason",
                 c["reason"], reason or None)
    return rep


def _check_scope(rep: Report) -> Report:
    from trustfirewall.stateless import scope_for
    v = load_vectors("scope")
    for c in v["cases"]:
        _cmp(rep, "scope", f"{c['mcpMethod']!r}+{c['mcpName']!r}", "scope",
             c["scope"], scope_for(c["mcpMethod"], c["mcpName"]))
    return rep


def _check_bind_digest(rep: Report) -> Report:
    from trustfirewall.stateless import bind_digest, NonCanonicalHeader
    from protocol.hashing import AVAILABLE, HashUnavailable
    v = load_vectors("bind_digest")
    if not AVAILABLE:
        # Reported as a skip, never as a pass. The digest vectors are the ones
        # that cannot be checked without the real hash, and claiming agreement
        # we did not verify is the failure mode this whole harness exists to
        # prevent. A base install legitimately lacks keccak256; it simply
        # cannot answer this question.
        rep.skipped.append(
            f"bind_digest ({len(v['cases'])} cases): keccak256 unavailable, "
            f"install 'xcp[client]'")
        return rep
    for c in v["cases"]:
        name = f"{c['mcpMethod']!r}+{c['mcpName']!r}"
        try:
            got, ok = bind_digest(c["mcpMethod"], c["mcpName"],
                                  c["bodyUtf8"].encode()), True
        except NonCanonicalHeader:
            got, ok = None, False
        _cmp(rep, "bind_digest", name, "ok", c["ok"], ok)
        _cmp(rep, "bind_digest", name, "digest", c["digest"], got)
    return rep


def _check_tier(rep: Report) -> Report:
    from federation.delegation import canonical_tier, narrow_tier, widens
    v = load_vectors("tier")
    for c in v["canonicalTier"]:
        try:
            got, ok = canonical_tier(c["input"]), True
        except Exception:
            got, ok = None, False
        _cmp(rep, "tier", f"canonical {c['input']!r}", "ok", c["ok"], ok)
        _cmp(rep, "tier", f"canonical {c['input']!r}", "canonical",
             c["canonical"], got)
    for c in v["narrowTier"]:
        name = f"narrow {c['asserted']}->{c['ceiling']}"
        try:
            got, ok = narrow_tier(c["asserted"], c["ceiling"]), True
        except Exception:
            got, ok = None, False
        _cmp(rep, "tier", name, "ok", c["ok"], ok)
        _cmp(rep, "tier", name, "effective", c["effective"], got)
    for c in v["widens"]:
        _cmp(rep, "tier", f"widens {c['asserted']}/{c['effective']}", "widens",
             c["widens"], widens(c["asserted"], c["effective"]))
    return rep


def _check_negotiate(rep: Report) -> Report:
    from protocol.version import negotiate, parse_accept, VersionError
    v = load_vectors("negotiate")
    for c in v["cases"]:
        try:
            n = negotiate(parse_accept(c["acceptHeader"]))
            got_ok, version, down = True, n.version, n.downgraded
        except VersionError:
            got_ok, version, down = False, None, None
        _cmp(rep, "negotiate", c["name"], "ok", c["ok"], got_ok)
        _cmp(rep, "negotiate", c["name"], "version", c["version"], version)
        _cmp(rep, "negotiate", c["name"], "downgraded", c["downgraded"], down)
    return rep


def _check_lattice(rep: Report) -> Report:
    from trust.tiers import AgentTier, HumanTier, resolve
    v = load_vectors("lattice")
    for c in v["cells"]:
        t = resolve(AgentTier(c["agentTier"]), HumanTier(c["humanTier"]))
        _cmp(rep, "lattice", c["cell"], "envelope", c["envelope"], t.to_dict())
    return rep


if __name__ == "__main__":
    r = check_python()
    print(r.summary())
    raise SystemExit(0 if r.ok else 1)
