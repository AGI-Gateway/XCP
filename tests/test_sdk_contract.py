"""
test_sdk_contract.py — the contract five SDKs are built against must hold.

Three separate properties, because they fail for different reasons:

  1. This implementation reproduces the committed vectors. Catches a code
     change that moved a behaviour without regenerating the contract.

  2. The generator is idempotent. Catches the reverse: a committed contract
     edited by hand, or stale relative to the sources it claims to describe.

  3. No module computes a digest that depends on its environment. This is a
     regression guard for a defect that was present in eleven modules and
     invisible to every test in this suite, because a suite run without
     eth_utils exercises the fallback consistently and passes.

Property 3 deserves its own note. The old code was:

    if _ETH: return keccak(data)
    else:    return sha3_256(data)

Those are different functions. A node installed as `xcp[client]` and a node
installed as `xcp` computed different binding digests for identical bytes, so
each rejected every credential the other minted, and neither log mentioned a
hash. Self-consistency is not agreement; this file tests for agreement.

    python tests/test_sdk_contract.py
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

GENERATOR = ROOT / "scripts" / "generate-sdk-contract.py"
CONTRACT = ROOT / "sdk" / "contract" / "descriptor.json"
VECTORS = ROOT / "sdk" / "vectors"

#: Packages whose digests are compared across implementations. A silent
#: algorithm switch in any of these is a federation-splitting defect.
INTEROP_PACKAGES = ("trustfirewall", "federation", "receipts", "privacy",
                    "protocol", "trust", "core")


def test_this_implementation_reproduces_every_vector():
    from sdk import check_python
    rep = check_python()
    assert rep.ok, "\n" + rep.summary()
    assert rep.passed > 100, f"only {rep.passed} comparisons ran; vectors missing?"


def test_the_committed_contract_is_not_stale():
    """Regenerate and diff, the same guard CI applies to the contract ABIs."""
    r = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                       capture_output=True, text=True, cwd=str(ROOT))
    assert r.returncode == 0, (
        "the committed SDK contract differs from what the sources produce.\n"
        "Run: python scripts/generate-sdk-contract.py\n" + r.stderr)


def test_no_module_substitutes_a_different_hash_function():
    """
    keccak256 has no stand-in. A module that falls back to SHA3-256 makes its
    digests depend on which optional packages the environment happens to have,
    which splits a federation silently.
    """
    offenders = []
    for pkg in INTEROP_PACKAGES:
        for py in (ROOT / pkg).rglob("*.py"):
            if "__pycache__" in py.parts:
                continue
            # Parse rather than grep. protocol/hashing.py quotes the old
            # defective code verbatim in its docstring to explain what it
            # refuses to do, and a textual match cannot tell prose from code
            # -- which would make documenting a defect indistinguishable from
            # committing one. A docstring is a string literal and never a Call
            # node, so the AST answers the question exactly.
            try:
                tree = ast.parse(py.read_text())
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr.startswith("sha3_")):
                    offenders.append(
                        f"{py.relative_to(ROOT)}:{node.lineno}")
    assert not offenders, (
        "these modules can substitute SHA3-256 for keccak256, so their "
        f"digests vary by environment: {offenders}. Use "
        "protocol.hashing.digest, which refuses instead.")


def test_the_canonical_digest_refuses_rather_than_substituting():
    from protocol.hashing import digest, keccak256, HashUnavailable, AVAILABLE
    if AVAILABLE:
        # keccak256("") is a fixed, well-known value. If this ever equals the
        # SHA3-256 of the same input, the substitution is back.
        import hashlib
        assert digest(b"") != "0x" + hashlib.sha3_256(b"").hexdigest(), \
            "digest() is returning SHA3-256, not keccak256"
        assert digest(b"").startswith("0x") and len(digest(b"")) == 66
    else:
        for fn in (lambda: digest(b"x"), lambda: keccak256(b"x")):
            try:
                fn()
                raise AssertionError("produced a digest with no keccak256 available")
            except HashUnavailable:
                pass


def test_every_delegating_module_uses_the_one_helper():
    """A module that defines its own digest must delegate, not reimplement."""
    missing = []
    for pkg in ("trustfirewall", "federation", "receipts", "privacy"):
        for py in (ROOT / pkg).rglob("*.py"):
            if "__pycache__" in py.parts:
                continue
            src = py.read_text()
            if re.search(r"^def digest\(", src, re.M) and \
                    "_canonical_digest" not in src:
                missing.append(str(py.relative_to(ROOT)))
    assert not missing, f"these define digest() without delegating: {missing}"


def test_the_descriptor_describes_the_live_sources():
    """
    The descriptor is generated, but a generator can still read the wrong
    thing. Cross-check its counts against the modules directly.
    """
    d = json.loads(CONTRACT.read_text())

    from ops.config import SETTINGS
    assert len(d["configuration"]["settings"]) == len(SETTINGS)

    from conformance.suite import CHECKS
    assert len(d["conformance"]) == len(CHECKS)

    from trust.tiers import AgentTier, HumanTier
    assert len(d["lattice"]["cells"]) == len(AgentTier) * len(HumanTier)

    gw = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    assert len(d["endpoints"]) == len(re.findall(r'^@app\.(?:get|post)\(', gw, re.M))

    from protocol.version import SUPPORTED, CURRENT
    assert d["protocol"]["versions"] == list(SUPPORTED)
    assert d["protocol"]["current"] == CURRENT


def test_the_identity_contract_pins_ows_rather_than_delegating_to_trim():
    """
    The single most portable-looking rule in the contract is the one most
    likely to be ported wrongly: every language's trim() strips a different
    set. The descriptor must state the two-character set explicitly, and the
    vectors must cover codepoints a host trim() would remove.
    """
    d = json.loads(CONTRACT.read_text())
    ows = d["headers"]["identity"]["ows"]
    assert ows == [" ", "\t"], f"OWS must be exactly SP and HTAB, got {ows!r}"

    v = json.loads((VECTORS / "identity_header.json").read_text())
    non_ows = [c for c in v["cases"] if "is NOT OWS" in c["name"]]
    assert len(non_ows) >= 20, (
        f"only {len(non_ows)} non-OWS whitespace vectors; a port using its "
        f"language's trim() could pass the suite")
    # Every one of them must fail to yield the bare footprint.
    bare = "0x" + "ab" * 32
    for c in non_ows:
        assert c["footprint"] != bare, (
            f"case {c['name']!r} expects the footprint stripped to {bare!r}, "
            f"which means OWS-only stripping is not being tested")


def test_vectors_are_language_neutral():
    """
    Every expected value must be a JSON scalar stated literally. A vector a
    port has to interpret has already lost the property vectors provide.
    """
    for f in sorted(VECTORS.glob("*.json")):
        d = json.loads(f.read_text())
        assert "$comment" in d, f"{f.name} has no explanation for a porter"
        # Case groups are lists of objects. Lists of scalars are metadata
        # ("function", "supported"), not cases.
        groups = [v for v in d.values()
                  if isinstance(v, list) and v and isinstance(v[0], dict)]
        assert groups, f"{f.name} contains no case groups"
        for group in groups:
            for case in group:
                assert isinstance(case, dict), f"{f.name}: case is not an object"
                for k, val in case.items():
                    assert val is None or isinstance(
                        val, (str, int, float, bool, list, dict)), \
                        f"{f.name}: {k} is not JSON-representable"


def test_the_wheel_ships_the_contract():
    """
    An SDK author in another language needs the vectors without cloning. They
    are declared as package data; this checks the declaration still matches
    where the files actually live.
    """
    import tomllib
    pp = tomllib.loads((ROOT / "pyproject.toml").read_text())
    data = pp["tool"]["setuptools"]["package-data"]["sdk"]
    assert "vectors/*.json" in data and "contract/*.json" in data
    assert (VECTORS / "identity_header.json").exists()
    assert CONTRACT.exists()


def test_the_base_distribution_declares_no_dependencies():
    """
    The zero-dependency claim is the reason an evaluator can try this at all.
    If it ever acquires a dependency, that must be a deliberate, reviewed
    change rather than a drive-by import.
    """
    import tomllib
    pp = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert pp["project"]["dependencies"] == [], (
        "the base distribution has acquired dependencies: "
        f"{pp['project']['dependencies']}")
    extras = pp["project"]["optional-dependencies"]
    for required in ("client", "gateway", "admin"):
        assert required in extras, f"no {required!r} extra"
    # The surfaces that need a digest must pull the package that provides it.
    for surface in ("client", "gateway"):
        assert any("eth-utils" in d for d in extras[surface]), (
            f"the {surface} extra needs eth-utils: without it every digest "
            f"raises HashUnavailable")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
