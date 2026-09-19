"""
test_oauth_bridge.py — a mandate may narrow a grant and must never widen it.

XCP's adoption cost turns on not requiring a second authority. Deriving the
mandate from an existing OAuth grant removes that cost, and introduces exactly
one way to get it catastrophically wrong: if derivation can enlarge a grant, it
is a privilege escalation path wearing a compatibility label.

    python tests/test_oauth_bridge.py
"""
from __future__ import annotations
import sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from trustfirewall.oauth_bridge import (Grant, derive_mandate, map_scopes,
                                        widens, GrantError)

NOW = int(time.time())


def _grant(**kw):
    base = dict(sub="user@corp.example", scope="read", exp=NOW + 600,
                client_id="agent-42")
    base.update(kw)
    return Grant(**base)


# ── the invariant ──────────────────────────────────────────────────────────

def test_a_mandate_cannot_request_more_than_the_grant():
    try:
        derive_mandate(_grant(), requested_scope=["admin:registry/delete"])
        assert False, "derivation widened a grant"
    except GrantError:
        pass


def test_requesting_less_is_honoured():
    m = derive_mandate(_grant(scope="read tools"),
                       requested_scope=["mcp:tools/search"])
    assert m["mandateScope"] == ["mcp:tools/search"]


def test_an_unmapped_scope_conveys_nothing():
    """An unrecognised scope is an unknown authority. Defaulting unknown
    authority to permitted is the failure this layer exists to prevent."""
    assert map_scopes(_grant(scope="some:vendor:scope")) == []


def test_a_grant_with_no_usable_scope_is_refused():
    try:
        derive_mandate(_grant(scope="unrecognised"))
        assert False, "issued a mandate that permits nothing"
    except GrantError as e:
        assert "no XCP-recognised scope" in str(e)


def test_a_mandate_cannot_outlive_its_grant():
    m = derive_mandate(_grant(exp=NOW + 60), max_ttl=86400)
    assert m["notAfter"] <= NOW + 60


def test_an_expired_grant_yields_nothing():
    try:
        derive_mandate(_grant(exp=NOW - 1)); assert False
    except GrantError:
        pass


def test_a_grant_without_a_subject_is_refused():
    try:
        derive_mandate(_grant(sub="")); assert False
    except GrantError as e:
        assert "principal" in str(e)


# ── checking a mandate somebody else derived ───────────────────────────────

def test_widening_is_detectable_after_the_fact():
    """A verifier must be able to check a mandate an intermediary claims to
    have derived correctly."""
    g = _grant()
    m = derive_mandate(g)
    assert widens(g, m) == []
    forged = dict(m, mandateScope=m["mandateScope"] + ["admin:registry/delete"])
    assert widens(g, forged), "an added scope must be detectable"
    swapped = dict(m, principal="someone-else@corp.example")
    assert widens(g, swapped), "a swapped principal must be detectable"
    longer = dict(m, notAfter=g.exp + 9999)
    assert widens(g, longer), "an extended expiry must be detectable"


# ── RFC 8693 actor chains ──────────────────────────────────────────────────

def test_the_actor_chain_is_flattened_outermost_first():
    g = _grant(act={"sub": "orchestrator", "act": {"sub": "subagent"}})
    assert derive_mandate(g)["delegationPath"] == ["orchestrator", "subagent"]


def test_a_cyclic_actor_claim_terminates():
    """A malformed or hostile token must not hang the verifier."""
    node: dict = {"sub": "a"}
    node["act"] = node                      # self-referential
    chain = _grant(act=node).actor_chain()
    assert len(chain) <= 16


def test_no_actor_claim_yields_an_empty_path():
    assert derive_mandate(_grant())["delegationPath"] == []


# ── the module stays in its lane ───────────────────────────────────────────

def test_this_module_does_not_validate_tokens():
    """Token validation belongs to the caller. Performing it here would move
    it into a component with no business doing it."""
    import ast
    src = (ROOT / "trustfirewall" / "oauth_bridge.py").read_text()
    # Strip docstrings and comments: the module DESCRIBES token validation as
    # the caller's job, and matching that prose was a false positive the first
    # time this test ran.
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            d = ast.get_docstring(node)
            if d:
                src = src.replace(d, "")
    code = "\n".join(l.split("#", 1)[0] for l in src.splitlines())
    for forbidden in ("jwt.decode", "verify_signature", "introspect(",
                      "requests.post", "httpx."):
        assert forbidden not in code, f"bridge is validating tokens: {forbidden}"
    assert "ALREADY-VALIDATED" in (ROOT / "trustfirewall" /
                                   "oauth_bridge.py").read_text()


def test_the_scope_map_is_explicit_not_pattern_derived():
    """A mapping an operator cannot read is one they cannot audit."""
    from trustfirewall.oauth_bridge import DEFAULT_SCOPE_MAP
    assert isinstance(DEFAULT_SCOPE_MAP, dict) and DEFAULT_SCOPE_MAP


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    p = f_ = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); p += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:120]}"); f_ += 1
    print(f"\n{p} passed, {f_} failed")
    sys.exit(1 if f_ else 0)
