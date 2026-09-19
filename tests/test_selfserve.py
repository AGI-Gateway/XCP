"""
test_selfserve.py — tests for the self-serve layer (trust lattice + ARD publishing).

    python tests/test_selfserve.py     # or: pytest tests/test_selfserve.py -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from trust.tiers import (AgentTier, HumanTier, Entitlements, resolve, next_upgrade,
                         lattice_table, session_binding, Rail, MAX_TTL, TierError)
from discovery.ard import (Publisher, Resource, build_catalog, validate_catalog,
                           build_mcp_manifest, representative_queries, mint_urn,
                           resource_from_tools_list, CatalogError)


# ── trust lattice ──────────────────────────────────────────────────────────

def test_lattice_is_complete():
    rows = lattice_table()
    assert len(rows) == 9, "3 agent tiers x 3 human tiers"
    cells = {r["cell"] for r in rows}
    assert cells == {f"A{a}xH{h}" for a in range(3) for h in range(3)}


def test_authority_increases_up_the_lattice():
    low = resolve(AgentTier.FREE, HumanTier.PUBLIC)
    high = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE)
    assert len(high.scopes) > len(low.scopes)
    assert high.ttl_seconds > low.ttl_seconds
    assert high.rails > low.rails
    assert low.rails == 0 and low.settlement == "none"


def test_weaker_leg_caps_authority():
    # a corporate human cannot lift an unbacked agent
    shadowed = resolve(AgentTier.FREE, HumanTier.ENTERPRISE)
    assert shadowed.settlement == "none"
    assert shadowed.rails == 0
    assert shadowed.posture == "observe", "unbacked agent is audit-only"


def test_company_autonomous_exception():
    # A2xH0 is deliberately NOT capped by the absent human
    svc = resolve(AgentTier.COMPANY, HumanTier.PUBLIC)
    assert svc.settlement == "metered", "the company is the principal"
    assert svc.rails != 0
    assert svc.spend_cap_minor > 0
    # ...and it outranks a free agent with a corporate human
    assert svc.rails > resolve(AgentTier.FREE, HumanTier.ENTERPRISE).rails


def test_ttl_never_exceeds_protocol_cap():
    for row in lattice_table():
        assert row["ttl_seconds"] <= MAX_TTL


def test_entitlements_only_narrow():
    base = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE)
    narrowed = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE,
                       Entitlements(approval_limit_minor=1000,
                                    denied_scopes=["pay:*"]))
    assert narrowed.spend_cap_minor == 1000
    assert "pay:*" not in narrowed.scopes
    assert len(narrowed.scopes) < len(base.scopes)


def test_entitlements_cannot_widen():
    low = resolve(AgentTier.FREE, HumanTier.PUBLIC,
                  Entitlements(allowed_scopes=["pay:*"], approval_limit_minor=10**9))
    # an entitlement cannot grant a scope the tier never had
    assert "pay:*" not in low.scopes
    # spend cap was 0 (no rails) — an entitlement limit must not create settlement
    assert low.rails == 0


def test_zero_limit_disables_settlement():
    t = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE,
                Entitlements(approval_limit_minor=0))
    assert t.spend_cap_minor == 0 and t.settlement == "none" and t.rails == 0


def test_upgrade_path_terminates():
    assert next_upgrade(AgentTier.FREE, HumanTier.PUBLIC).startswith("Agent")
    assert next_upgrade(AgentTier.COMPANY, HumanTier.PUBLIC).startswith("Human")
    assert next_upgrade(AgentTier.COMPANY, HumanTier.ENTERPRISE) is None


def test_session_binding_shape():
    b = session_binding(AgentTier.REGISTRY, HumanTier.GENERAL_SSO,
                        "0xabc", 42001)
    for k in ("agentId", "certFootprint", "railsBitmap", "ttlSeconds",
              "posture", "scopes", "tier"):
        assert k in b, f"missing {k}"
    assert b["tier"] == "A1xH1"
    assert b["railsBitmap"] & Rail.X402


# ── ARD catalog ────────────────────────────────────────────────────────────

_TOOLS = [
    {"name": "fetch", "description": "Fetch a URL and return its text.",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
    {"name": "summarize", "description": "Summarize a document into bullet points.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
]


def _pub() -> Publisher:
    return Publisher(domain="acme.example", name="Acme Corp")


def test_urn_is_domain_anchored_and_stable():
    u = mint_urn("acme.example", "mcp-server", "Research Tools")
    assert u == "urn:ard:acme.example:mcp-server:research-tools"
    assert u == mint_urn("acme.example", "mcp-server", "research tools")


def test_representative_queries_derived_from_tools():
    qs = representative_queries(_TOOLS)
    assert qs, "should derive queries"
    joined = " ".join(qs).lower()
    assert "fetch" in joined and "summarize" in joined


def test_catalog_builds_and_validates():
    r = Resource(name="research", description="Research tools",
                 endpoint="https://acme.example/mcp", tools=_TOOLS,
                 trust_tier="A2xH2", xcp_gateway="https://gw.acme.example")
    cat = build_catalog(_pub(), [r])
    assert validate_catalog(cat) == [], validate_catalog(cat)
    e = cat["entries"][0]
    assert e["id"].startswith("urn:ard:acme.example:")
    assert e["trust"]["xcpTrustTier"] == "A2xH2"
    assert e["trust"]["verifiedAtConnect"] is True
    assert e["representativeQueries"]


def test_value_or_reference_rule():
    # ARD requires exactly one of url/data — validator must catch a violation
    cat = build_catalog(_pub(), [Resource(name="x", description="d",
                                          endpoint="https://a.example/mcp", tools=_TOOLS)])
    cat["entries"][0]["data"] = {"inline": True}
    assert any("exactly one of url or data" in p for p in validate_catalog(cat))


def test_validator_flags_real_problems():
    cat = build_catalog(_pub(), [Resource(name="x", description="d",
                                          endpoint="http://a.example/mcp")])
    problems = validate_catalog(cat)
    assert any("https" in p for p in problems)
    assert any("representativeQueries" in p for p in problems)


def test_duplicate_ids_detected():
    r = Resource(name="same", description="d", endpoint="https://a.example/mcp", tools=_TOOLS)
    cat = build_catalog(_pub(), [r, r])
    assert any("duplicated" in p for p in validate_catalog(cat))


def test_endpoint_required():
    try:
        build_catalog(_pub(), [Resource(name="x", description="d", endpoint="")])
        assert False, "should reject an empty endpoint"
    except CatalogError:
        pass


def test_mcp_manifest_shape():
    r = Resource(name="research", description="Research tools",
                 endpoint="https://acme.example/mcp", tools=_TOOLS, trust_tier="A1xH1")
    m = build_mcp_manifest(_pub(), r)
    assert m["name"] == "acme-example/research"
    assert m["remotes"][0]["url"] == "https://acme.example/mcp"
    assert m["_xcp"]["trustTier"] == "A1xH1"


def test_resource_from_tools_list():
    r = resource_from_tools_list("research", "d", "https://a.example/mcp",
                                 {"tools": _TOOLS})
    assert len(r.tools) == 2
    cat = build_catalog(_pub(), [r])
    assert cat["entries"][0]["toolCount"] == 2


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
