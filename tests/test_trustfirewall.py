"""
test_trustfirewall.py — stateless MCP identity and graded corpus reachability.

The invariants that matter:
  · a credential cannot be replayed against a different call
  · verification needs no shared state (any instance, cold start, any region)
  · nothing binding ever happens against an unvetted server
  · money never moves toward an anonymous or unattested counterparty
  · the whole corpus stays reachable — unvetted means observed, not blocked

    python tests/test_trustfirewall.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from trustfirewall.stateless import (mint, verify, scope_for, bind_digest,
                                     RequestCredential, McpRequest, new_flow,
                                     CredentialError, H_MCP_METHOD, H_MCP_NAME,
                                     H_XCP_CREDENTIAL, MCP_SPEC_TARGET)
from trustfirewall.firewall import (TrustFirewall, ServerClass, Effect,
                                    reachability, corpus_matrix, is_read_only)

KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
FP = "0x" + "ab" * 32


def _cred(method="tools/call", name="search", body=b"{}", tier="A2xH2", **kw):
    return mint(KEY, agent_id=42001, chain_id=8453, footprint=FP, tier=tier,
                mcp_method=method, mcp_name=name, body=body, **kw)


def _headers(cred, method="tools/call", name="search"):
    return {H_MCP_METHOD: method, H_MCP_NAME: name,
            H_XCP_CREDENTIAL: cred.to_header()}


# ── scope derivation from the mandatory MCP 2026-07-28 headers ─────────────

def test_scope_maps_from_headers_without_body():
    assert scope_for("tools/call", "search") == "mcp:tools/search"
    assert scope_for("tools/list") == "mcp:tools/list"
    assert scope_for("resources/read", "file://x") == "mcp:resources/read"
    assert scope_for("prompts/get", "greet") == "mcp:prompts/greet"


def test_unknown_method_still_yields_a_scope():
    # total mapping: unknown calls get a scope so they are denied by policy,
    # not allowed because no rule matched
    assert scope_for("weird/thing").startswith("mcp:")
    assert scope_for("") == "mcp:unknown/"


def test_read_only_classification():
    assert is_read_only("tools/list") and is_read_only("resources/read")
    assert not is_read_only("tools/call")


# ── stateless credential ───────────────────────────────────────────────────

def test_valid_credential_verifies():
    c = _cred()
    assert verify(c, mcp_method="tools/call", mcp_name="search", body=b"{}") == []


def test_verification_is_stateless():
    """Serialise, discard everything, verify from the wire form alone."""
    wire = _cred().to_header()
    fresh = RequestCredential.from_header(wire)
    assert verify(fresh, mcp_method="tools/call", mcp_name="search", body=b"{}") == []


def test_replay_against_a_different_tool_fails():
    c = _cred(name="search")
    problems = verify(c, mcp_method="tools/call", mcp_name="transfer_funds", body=b"{}")
    assert problems, "credential must not work for a different tool"
    assert any("scope mismatch" in p or "binding" in p for p in problems)


def test_replay_with_altered_arguments_fails():
    c = _cred(body=b'{"amount":1}')
    problems = verify(c, mcp_method="tools/call", mcp_name="search",
                      body=b'{"amount":1000000}')
    assert any("binding mismatch" in p for p in problems)


def test_expired_credential_rejected():
    c = _cred(ttl_seconds=1)
    assert any("expired" in p for p in
               verify(c, mcp_method="tools/call", mcp_name="search",
                      body=b"{}", now=int(time.time()) + 30))


def test_overlong_ttl_rejected():
    c = _cred(ttl_seconds=86400)
    assert any("ttl exceeds" in p for p in
               verify(c, mcp_method="tools/call", mcp_name="search", body=b"{}"))


def test_tampered_signature_detected():
    c = _cred()
    c.agent_id = 99999
    assert verify(c, mcp_method="tools/call", mcp_name="search", body=b"{}")


def test_unsigned_credential_rejected():
    c = RequestCredential(agent_id=1, chain_id=1, footprint=FP, tier="A0xH0",
                          scope="mcp:tools/x", bind=bind_digest("tools/call", "x", b""),
                          exp=int(time.time()) + 60)
    assert any("unsigned" in p for p in
               verify(c, mcp_method="tools/call", mcp_name="x", body=b""))


def test_malformed_header_raises():
    try:
        RequestCredential.from_header("!!!not-base64!!!")
        assert False, "should reject a malformed credential"
    except CredentialError:
        pass


def test_legacy_session_header_flagged():
    req = McpRequest.from_headers({H_MCP_METHOD: "tools/list",
                                   "mcp-session-id": "abc123"})
    signals = req.legacy_signals()
    assert any("mcp-session-id" in s for s in signals)
    assert MCP_SPEC_TARGET in signals[0]


def test_deprecated_method_flagged():
    req = McpRequest.from_headers({H_MCP_METHOD: "sampling/createMessage"})
    assert any("deprecated" in s for s in req.legacy_signals())


def test_mrtr_flow_links_round_trips():
    flow = new_flow()
    a = _cred(body=b'{"step":1}', flow=flow)
    b = _cred(body=b'{"step":2}', flow=flow)
    assert a.flow == b.flow and a.nonce != b.nonce
    # each round trip is independently bound to its own body
    assert verify(a, mcp_method="tools/call", mcp_name="search", body=b'{"step":1}') == []
    assert verify(a, mcp_method="tools/call", mcp_name="search", body=b'{"step":2}')


# ── graded reachability ────────────────────────────────────────────────────

def test_unvetted_server_is_reachable_but_never_binding():
    for tier in (0, 1, 2):
        effect, settlement, ob, _ = reachability(tier, ServerClass.UNKNOWN, read_only=True)
        assert effect == Effect.OBSERVE, "the corpus stays reachable"
        assert settlement == "none", "nothing binding against an unvetted server"
        assert ob.quarantine_output and ob.sandbox_execution


def test_unvetted_server_refuses_writes():
    for tier in (0, 1, 2):
        effect, _, _, _ = reachability(tier, ServerClass.UNKNOWN, read_only=False)
        assert effect == Effect.DENY


def test_free_agent_may_read_the_world_but_not_change_it():
    for klass in (ServerClass.PROBED, ServerClass.ATTESTED, ServerClass.CONTRACTED):
        r_effect, _, _, _ = reachability(0, klass, read_only=True)
        w_effect, _, _, _ = reachability(0, klass, read_only=False)
        assert r_effect == Effect.ALLOW
        assert w_effect == Effect.DENY


def test_settlement_requires_an_accountable_counterparty():
    for tier in (0, 1, 2):
        for klass in (ServerClass.UNKNOWN,):
            _, settlement, _, _ = reachability(tier, klass, read_only=False)
            assert settlement == "none"
    # full settlement only at the top of both axes
    _, s, _, _ = reachability(2, ServerClass.CONTRACTED, read_only=False)
    assert s == "full"
    _, s, _, _ = reachability(1, ServerClass.CONTRACTED, read_only=False)
    assert s == "metered"


def test_every_settling_combination_requires_a_receipt():
    for row in corpus_matrix():
        if row["settlement"] != "none":
            assert row["receipt"], f"{row} settles without a receipt obligation"


def test_output_from_non_contracted_is_quarantined():
    for row in corpus_matrix():
        if row["serverClass"] != "contracted":
            assert row["quarantine"], f"{row} does not quarantine untrusted output"


def test_matrix_is_complete():
    rows = corpus_matrix()
    assert len(rows) == 3 * 4 * 2, "3 caller tiers x 4 server classes x read/write"


# ── the firewall end to end ────────────────────────────────────────────────

def _fw(posture="enforce"):
    fw = TrustFirewall(posture=posture)
    fw.load_lattice()
    return fw


def test_firewall_allows_a_good_call():
    fw = _fw()
    fw.classify("api.acme.example", ServerClass.CONTRACTED)
    c = _cred(method="tools/call", name="search", body=b"{}")
    d = fw.decide(_headers(c), b"{}", server_host="api.acme.example")
    assert d.allowed and d.binding, d.reason
    assert d.scope == "mcp:tools/search"


def test_firewall_denies_missing_method_header():
    fw = _fw()
    d = fw.decide({H_MCP_NAME: "search"}, b"{}", server_host="x")
    assert not d.allowed and "Mcp-Method" in d.reason


def test_firewall_denies_anonymous_in_enforce():
    fw = _fw()
    fw.classify("api.acme.example", ServerClass.CONTRACTED)
    d = fw.decide({H_MCP_METHOD: "tools/call", H_MCP_NAME: "search"}, b"{}",
                  server_host="api.acme.example")
    assert not d.allowed and "anonymous" in d.reason


def test_firewall_observes_anonymous_in_observe_posture():
    fw = _fw(posture="observe")
    d = fw.decide({H_MCP_METHOD: "tools/list"}, b"", server_host="unknown.example")
    assert d.effect == Effect.OBSERVE and not d.binding


def test_firewall_never_binds_against_unknown_server():
    fw = _fw()
    c = _cred(method="tools/list", name="", body=b"")
    d = fw.decide(_headers(c, "tools/list", ""), b"", server_host="random.example")
    assert d.effect == Effect.OBSERVE, "unknown server: reachable but not binding"
    assert d.settlement == "none"
    assert d.obligations.quarantine_output


def test_firewall_blocks_write_to_unknown_server():
    fw = _fw()
    c = _cred(method="tools/call", name="delete_all", body=b"{}")
    d = fw.decide(_headers(c, "tools/call", "delete_all"), b"{}",
                  server_host="random.example")
    assert not d.allowed


def test_firewall_blocks_replayed_credential():
    fw = _fw()
    fw.classify("api.acme.example", ServerClass.CONTRACTED)
    c = _cred(name="search", body=b"{}")
    # same credential, different tool
    d = fw.decide(_headers(c, "tools/call", "transfer_funds"), b"{}",
                  server_host="api.acme.example")
    assert not d.allowed


def test_firewall_enforces_tier_scope():
    fw = _fw()
    fw.classify("api.acme.example", ServerClass.CONTRACTED)
    fw.set_tier_scopes("A0xH0", ["mcp:tools/*.read"])
    c = _cred(method="tools/call", name="delete", body=b"{}", tier="A0xH0")
    d = fw.decide(_headers(c, "tools/call", "delete"), b"{}",
                  server_host="api.acme.example")
    assert not d.allowed


def test_observe_posture_downgrades_never_upgrades():
    fw = _fw(posture="observe")
    fw.classify("api.acme.example", ServerClass.CONTRACTED)
    c = _cred(body=b"{}")
    d = fw.decide(_headers(c), b"{}", server_host="api.acme.example")
    assert d.effect == Effect.OBSERVE and d.settlement == "none"


def test_decision_carries_an_audit_trail():
    fw = _fw()
    fw.classify("api.acme.example", ServerClass.ATTESTED)
    c = _cred(body=b"{}")
    d = fw.decide(_headers(c), b"{}", server_host="api.acme.example")
    assert d.checks and any("server_class" in x for x in d.checks)
    assert "effect" in d.to_dict() and "obligations" in d.to_dict()


def test_unclassified_host_defaults_to_unknown():
    fw = _fw()
    assert fw.class_of("never-seen.example") == ServerClass.UNKNOWN


def test_legacy_client_surfaces_as_warning_not_failure():
    fw = _fw()
    fw.classify("api.acme.example", ServerClass.CONTRACTED)
    c = _cred(body=b"{}")
    h = _headers(c)
    h["mcp-session-id"] = "stale-session"
    d = fw.decide(h, b"{}", server_host="api.acme.example")
    assert d.allowed, "a stale header should warn, not break the call"
    assert any("mcp-session-id" in w for w in d.warnings)


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
