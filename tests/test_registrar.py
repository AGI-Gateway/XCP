"""
test_registrar.py — the chain is one option, and the lattice stays honest.

XCP's lattice always said A0 means "self-asserted keypair" and A2 means "a legal
entity signs the root". That was a claim about who vouched, and it never needed
a blockchain -- but the implementation did: session/open refused any request
without a non-zero ERC-8004 agentId, and the production profile refused to start
without a verifier. So the only chain-free path was the development profile,
which self-registers anything.

These tests hold the replacement to two standards at once:

  * A node must be able to run the production profile with nothing but the CA
    or identity provider the operator already has.
  * Removing the chain must not make any tier cheaper. A registrar can only
    justify what it actually establishes.

    python tests/test_registrar.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from trust.registrar import (CEILINGS, PRODUCTION_SAFE, Attestation,  # noqa: E402
                             Registrar, RegistrarConfig, RegistrarError,
                             describe, from_env)
from trust.tiers import AgentTier, HumanTier, resolve                 # noqa: E402

CA = {"XCP_PEER_CA_BUNDLE": "/etc/xcp/ca.pem"}
IDP = {"XCP_OIDC_ISSUER": "https://idp.example/"}
CHAIN = {"XCP_VERIFY_URL": "http://verifier:8500"}


# ── the ceilings are the whole safety argument ────────────────────────────

def test_each_registrar_justifies_exactly_what_it_establishes():
    assert CEILINGS[Registrar.NONE] is AgentTier.FREE
    assert CEILINGS[Registrar.MTLS] is AgentTier.REGISTRY
    assert CEILINGS[Registrar.OIDC] is AgentTier.REGISTRY
    assert CEILINGS[Registrar.CHAIN] is AgentTier.COMPANY


def test_only_a_registry_can_justify_a_company_tier():
    """
    A2 means a legal entity signed a root that someone who does NOT trust this
    operator can check. An internal CA is the operator vouching for themselves,
    which is a different claim however good their key management is.
    """
    for kind in (Registrar.NONE, Registrar.MTLS, Registrar.OIDC):
        assert int(CEILINGS[kind]) < int(AgentTier.COMPANY), (
            f"{kind.value} defaults to a ceiling that lets a node assert A2 "
            f"on its own say-so")


def test_self_assertion_is_not_a_production_registrar():
    assert Registrar.NONE not in PRODUCTION_SAFE
    ok, why = from_env({"XCP_REGISTRAR": "none"}).permits_production()
    assert not ok and "absence of one" in why


def test_the_production_profile_accepts_a_ca_or_an_idp():
    """The point of the change: a real production node with no chain."""
    for env in ({"XCP_REGISTRAR": "mtls", **CA},
                {"XCP_REGISTRAR": "oidc", **IDP}):
        ok, why = from_env(env).permits_production()
        assert ok, f"{env} was refused: {why}"


def test_a_registrar_with_no_authority_configured_is_refused():
    """
    mtls with no CA and oidc with no issuer would check nothing at all, which
    is self-assertion wearing a registrar's name.
    """
    for kind, missing in (("mtls", "XCP_PEER_CA_BUNDLE"), ("oidc", "XCP_OIDC_ISSUER")):
        ok, why = from_env({"XCP_REGISTRAR": kind}).permits_production()
        assert not ok, f"{kind} with no authority was accepted"
        assert missing in why, f"the error does not say to set {missing}"
    ok, why = from_env({"XCP_REGISTRAR": "chain"}).permits_production()
    assert not ok and "XCP_VERIFY_URL" in why


# ── configuration ─────────────────────────────────────────────────────────

def test_the_registrar_is_inferred_from_a_configured_verifier():
    """An operator who set up a verifier should not also have to name chain."""
    assert from_env(CHAIN).kind is Registrar.CHAIN
    assert from_env({}).kind is Registrar.NONE


def test_explicit_configuration_beats_inference():
    cfg = from_env({"XCP_REGISTRAR": "mtls", **CA, **CHAIN})
    assert cfg.kind is Registrar.MTLS


def test_an_unknown_registrar_is_refused_rather_than_defaulted():
    try:
        from_env({"XCP_REGISTRAR": "blockchain"})
        raise AssertionError("an unknown registrar was accepted")
    except RegistrarError as e:
        assert "not one of" in str(e)


def test_lowering_the_ceiling_is_quiet():
    """Trusting your own registrar less is not a claim anyone must evaluate."""
    cfg = from_env({"XCP_REGISTRAR": "chain", "XCP_REGISTRAR_CEILING": "A0", **CHAIN})
    assert cfg.ceiling is AgentTier.FREE and not cfg.raised


def test_raising_the_ceiling_is_permitted_and_published():
    """
    There are real deployments where an internal CA IS a legal entity signing.
    The answer is publication, not refusal -- but it must be impossible to do
    quietly.
    """
    cfg = from_env({"XCP_REGISTRAR": "mtls", "XCP_REGISTRAR_CEILING": "A2", **CA})
    assert cfg.ceiling is AgentTier.COMPANY
    assert cfg.raised is True
    assert cfg.to_dict()["ceilingRaised"] is True
    assert "RAISED" in describe(cfg) and "discount" in describe(cfg)


def test_a_bad_ceiling_is_refused():
    try:
        from_env({"XCP_REGISTRAR": "mtls", "XCP_REGISTRAR_CEILING": "enterprise", **CA})
        raise AssertionError("a nonsense ceiling was accepted")
    except RegistrarError as e:
        assert "agent tier" in str(e)


def test_the_published_record_names_what_vouches_and_not_where_it_lives():
    """
    A peer needs to know WHAT vouches. A CA bundle path is internal topology
    and a secret is a secret; neither belongs in a public record.
    """
    d = from_env({"XCP_REGISTRAR": "oidc", **IDP}).to_dict()
    assert d["kind"] == "oidc" and d["authorityConfigured"] is True
    assert "https://idp.example/" not in str(d)
    assert "/etc/xcp" not in str(from_env({"XCP_REGISTRAR": "mtls", **CA}).to_dict())


# ── the point of it all ───────────────────────────────────────────────────

def test_a_capable_production_tier_is_reachable_with_no_chain():
    """
    A1xH2 -- an internal CA for the agent, enterprise SSO for the human -- is
    "Delegated corporate": chain scopes, three rails, a 250,000 ceiling,
    metered settlement, full enforcement. If this ever stops being reachable
    without a chain, the adoption wall is back.
    """
    cfg = from_env({"XCP_REGISTRAR": "mtls", **CA})
    assert int(cfg.ceiling) >= int(AgentTier.REGISTRY)

    envelope = resolve(AgentTier.REGISTRY, HumanTier.ENTERPRISE)
    assert envelope.cell == "A1xH2"
    assert envelope.posture == "enforce"
    assert envelope.settlement == "metered"
    assert envelope.spend_cap_minor >= 100_000
    assert any(s.startswith("t2t:chain") for s in envelope.scopes), \
        "A1xH2 no longer carries chain scopes; the chain-free ceiling is weaker"


def test_the_chain_still_buys_something():
    """
    If a chain-free node could reach every tier, the registry would be
    decoration. A2 must remain out of reach by default.
    """
    for kind in ("mtls", "oidc"):
        env = {"XCP_REGISTRAR": kind, **CA, **IDP}
        assert from_env(env).ceiling is not AgentTier.COMPANY
    assert from_env({"XCP_REGISTRAR": "chain", **CHAIN}).ceiling is AgentTier.COMPANY


def test_the_registrar_caps_the_agent_leg_only():
    """
    The two legs are vouched for by different parties. Capping the human leg
    with the agent's registrar would let an internal CA silently downgrade an
    enterprise SSO session, which the lattice explicitly does not say.
    """
    from federation.delegation import narrow_tier
    cfg = from_env({"XCP_REGISTRAR": "mtls", **CA})
    ceiling = f"A{int(cfg.ceiling)}xH2"
    assert narrow_tier("A2xH2", ceiling) == "A1xH2"
    assert narrow_tier("A2xH0", ceiling) == "A1xH0"
    assert narrow_tier("A0xH1", ceiling) == "A0xH1"


def test_an_attestation_refuses_cleanly():
    a = Attestation.refused(Registrar.MTLS, "certificate is not signed by the anchored CA")
    assert not a.ok and a.agent_tier is AgentTier.FREE and a.agent_id == 0


def test_an_attestation_without_a_numeric_id_is_normal():
    """
    Only a registry issues numbers. The footprint is the identity everywhere
    else, which is what "self-asserted keypair" and "the CA signed this
    certificate" both actually mean.
    """
    a = Attestation(registrar=Registrar.MTLS, subject="CN=svc-reconciliation",
                    footprint="0x" + "ab" * 32, agent_tier=AgentTier.REGISTRY)
    assert a.ok and a.agent_id == 0 and a.to_dict()["agentId"] == 0


def test_the_settings_registry_documents_every_registrar_knob():
    from ops.config import get
    for name in ("XCP_REGISTRAR", "XCP_REGISTRAR_CEILING", "XCP_OIDC_ISSUER",
                 "XCP_CLIENT_CA_BUNDLE"):
        s = get(name)
        assert s is not None, f"{name} is not in ops.config.SETTINGS"
    assert get("XCP_REGISTRAR_CEILING").unsafe, (
        "raising the ceiling weakens what a peer can rely on and must be "
        "marked unsafe so `xcp config --unsafe` lists it")


def test_the_gateway_requires_an_agent_id_only_for_a_registry():
    """The wire format is unchanged -- 0;0;<footprint> already parses -- so
    this needed no SDK vector changes. Guard that it stays that way."""
    from protocol.identity import parse
    ident = parse("0;0;0x" + "ab" * 32)
    assert ident.agent_id == 0 and ident.chain_id == 0
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    assert "Registrar.CHAIN and not agent_id" in src, (
        "session_open no longer makes agentId conditional on the registrar")


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
