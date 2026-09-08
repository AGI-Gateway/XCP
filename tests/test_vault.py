"""
test_vault.py — credentials stay out of the repository, by construction.

The most important test here is `test_no_credentials_anywhere_in_the_repo`. It is
a build-breaking control, not a guideline: if anyone ever commits something
shaped like a live credential, CI fails before it reaches a public mirror where
git history would keep it forever.

    python tests/test_vault.py
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vault import (SecretRef, Secret, Vault, VaultConfig, Backend, VaultError,
                   SecretNotFound, scan_for_secrets, IdentityProvider,
                   AuthMethod, ProviderKind, PUBLIC_PROVIDERS, PRIVATE_PROVIDERS,
                   load_builtin, providers, get_provider, reset,
                   register_provider, IdPError, entitlements_from_claims)
from connectors import load_catalog, required_secrets, CatalogError, parse_entry


# ── the rule: references, never values ─────────────────────────────────────

def test_secret_ref_has_nowhere_to_put_a_value():
    ref = SecretRef(backend=Backend.ENV, path="connectors/github", key="token")
    assert not hasattr(ref, "value")
    assert "value" not in ref.to_dict()


def test_ref_roundtrips_through_its_uri():
    uri = "vault://hashicorp/xcp/connectors/github#client_secret"
    r = SecretRef.parse(uri)
    assert r.backend == Backend.HASHICORP
    assert r.path == "xcp/connectors/github" and r.key == "client_secret"
    assert r.uri == uri


def test_ref_rejects_a_literal_credential():
    for literal in ["ghp_" + "A" * 30, "AKIA" + "B" * 16, "sk-" + "c" * 24]:
        try:
            SecretRef(backend=Backend.ENV, path=literal)
            assert False, f"should refuse a literal: {literal[:8]}…"
        except VaultError:
            pass


def test_unknown_scheme_or_backend_rejected():
    for bad in ["https://example.com/secret", "vault://nope/path"]:
        try:
            SecretRef.parse(bad); assert False, f"should reject {bad}"
        except VaultError:
            pass


def test_dev_backends_refused_for_production():
    for b in (Backend.ENV, Backend.FILE):
        try:
            SecretRef(backend=b, path="p").require_production_backend()
            assert False, f"{b} must not pass a production check"
        except VaultError:
            pass
    SecretRef(backend=Backend.HASHICORP, path="p").require_production_backend()


# ── a resolved Secret resists leaking ──────────────────────────────────────

def test_secret_never_renders_its_value():
    s = Secret("super-secret-value",
               SecretRef(backend=Backend.ENV, path="a", key="b"))
    for rendered in (repr(s), str(s), f"{s}", "{}".format(s)):
        assert "super-secret-value" not in rendered
        assert "redacted" in rendered
    assert s.reveal() == "super-secret-value", "explicit access still works"


def test_secret_refuses_serialisation():
    s = Secret("v")
    try:
        s.for_json(); assert False, "should refuse to serialise"
    except VaultError:
        pass
    try:
        json.dumps(s); assert False, "should not be JSON-encodable"
    except TypeError:
        pass


def test_secret_refuses_iteration():
    try:
        list(Secret("abc")); assert False, "should refuse iteration"
    except VaultError:
        pass


# ── resolution ─────────────────────────────────────────────────────────────

def test_env_backend_resolves_and_reports_missing():
    v = Vault(VaultConfig(env_prefix="XCP_TEST_"))
    ref = SecretRef(backend=Backend.ENV, path="connectors/demo", key="token")
    os.environ["XCP_TEST_CONNECTORS_DEMO_TOKEN"] = "resolved-ok"
    try:
        assert v.resolve(ref).reveal() == "resolved-ok"
    finally:
        del os.environ["XCP_TEST_CONNECTORS_DEMO_TOKEN"]
    try:
        v.resolve(ref); assert False, "a required secret that is unset must raise"
    except SecretNotFound:
        pass
    optional = SecretRef(backend=Backend.ENV, path="connectors/demo",
                         key="token", required=False)
    assert v.resolve(optional).reveal() == ""


def test_unconfigured_managed_backend_fails_loudly():
    v = Vault()
    try:
        v.resolve(SecretRef(backend=Backend.AWS, path="p", key="k"))
        assert False, "must not silently return nothing"
    except VaultError as e:
        assert "register_resolver" in str(e), "the error should say how to fix it"


def test_custom_resolver_can_be_registered():
    v = Vault()
    v.register_resolver(Backend.AWS, lambda path, key: f"{path}:{key}")
    assert v.resolve(SecretRef(backend=Backend.AWS, path="p", key="k")).reveal() == "p:k"


def test_relative_file_root_rejected():
    try:
        Vault(VaultConfig(file_root="./secrets")); assert False
    except VaultError:
        pass


# ── identity providers ─────────────────────────────────────────────────────

def test_public_and_private_providers_present():
    reset(); load_builtin()
    ids = {p.id for p in providers()}
    for expected in ("google", "microsoft", "meta", "entra-id", "okta",
                     "active-directory"):
        assert expected in ids, f"missing {expected}"


def test_public_providers_map_to_h1_private_with_entitlements_to_h2():
    reset(); load_builtin()
    for p in providers(ProviderKind.PUBLIC):
        assert p.human_tier() == 1, f"{p.id} should be H1"
    assert get_provider("entra-id").human_tier() == 2
    assert get_provider("okta").human_tier() == 2


def test_identity_without_entitlements_is_only_h1():
    """Knowing who someone is does not tell you what they may spend."""
    p = IdentityProvider(id="dir-only", name="Directory", kind=ProviderKind.PRIVATE,
                         methods=[AuthMethod.LDAP], supports_entitlements=False)
    assert p.human_tier() == 1


def test_consumer_provider_cannot_claim_entitlements():
    p = IdentityProvider(id="bad", name="Bad", kind=ProviderKind.PUBLIC,
                         methods=[AuthMethod.OIDC], issuer="https://x",
                         supports_entitlements=True, groups_claim="groups")
    assert any("consumer provider" in x for x in p.validate())


def test_providers_carry_no_literal_secrets():
    reset(); load_builtin()
    for p in providers():
        blob = json.dumps(p.to_dict())
        assert not scan_for_secrets(blob), f"{p.id} contains a literal credential"
        for r in (p.client_id_ref, p.client_secret_ref):
            if r is not None:
                assert r.uri.startswith("vault://")


def test_all_builtin_providers_validate():
    for p in list(PUBLIC_PROVIDERS.values()) + list(PRIVATE_PROVIDERS.values()):
        assert p.validate() == [], f"{p.id}: {p.validate()}"


def test_https_enforced_on_provider_endpoints():
    p = IdentityProvider(id="x", name="x", kind=ProviderKind.PRIVATE,
                         methods=[AuthMethod.OIDC], issuer="https://i",
                         token_url="http://insecure.example/token")
    assert any("https" in m for m in p.validate())


def test_claims_become_narrowing_entitlements():
    reset(); load_builtin()
    okta = get_provider("okta")
    ent = entitlements_from_claims(okta, {
        "groups": ["finance", "approvers"],
        "cost_center": "CC-1024",
        "approval_limit": 50_000,
    })
    assert ent.groups == ["finance", "approvers"]
    assert ent.cost_center == "CC-1024"
    assert ent.approval_limit_minor == 50_000
    # and it can only narrow the lattice, never widen it
    from trust.tiers import AgentTier, HumanTier, resolve
    base = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE)
    narrowed = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE, ent)
    assert narrowed.spend_cap_minor == 50_000
    assert base.spend_cap_minor == 0 or narrowed.spend_cap_minor <= base.spend_cap_minor


def test_duplicate_provider_registration_refused():
    reset(); load_builtin()
    try:
        register_provider(get_provider("google")); assert False
    except IdPError:
        pass


# ── connector catalog ──────────────────────────────────────────────────────

def test_catalog_loads_and_every_entry_validates():
    entries = load_catalog()
    assert entries, "catalog should not be empty"
    for e in entries:
        assert e.validate() == [], f"{e.id}: {e.validate()}"


def test_every_catalog_secret_is_a_reference():
    for e in load_catalog():
        for name, ref in e.secret_refs.items():
            assert ref.startswith("vault://"), f"{e.id}.{name} is not a reference"
            assert not scan_for_secrets(ref), f"{e.id}.{name} is a literal"


def test_catalog_rejects_a_literal_credential():
    bad = {"id": "leaky", "name": "Leaky", "endpoint": {"url": "https://x/mcp"},
           "auth": {"method": "api_key",
                    "secrets": {"api_key": "ghp_" + "A" * 30}}}
    problems = parse_entry(bad).validate()
    assert any("literal" in p for p in problems), problems


def test_payments_connector_requires_top_tier_for_writes():
    for e in load_catalog():
        if "payments" in e.tags or "financial" in e.tags:
            assert e.min_write_tier.startswith("A2"), \
                f"{e.id} moves money but allows writes below A2"


def test_template_is_excluded_but_valid():
    ids = {e.id for e in load_catalog()}
    assert "example-saas" not in ids, "the template must not register"
    tmpl = [e for e in load_catalog(include_template=True) if e.id == "example-saas"]
    assert tmpl and tmpl[0].validate() == []


def test_required_secrets_lists_what_to_provision():
    req = required_secrets()
    assert req, "should report the secrets an operator must set"
    for cid, refs in req.items():
        for r in refs:
            assert r.startswith("vault://")


def test_catalog_registers_into_firewall_with_its_trust_class():
    from providers import reset as preset
    from trustfirewall import TrustFirewall, ServerClass
    from connectors import register_all
    preset()
    fw = TrustFirewall()
    n = register_all(firewall=fw)
    assert n >= 5
    assert fw.class_of("api.githubcopilot.com") == ServerClass.ATTESTED
    assert fw.class_of("mcp.stripe.com") == ServerClass.CONTRACTED


# ── the build-breaking control ─────────────────────────────────────────────

def test_no_credentials_anywhere_in_the_repo():
    """
    Scan every tracked text file for anything shaped like a live credential.
    This is the control that makes 'we never store secrets' true rather than
    aspirational — a leak fails CI before it reaches a public mirror.
    """
    skip_dirs = {".git", "__pycache__", "site", "dist", "node_modules", ".venv"}
    skip_files = {"test_vault.py", "refs.py"}      # these contain the patterns
    text_ext = {".py", ".md", ".yaml", ".yml", ".toml", ".json", ".sh", ".txt",
                ".proto", ".sol", ".go", ".java", ".html", ".css", ".cfg", ""}
    findings: list[str] = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or any(d in p.parts for d in skip_dirs):
            continue
        if p.name in skip_files or p.suffix not in text_ext:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue
        for kind in scan_for_secrets(text):
            findings.append(f"{p.relative_to(ROOT)}: {kind}")
    assert not findings, "credential-shaped material committed:\n  " + \
                         "\n  ".join(findings)


def test_no_certificate_or_key_files_tracked():
    bad = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
           if p.is_file() and p.suffix in {".key", ".pem", ".p12", ".pfx"}
           and ".git" not in p.parts]
    assert not bad, f"key material in the repo: {bad}"


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
