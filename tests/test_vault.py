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
    # The shipped catalog never claims `attested` or `contracted`. Those are
    # relationships an OPERATOR has with a vendor — a signed manifest they pinned,
    # a contract they hold — not facts about the vendor that a public catalog can
    # assert on their behalf. Promotion is always a local decision.
    assert fw.class_of("api.githubcopilot.com") == ServerClass.PROBED
    assert fw.class_of("mcp.stripe.com") == ServerClass.PROBED
    assert fw.class_of("mcp.notion.com") == ServerClass.PROBED


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


# ── verification status caps trust (the routing-safety rule) ───────────────

def test_verification_status_caps_trust_class():
    from connectors import parse_entry
    bad = {"id": "overclaim", "name": "Overclaim",
           "endpoint": {"url": "https://x.example/mcp"},
           "verification": {"status": "unconfirmed"},
           "auth": {"method": "none"},
           "trust": {"class": "contracted"}}
    problems = parse_entry(bad).validate()
    assert any("exceeds what a" in p for p in problems), problems


def test_confirmed_entry_must_cite_a_source():
    from connectors import parse_entry
    e = parse_entry({"id": "c", "name": "C",
                     "endpoint": {"url": "https://x.example/mcp"},
                     "verification": {"status": "confirmed"},
                     "auth": {"method": "none"}, "trust": {"class": "probed"}})
    assert any("must cite a source" in p for p in e.validate())


def test_self_hosted_uses_a_placeholder_host():
    from connectors import parse_entry
    e = parse_entry({"id": "s", "name": "S",
                     "endpoint": {"url": "https://real-looking.example/mcp"},
                     "verification": {"status": "self_hosted"},
                     "auth": {"method": "none"}, "trust": {"class": "unknown"}})
    assert any("placeholder" in p for p in e.validate())


def test_every_curated_entry_declares_verification():
    from connectors import load_catalog, VALID_VERIFICATION
    for e in load_catalog():
        assert e.verification_status in VALID_VERIFICATION
        if e.verification_status == "confirmed":
            assert e.verification_source.startswith("https://"), e.id


# ── global catalog: ingestion at scale ─────────────────────────────────────

def _catalog():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); return c


def test_curated_core_loads():
    c = _catalog()
    assert c.stats()["curated"] >= 20


def test_ingest_from_mcp_registry_shape():
    from connectors import Source, SourceKind
    c = _catalog()
    doc = {"servers": [
        {"name": "acme/tool", "description": "d",
         "remotes": [{"type": "streamable-http", "url": "https://mcp.acme.example/mcp"}]},
        {"name": "local-only", "description": "no remote", "remotes": []},
    ]}
    n = c.ingest(Source(id="reg", kind=SourceKind.OFFICIAL,
                        url="https://registry.example/v0/servers"), doc)
    assert n == 1, "stdio-only servers are not routable and must be skipped"


def test_ingested_entries_are_never_trusted_by_the_document():
    from connectors import Source, SourceKind
    c = _catalog()
    doc = {"entries": [{"id": "evil", "name": "Evil", "url": "https://evil.example/mcp",
                        "trust": {"slyTrustTier": "A2xH2", "auth": "none"}}]}
    c.ingest(Source(id="ard", kind=SourceKind.ARD, url="https://evil.example"), doc)
    e = [x for x in c.ingested.values() if x.host == "evil.example"][0]
    assert e.trust_class == "unknown", "a remote document must not set its own trust"
    assert e.verification_status == "unconfirmed"


def test_curated_wins_over_crawled():
    from connectors import Source, SourceKind
    c = _catalog()
    doc = {"servers": [{"name": "notion-impostor",
                        "remotes": [{"url": "https://mcp.notion.com/mcp"}]}]}
    c.ingest(Source(id="agg", kind=SourceKind.AGGREGATOR,
                    url="https://agg.example/list"), doc)
    assert not any(x.host == "mcp.notion.com" for x in c.ingested.values()), \
        "a crawled entry must not shadow a curated host"


def test_source_cannot_grant_trust_above_unknown():
    from connectors import Source, SourceKind, IngestError
    c = _catalog()
    s = Source(id="greedy", kind=SourceKind.AGGREGATOR,
               url="https://x.example/l", max_trust="contracted")
    try:
        c.ingest(s, {"servers": []}); assert False, "should refuse"
    except IngestError:
        pass


def test_ingestion_is_ssrf_guarded():
    from connectors import Source, SourceKind, IngestError
    c = _catalog()
    for bad in ("https://169.254.169.254/latest/meta-data/",
                "https://localhost/catalog.json"):
        try:
            c.ingest_url(Source(id="s", kind=SourceKind.ARD, url=bad))
            assert False, f"should refuse {bad}"
        except IngestError:
            pass


def test_all_entries_reach_the_firewall_as_unknown_unless_curated():
    from trustfirewall import TrustFirewall, ServerClass
    from connectors import Source, SourceKind
    c = _catalog()
    c.ingest(Source(id="a", kind=SourceKind.AGGREGATOR, url="https://a.example/l"),
             {"servers": [{"name": "rando",
                           "remotes": [{"url": "https://rando.example/mcp"}]}]})
    fw = TrustFirewall()
    c.apply_to_firewall(fw)
    assert fw.class_of("rando.example") == ServerClass.UNKNOWN
    assert fw.class_of("mcp.notion.com") == ServerClass.PROBED


def test_routing_prefers_verified_endpoints():
    c = _catalog()
    routes = c.route("mcp:tools/notion.search")
    assert routes and routes[0]["verification"] == "confirmed"


def test_export_is_ingestible_by_a_peer():
    from connectors import Source, SourceKind, GlobalCatalog
    a = _catalog()
    doc = a.export()
    b = GlobalCatalog()
    n = b.ingest(Source(id="peer", kind=SourceKind.PEER,
                        url="https://peer.example/catalog"), doc)
    assert n > 0, "a peer must be able to ingest our export"
    for e in b.ingested.values():
        assert e.trust_class == "unknown", "peer data is never trusted on arrival"


def test_oversized_document_refused():
    from connectors import IngestError
    from connectors.sources import _safe_fetch, MAX_DOCUMENT_BYTES
    big = "x" * (MAX_DOCUMENT_BYTES + 10)
    try:
        _safe_fetch("https://ok.example/doc", fetcher=lambda u: big)
        assert False, "should cap document size"
    except IngestError:
        pass


def test_shipped_catalog_never_claims_a_relationship_it_cannot_have():
    """
    `attested` means someone pinned a signed manifest; `contracted` means someone
    holds an agreement. Neither is a property of the vendor — both are properties
    of an operator's relationship with it. A public catalog must not assert them.
    """
    from connectors import load_catalog
    for e in load_catalog(include_template=True):
        assert e.trust_class in ("unknown", "probed"), (
            f"{e.id} ships as '{e.trust_class}'; promote locally instead")


# ── the long tail: routable vs installable ─────────────────────────────────

def test_snapshot_ships_thousands_of_real_servers():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated()
    n = c.load_snapshot()
    assert n > 3000, f"snapshot should carry the long tail, got {n}"


def test_most_of_the_ecosystem_is_installable_not_routable():
    """
    The honest shape of the corpus: the overwhelming majority of MCP servers are
    local stdio packages, not network endpoints. You cannot route agent traffic
    to a package that nobody is running.
    """
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    s = c.stats()
    assert s["ingestedByKind"]["installable"] > s["ingestedByKind"]["routable"] * 10


def test_installable_entries_are_never_classified_as_hosts():
    from connectors import GlobalCatalog
    from trustfirewall import TrustFirewall
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    fw = TrustFirewall()
    n = c.apply_to_firewall(fw)
    assert n < 500, "only routable endpoints belong in the firewall"
    for e in c.ingested.values():
        if not e.routable:
            assert e.host == "" or e.kind.value == "installable"


def test_snapshot_entries_arrive_untrusted():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    for e in list(c.ingested.values())[:400]:
        assert e.trust_class == "unknown"
        assert e.verification_status == "unconfirmed"


def test_snapshot_cannot_shadow_a_curated_host():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    curated_hosts = {__import__("urllib.parse", fromlist=["urlparse"])
                     .urlparse(x.endpoint_url).hostname for x in c.curated}
    for e in c.ingested.values():
        if e.routable:
            assert e.host not in curated_hosts


def test_repo_index_parser_extracts_remote_endpoints_when_present():
    from connectors.sources import normalise_repo_index, Source, SourceKind, EndpointKind
    md = ("- [acme/tool](https://github.com/acme/tool) - Does things. "
          "Remote endpoint `https://mcp.acme.example/mcp`.\n"
          "- [local/only](https://github.com/local/only) - Local only. "
          "Install: `npx -y local-only`.\n")
    got = normalise_repo_index(md, Source(id="s", kind=SourceKind.REPO_INDEX,
                                          url="https://raw.githubusercontent.com/x"))
    by_id = {e.id: e for e in got}
    assert by_id["acme-tool"].kind == EndpointKind.ROUTABLE
    assert by_id["acme-tool"].endpoint_url == "https://mcp.acme.example/mcp"
    assert by_id["local-only"].kind == EndpointKind.INSTALLABLE
    assert "npx" in by_id["local-only"].install_ref


# ── taxonomy: navigation, never trust ──────────────────────────────────────

def test_every_entry_gets_exactly_one_category():
    from connectors import GlobalCatalog, load_catalog
    from connectors.taxonomy import CATEGORIES
    for e in load_catalog():
        assert e.category in CATEGORIES, f"{e.id} -> {e.category}"
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    for e in list(c.ingested.values())[:500]:
        assert e.category in CATEGORIES


def test_classification_is_deterministic_and_first_match_wins():
    from connectors.taxonomy import classify
    assert classify("stripe-payments") == classify("stripe-payments")
    # a postgres vector-search server lands in one place, not three
    got = classify("pg-vector-search", "Postgres vector search for agents")
    assert got == "data-stores", got


def test_unclassified_residue_stays_honest():
    """`other` is honest residue. If it dominates, the taxonomy has stopped working."""
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    cats = c.categories()
    total = sum(v["total"] for v in cats.values())
    assert cats.get("other", {}).get("total", 0) / total < 0.25


def test_category_is_not_a_trust_signal():
    """A category must never raise what an entry is allowed to do."""
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    for e in list(c.ingested.values())[:300]:
        assert e.trust_class == "unknown"
        assert e.verification_status == "unconfirmed"


def test_browsing_by_category_filters_by_kind():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    routable = c.by_category("dev-tools", kind="routable", limit=200)
    assert routable, "dev-tools should have reachable endpoints"
    for r in routable:
        if not r.get("curated"):
            assert r["kind"] == "routable"


def test_curated_entries_classify_off_tags_not_boilerplate():
    from connectors import load_catalog
    by_id = {e.id: e for e in load_catalog()}
    assert by_id["stripe"].category == "finance-payments"
    assert by_id["github"].category == "dev-tools"
    assert by_id["notion"].category == "productivity"
    assert by_id["aws"].category == "cloud-infra"


# ── reachability + docs ────────────────────────────────────────────────────

def test_most_entries_carry_a_docs_link():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    withdocs = sum(1 for e in c.ingested.values() if e.docs)
    assert withdocs / len(c.ingested) > 0.7, "a catalog entry without docs is a dead end"


def test_validation_states_are_known_values():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    allowed = {"alive", "archived", "gone", "reachable", "unreachable", "unchecked"}
    for e in list(c.ingested.values())[:800]:
        assert e.validated in allowed, e.validated


def test_unchecked_is_reported_not_hidden():
    """A pass rate that quietly excludes unchecked entries is a lie."""
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    vs = c.validation_summary()
    assert "unchecked" in vs and vs["unchecked"] > 0


def test_validation_never_promotes_trust():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    for e in list(c.ingested.values())[:500]:
        assert e.trust_class == "unknown"


def test_dead_and_archived_artifacts_are_recorded():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    states = {e.validated for e in c.ingested.values()}
    assert "gone" in states and "archived" in states, \
        "validation must record failures, not silently drop them"


def test_curated_entries_expose_declared_tools():
    from connectors import load_catalog
    for e in load_catalog():
        assert e.scopes_exposed, f"{e.id} declares no tools"
        for s in e.scopes_exposed:
            assert s.startswith("mcp:"), s


# ── wrappable: public APIs, not yet MCP ────────────────────────────────────

def test_wrappable_is_not_routable():
    """
    The invariant this whole kind exists to protect: a public REST API is
    reachable, but an MCP agent cannot connect to it. Counting it as routable
    would send agent traffic somewhere every call fails.
    """
    from connectors.sources import EndpointKind
    assert EndpointKind.ROUTABLE.reachable_today is True
    assert EndpointKind.WRAPPABLE.reachable_today is False
    assert EndpointKind.INSTALLABLE.reachable_today is False


def test_wrappable_entries_never_reach_the_firewall():
    from connectors import GlobalCatalog
    from trustfirewall import TrustFirewall
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    wrappable = [e for e in c.ingested.values() if e.kind.value == "wrappable"]
    assert wrappable, "catalog should carry wrappable APIs"
    fw = TrustFirewall(); c.apply_to_firewall(fw)
    from trustfirewall import ServerClass
    for e in wrappable[:50]:
        assert not e.routable
        if e.host:
            assert fw.class_of(e.host) == ServerClass.UNKNOWN


def test_wrappable_needs_a_spec_to_be_a_lead():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    for e in c.ingested.values():
        if e.kind.value == "wrappable":
            assert e.spec_url, f"{e.id} is wrappable with no spec to generate from"


def test_openapi_parses_into_mcp_tools():
    from connectors.wrap import parse_openapi
    doc = {"openapi": "3.0.0", "info": {"title": "Demo", "version": "1"},
           "servers": [{"url": "https://api.demo.example"}],
           "paths": {"/things/{id}": {
               "get": {"operationId": "getThing", "summary": "Fetch a thing",
                       "parameters": [{"name": "id", "in": "path",
                                       "required": True,
                                       "schema": {"type": "string"}}]},
               "delete": {"operationId": "deleteThing"}}}}
    spec = parse_openapi(doc, api_id="demo")
    names = [o.tool_name for o in spec.operations]
    assert "getThing" in names
    assert "deleteThing" not in names, "DELETE must be opt-in"
    schema = spec.operations[0].input_schema()
    assert schema["required"] == ["id"]


def test_destructive_operations_are_opt_in():
    from connectors.wrap import parse_openapi
    doc = {"openapi": "3.0.0", "info": {"title": "D", "version": "1"},
           "servers": [{"url": "https://api.d.example"}],
           "paths": {"/x": {"delete": {"operationId": "wipe"}}}}
    try:
        parse_openapi(doc)
        assert False, "a spec with only DELETE should yield nothing by default"
    except Exception:
        pass
    spec = parse_openapi(doc, include_destructive=True)
    assert spec.operations[0].destructive


def test_spec_without_https_server_is_refused():
    from connectors.wrap import parse_openapi, WrapError
    doc = {"openapi": "3.0.0", "info": {"title": "X", "version": "1"},
           "servers": [{"url": "http://insecure.example"}],
           "paths": {"/a": {"get": {"operationId": "a"}}}}
    try:
        parse_openapi(doc); assert False, "must refuse a spec with no https server"
    except WrapError:
        pass


def test_generated_server_is_valid_python_and_holds_no_secret():
    from connectors.wrap import parse_openapi, generate
    from vault import scan_for_secrets
    doc = {"openapi": "3.0.0", "info": {"title": "Demo", "version": "1"},
           "servers": [{"url": "https://api.demo.example"}],
           "components": {"securitySchemes": {"b": {"type": "http",
                                                    "scheme": "bearer"}}},
           "paths": {"/x": {"get": {"operationId": "getX"}}}}
    spec = parse_openapi(doc, api_id="demo")
    code = generate(spec)
    compile(code, "<generated>", "exec")          # must be valid Python
    assert not scan_for_secrets(code), "a generated wrapper must contain no credential"
    assert "vault://" in code, "credentials must be resolved by reference"


def test_duplicate_operation_ids_are_disambiguated():
    from connectors.wrap import parse_openapi
    doc = {"openapi": "3.0.0", "info": {"title": "D", "version": "1"},
           "servers": [{"url": "https://api.d.example"}],
           "paths": {"/a": {"get": {"operationId": "same"}},
                     "/b": {"get": {"operationId": "same"}}}}
    names = [o.tool_name for o in parse_openapi(doc).operations]
    assert len(names) == len(set(names)), "MCP tool names must be unique"


# ── the wrappable set is complete and actually wrappable ───────────────────

def test_wrappable_set_is_substantial():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    w = [e for e in c.ingested.values() if e.kind.value == "wrappable"]
    assert len(w) > 2000, f"expected the full API directory, got {len(w)}"


def test_every_wrappable_entry_is_actually_wrappable():
    """A wrappable entry with no spec is a dead end, not a lead."""
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    for e in c.ingested.values():
        if e.kind.value == "wrappable":
            assert e.spec_url.startswith("https://"), e.id


def test_specs_are_mirrored_not_vendor_hosted():
    """
    Wrapping must not depend on a third-party API host being up. Specs resolve
    from a mirror we can reach independently of the API itself.
    """
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    w = [e for e in c.ingested.values() if e.kind.value == "wrappable"]
    mirrored = sum(1 for e in w if "raw.githubusercontent.com" in e.spec_url)
    assert mirrored / len(w) > 0.95


def test_wrappable_entries_are_categorised_not_dumped_in_other():
    from connectors import GlobalCatalog
    c = GlobalCatalog(); c.load_curated(); c.load_snapshot()
    w = [e for e in c.ingested.values() if e.kind.value == "wrappable"]
    other = sum(1 for e in w if e.category == "other")
    assert other / len(w) < 0.25, "the API taxonomy mapping has stopped working"


def test_swagger_2_specs_are_supported():
    """Much of the public API corpus is still Swagger 2.0, not OpenAPI 3."""
    from connectors.wrap import parse_openapi
    doc = {"swagger": "2.0", "info": {"title": "Old", "version": "1"},
           "host": "api.old.example", "basePath": "/v1", "schemes": ["https"],
           "paths": {"/things": {"get": {"operationId": "listThings"}}}}
    spec = parse_openapi(doc, api_id="old")
    assert spec.base_url == "https://api.old.example/v1"
    assert spec.operations[0].tool_name == "listThings"


def test_oauth2_specs_resolve_to_a_credential_reference():
    from connectors.wrap import parse_openapi, generate
    doc = {"openapi": "3.0.0", "info": {"title": "O", "version": "1"},
           "servers": [{"url": "https://api.o.example"}],
           "components": {"securitySchemes": {"o": {"type": "oauth2",
                                                    "flows": {}}}},
           "paths": {"/a": {"get": {"operationId": "a"}}}}
    spec = parse_openapi(doc, api_id="o")
    assert spec.auth_scheme == "oauth2"
    assert spec.secret_ref.startswith("vault://")
    compile(generate(spec), "<gen>", "exec")


# ── session-scoped credentials: what makes hosting defensible ──────────────

def _spec(mode, auth="bearer"):
    from connectors.wrap import parse_openapi, CredentialSource
    schemes = ({"b": {"type": "http", "scheme": "bearer"}} if auth == "bearer"
               else {})
    doc = {"openapi": "3.0.0", "info": {"title": "Demo", "version": "1"},
           "servers": [{"url": "https://api.demo.example"}],
           "components": {"securitySchemes": schemes},
           "paths": {"/x": {"get": {"operationId": "getX"}}}}
    return parse_openapi(doc, api_id="demo",
                         credential_source=CredentialSource(mode))


def test_session_wrapper_holds_no_secret_reference():
    """An operator wrapper points at the operator's vault. A session wrapper
    must point at nothing — there is no key of its own to resolve."""
    assert _spec("operator").secret_ref.startswith("vault://")
    assert _spec("session").secret_ref == ""


def test_session_mode_never_falls_back_to_the_operator_key():
    """
    The invariant this feature exists for: a caller who supplies no credential
    must fail, not quietly spend the host's money under the host's liability.
    """
    from connectors.wrap import generate
    code = generate(_spec("session"))
    assert "_operator_credential()" in code, "operator path still defined"
    body = code[code.index("def _credential("):code.index("def _auth_headers")]
    start = body.index('if CREDENTIAL_SOURCE == "session"')
    session_branch = body[start:body.index('if CREDENTIAL_SOURCE == "operator"')]
    assert "_operator_credential" not in session_branch, \
        "session mode must not reach the operator credential"
    assert "raise CredentialError" in session_branch
    # and an unrecognised mode must fail closed rather than pick a default
    assert "unknown credential source" in code


def test_session_credential_requires_a_verified_request():
    from connectors.wrap import generate
    code = generate(_spec("session"))
    body = code[code.index("def _credential("):code.index("def _auth_headers")]
    assert "if not verified" in body, \
        "an unverified request must not be able to present a session credential"


def test_no_auth_upstream_needs_no_credential_at_all():
    from connectors.wrap import CredentialSource
    s = _spec("session", auth="none")
    assert s.credential_source is CredentialSource.NONE
    assert s.secret_ref == ""


def test_generated_wrappers_never_embed_a_credential():
    from connectors.wrap import generate
    from vault import scan_for_secrets
    for mode in ("operator", "session", "none"):
        code = generate(_spec(mode))
        compile(code, "<gen>", "exec")
        assert not scan_for_secrets(code), f"{mode} wrapper embeds a credential"


def test_health_reports_the_mode_not_the_credential():
    from connectors.wrap import generate
    code = generate(_spec("session"))
    health = code[code.index("async def health"):]
    assert "credentialSource" in health
    assert "reveal()" not in health and "SECRET_REF" not in health


def test_gateway_forwards_but_does_not_log_the_credential():
    import pathlib
    gw = pathlib.Path(__file__).resolve().parent.parent / "core/gateway/xcp_gateway.py"
    src = gw.read_text()
    assert "H_UPSTREAM_CREDENTIAL" in src, "gateway must forward the caller's key"
    # it must never reach the audit log
    audit = src[src.index("def audit("):src.index("def _reject(")]
    assert "credential" not in audit.lower()


def test_credential_source_round_trips_through_the_summary():
    for mode in ("operator", "session", "none"):
        assert _spec(mode, auth="bearer" if mode != "none" else "none"
                     ).summary()["credentialSource"] in ("operator", "session", "none")


# ── sealed credentials: removing the gateway from the trust set ────────────

def _rk():
    from vault.sealed import generate_recipient_key
    return generate_recipient_key()


def test_seal_unseal_roundtrip():
    from vault.sealed import seal, unseal
    priv, pub = _rk()
    blob = seal("sk_live_secret", pub, context="tools/call:Charge")
    assert unseal(blob, priv, pub, context="tools/call:Charge") == "sk_live_secret"


def test_the_gateway_cannot_read_a_sealed_credential():
    """
    The property the whole mode exists for: whoever forwards the blob has no key
    for it. Without this, a hosted wrapper means the gateway operator holds every
    user's upstream credential.
    """
    from vault.sealed import seal, unseal, SealError
    _priv, pub = _rk()
    other_priv, _other_pub = _rk()          # the gateway's own key, if it had one
    blob = seal("sk_live_secret", pub, context="c")
    assert "sk_live_secret" not in blob
    try:
        unseal(blob, other_priv, pub, context="c")
        assert False, "a non-recipient must not be able to open it"
    except SealError:
        pass


def test_sealed_blob_is_bound_to_its_context():
    """A blob sealed for one operation cannot be replayed against another."""
    from vault.sealed import seal, unseal, SealError
    priv, pub = _rk()
    blob = seal("cred", pub, context="tools/call:GetAccount")
    try:
        unseal(blob, priv, pub, context="tools/call:DeleteAccount")
        assert False, "context must bind"
    except SealError:
        pass


def test_sealed_blob_is_bound_to_its_recipient():
    from vault.sealed import seal, unseal, SealError
    priv_a, pub_a = _rk()
    _priv_b, pub_b = _rk()
    blob = seal("cred", pub_a, context="c")
    try:
        unseal(blob, priv_a, pub_b, context="c")   # wrong recipient in the AAD
        assert False, "recipient must bind"
    except SealError:
        pass


def test_tampered_ciphertext_is_rejected():
    from vault.sealed import seal, unseal, SealError
    priv, pub = _rk()
    blob = seal("cred", pub, context="c")
    tampered = blob[:-6] + ("A" if blob[-6] != "A" else "B") + blob[-5:]
    try:
        unseal(tampered, priv, pub, context="c")
        assert False, "AEAD must reject tampering"
    except SealError:
        pass


def test_unseal_error_is_uninformative():
    """A padding/AAD oracle is a real attack; the error must not distinguish."""
    from vault.sealed import seal, unseal, SealError
    priv, pub = _rk()
    other_priv, _ = _rk()
    blob = seal("cred", pub, context="c")
    msgs = set()
    for bad in ((other_priv, pub, "c"), (priv, pub, "wrong")):
        try:
            unseal(blob, *bad)
        except SealError as e:
            msgs.add(str(e))
    assert len(msgs) == 1, f"error text leaks which check failed: {msgs}"


def test_refuses_to_seal_nothing():
    from vault.sealed import seal, SealError
    _priv, pub = _rk()
    try:
        seal("", pub); assert False
    except SealError:
        pass


def test_persisted_key_recovers_the_same_public_half():
    from vault.sealed import seal_public_from_private
    priv, pub = _rk()
    assert seal_public_from_private(priv).public_b64 == pub.public_b64


# ── the generator honours all three modes ──────────────────────────────────

def _wrapspec():
    from connectors.wrap import parse_openapi
    return parse_openapi({
        "openapi": "3.0.0", "info": {"title": "D", "version": "1"},
        "servers": [{"url": "https://api.d.example"}],
        "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
        "paths": {"/x": {"get": {"operationId": "getX"}}}}, api_id="d")


def test_all_credential_modes_generate_valid_servers():
    from connectors.wrap import generate
    from vault import scan_for_secrets
    for mode in ("operator", "session", "sealed"):
        code = generate(_wrapspec(), credential_source=mode)
        compile(code, "<gen>", "exec")
        assert not scan_for_secrets(code)
        assert f'CREDENTIAL_SOURCE = "{mode}"' in code


def test_unknown_credential_mode_is_refused():
    from connectors.wrap import generate, WrapError
    try:
        generate(_wrapspec(), credential_source="trust-me")
        assert False, "an unknown mode must not silently default"
    except WrapError:
        pass


def test_multi_tenant_modes_never_fall_back_to_the_operator_key():
    """
    Falling back would spend the host's money and assume the host's liability —
    the exact failure these modes exist to prevent.
    """
    from connectors.wrap import generate
    for mode in ("session", "sealed"):
        code = generate(_wrapspec(), credential_source=mode)
        body = code[code.index("def _credential("):]
        i = body.index(f'if CREDENTIAL_SOURCE == "{mode}":')
        j = body.index('if CREDENTIAL_SOURCE == "operator":')
        assert "_operator_credential()" not in body[i:j], mode


def test_caller_supplied_modes_require_a_verified_session():
    from connectors.wrap import generate
    for mode in ("session", "sealed"):
        code = generate(_wrapspec(), credential_source=mode)
        assert "only accepted on a gateway-verified" in code


def test_sealed_mode_publishes_a_key_endpoint():
    from connectors.wrap import generate
    assert "/xcp/credential-key" in generate(_wrapspec(), credential_source="sealed")


def test_sealed_mode_refuses_an_ephemeral_key_by_default():
    """
    Silently generating a new key on restart breaks every credential already
    sealed to the wrapper, with no error anyone can see. Fail closed instead.
    """
    from connectors.wrap import generate
    code = generate(_wrapspec(), credential_source="sealed")
    assert "XCP_SEAL_EPHEMERAL" in code
    assert "raise RuntimeError(" in code
    i = code.index("sealed mode needs a persistent key")
    assert "XCP_SEAL_PRIVATE" in code[i - 400:i + 400]


def test_sealed_mode_supports_key_rotation():
    """Rolling a key must not break requests already sealed to the old one."""
    from connectors.wrap import generate
    code = generate(_wrapspec(), credential_source="sealed")
    assert "XCP_SEAL_PREVIOUS" in code


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
