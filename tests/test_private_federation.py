"""
test_private_federation.py — several datacentres, one organisation.

WHAT THIS FILE IS ABOUT
-----------------------
A private federation was impossible to run under the production profile, and the
reason was a conflict between two controls rather than a missing feature:

  · the egress guard refused any host resolving to a private address unless
    XCP_ALLOW_INSECURE_PEERS=1, and that same flag also accepted plain-HTTP
    peering;
  · the production profile refuses to start with that flag set.

So an operator peering 10.40.0.0/16 across datacentres had to choose between a
profile they could not claim and a guard they had to disable wholesale. And even
with the guard off, peers carrying certificates from the organisation's own CA
failed chain validation, because both halves of peering used the ambient system
trust store -- failing before the certificate footprint binding was reached.

Two settings resolve it: XCP_PRIVATE_PEER_CIDRS (where peers live) and
XCP_PEER_CA_BUNDLE (who signs them). Most of what follows is about what they do
NOT permit, because that is where their value is: a declaration is only worth
having if it is narrower than switching the guard off.

NOTE ON ADDRESSES. Loopback can never be re-admitted by a declaration -- a peer
on 127.0.0.1 is this node, and a range that reached it could aim the gateway at
its own admin surface. So the address decision is tested at the resolver
boundary, which is where it happens in production anyway: an internal DNS name
resolves into a private range. The certificate half is tested over real TLS.

No pytest: every test file here runs standalone, which is what lets CI execute
them one at a time with only the dependencies each actually needs.

    python tests/test_private_federation.py
"""
from __future__ import annotations

import asyncio
import datetime
import importlib
import ipaddress
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from security.xcpsec import egress as eg                             # noqa: E402
from security.xcpsec.egress import (EgressConfigError, EgressDenied,  # noqa: E402
                                    EgressPolicy, address_permitted,
                                    check_url, parse_private_networks)

DC1 = "10.40.0.0/16"
DC2 = "fd00:dc2::/48"


def _policy(spec: str = f"{DC1},{DC2}", **kw) -> EgressPolicy:
    return EgressPolicy(private_networks=parse_private_networks(spec), **kw)


def _refuses(exc, fn, *a, **kw) -> str:
    """Assert `fn` raises `exc`; return the message for further assertions."""
    try:
        fn(*a, **kw)
    except exc as e:
        return str(e)
    raise AssertionError(f"{getattr(fn, '__name__', fn)} did not raise "
                         f"{exc.__name__}")


class _resolves_to:
    """
    Pin what a hostname resolves to, so the address decision can be tested
    without a private interface on the test machine. A context manager rather
    than a fixture, so this file needs no test runner.
    """

    def __init__(self, *addresses: str) -> None:
        self.addresses = sorted(addresses)

    def __enter__(self) -> None:
        self._real = eg.resolved_addresses
        eg.resolved_addresses = lambda host: list(self.addresses)

    def __exit__(self, *exc) -> None:
        eg.resolved_addresses = self._real


# ── where peers may live ───────────────────────────────────────────────────

def test_a_declared_range_permits_a_peer_on_a_private_address():
    with _resolves_to("10.40.7.21"):
        assert check_url("https://dc1-gw.internal.example", _policy())


def test_an_undeclared_private_range_is_still_refused():
    """The SSRF defence survives. This is the whole point of declaring."""
    with _resolves_to("10.99.7.21"):
        _refuses(EgressDenied, check_url,
                 "https://elsewhere.internal.example", _policy())


def test_a_host_resolving_both_inside_and_outside_is_refused():
    """
    Every address a name resolves to must pass. A name that answers with one
    declared address and one undeclared one is a DNS-rebinding shape, and the
    undeclared answer is the one an attacker arranged.
    """
    with _resolves_to("10.40.7.21", "10.99.7.21"):
        _refuses(EgressDenied, check_url,
                 "https://mixed.internal.example", _policy())


def test_a_declaration_cannot_re_admit_the_cloud_metadata_address():
    """
    169.254.169.254 sits inside several plausible declarations. If declaring a
    range could reach it, declaring would be no safer than switching the guard
    off -- which is the only reason this setting is allowed in production.
    """
    assert not address_permitted("169.254.169.254", _policy("169.254.0.0/16"))


def test_a_declaration_cannot_re_admit_loopback():
    """A peer on loopback is this node, including its own admin surface."""
    assert not address_permitted("127.0.0.1", _policy("127.0.0.0/8"))
    assert not address_permitted("::1", _policy("fc00::/7"))


def test_a_declaration_cannot_re_admit_carrier_grade_nat():
    assert not address_permitted("100.64.0.1", _policy("100.64.0.0/10"))


def test_a_public_address_needs_no_declaration():
    assert address_permitted("8.8.8.8", _policy())
    assert address_permitted("8.8.8.8", EgressPolicy())


def test_an_ipv6_declaration_works_independently_of_ipv4():
    with _resolves_to("fd00:dc2::7"):
        assert check_url("https://dc2-gw.internal.example", _policy())
    with _resolves_to("fd00:dc9::7"):
        _refuses(EgressDenied, check_url,
                 "https://dc9-gw.internal.example", _policy())


# ── what declaring does NOT buy ────────────────────────────────────────────

def test_a_private_federation_still_requires_tls():
    """
    Declaring a range says where peers are, not that the network between them
    can be trusted. An internal network is exactly where an attacker with a
    foothold is already positioned to read and rewrite traffic.
    """
    with _resolves_to("10.40.7.21"):
        msg = _refuses(EgressDenied, check_url,
                       "http://dc1-gw.internal.example", _policy())
    assert "TLS" in msg


def test_the_blanket_flag_and_the_declared_ranges_are_different_decisions():
    """
    They were one variable, which is why the production profile had to refuse
    the only setting a private federation could use.
    """
    declared = _policy()
    assert declared.permits_private and not declared.allow_private
    assert not declared.allow_http

    blanket = EgressPolicy(allow_private=True, allow_http=True)
    assert address_permitted("10.99.7.21", blanket), \
        "the blanket flag is still the development escape hatch"
    assert not address_permitted("10.99.7.21", declared)


def test_a_declaration_broader_than_the_floor_is_refused():
    """
    A /0 declaration is XCP_ALLOW_INSECURE_PEERS under a name the production
    profile does not check for. The floors admit 10.0.0.0/8 and fc00::/7, which
    are the broadest real private blocks.
    """
    for spec in ("0.0.0.0/0", "::/0", "10.0.0.0/7", "8.0.0.0/4"):
        _refuses(EgressConfigError, parse_private_networks, spec)


def test_the_broadest_legitimate_declarations_are_accepted():
    assert parse_private_networks("10.0.0.0/8")
    assert parse_private_networks("fc00::/7")


def test_a_malformed_declaration_stops_the_node_rather_than_narrowing_silently():
    """
    Dropping the bad entry and carrying on would leave the operator believing a
    range is declared when it is not, and the symptom appears later as a peer
    that cannot be reached for no visible reason.
    """
    for spec in ("not-a-cidr", "10.40.0.0/33", "10.40.0.0/16,garbage",
                 "999.1.1.1/16"):
        _refuses(EgressConfigError, parse_private_networks, spec)


def test_an_empty_declaration_is_not_an_error():
    assert parse_private_networks("") == ()
    assert parse_private_networks("  ,  ") == ()


def test_a_changed_declaration_takes_effect():
    """The parse is cached; the cache must be keyed on the value, not set once."""
    prior = os.environ.get("XCP_PRIVATE_PEER_CIDRS")
    try:
        os.environ["XCP_PRIVATE_PEER_CIDRS"] = DC1
        assert len(eg.private_networks_from_env()) == 1
        os.environ["XCP_PRIVATE_PEER_CIDRS"] = f"{DC1},{DC2}"
        assert len(eg.private_networks_from_env()) == 2
        del os.environ["XCP_PRIVATE_PEER_CIDRS"]
        assert eg.private_networks_from_env() == ()
    finally:
        os.environ.pop("XCP_PRIVATE_PEER_CIDRS", None)
        if prior is not None:
            os.environ["XCP_PRIVATE_PEER_CIDRS"] = prior


def test_the_refusal_does_not_describe_the_network():
    """
    An unauthenticated caller attempts peering, so the refusal must not become
    a map. It says this host is not permitted and nothing about which ranges
    are, or which address failed.
    """
    with _resolves_to("10.99.7.21"):
        msg = _refuses(EgressDenied, check_url,
                       "https://probe.internal.example", _policy())
    for leak in ("10.", "fd00", "/16", "169.254", "declared"):
        assert leak not in msg, f"the refusal leaked {leak!r}"


# ── the production profile ─────────────────────────────────────────────────

_PROD_ENV = dict(
    XCP_PROFILE="production", XCP_POSTURE="enforce",
    XCP_VERIFY_URL="http://127.0.0.1:8599", XCP_SECURITY="1",
    XCP_RATE_LIMIT="1", XCP_LIMIT_FAIL_OPEN="0",
    XCP_ADMIN_TOKEN="production-profile-test-token")


def _boots(**overrides) -> tuple[bool, str]:
    """
    Import the gateway in a fresh interpreter. Returns (started, output).

    A fresh process, not importlib.reload: the profile checks run at module
    scope and a reloaded module keeps the first interpreter's environment.
    `security/` goes on the path because the gateway imports `xcpsec` as a
    top-level package, which is how it is deployed.
    """
    env = {**os.environ, **_PROD_ENV, **overrides}
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "security")])
    r = subprocess.run(
        [sys.executable, "-c",
         "import core.gateway.xcp_gateway as g;"
         "print('STARTED', len(g.PRIVATE_PEER_CIDRS), g.PEER_TRUST['anchor'])"],
        capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))
    return "STARTED" in r.stdout, r.stdout + r.stderr


def test_the_production_profile_accepts_declared_ranges():
    """
    The blocker this file exists for. Before the split there was no value of
    the environment that gave a production node reachable private peers.
    """
    started, out = _boots(XCP_PRIVATE_PEER_CIDRS=f"{DC1},{DC2}")
    assert started, f"production refused to start with declared ranges:\n{out}"
    assert "STARTED 2" in out, f"the ranges were not loaded:\n{out}"


def test_the_production_profile_still_refuses_the_blanket_flag():
    started, out = _boots(XCP_ALLOW_INSECURE_PEERS="1")
    assert not started, "production started with the blanket flag set"
    assert "XCP_ALLOW_INSECURE_PEERS" in out


def test_the_refusal_points_at_the_setting_that_does_work():
    """
    A refusal with no route forward is what pushed operators to run the
    development profile in production.
    """
    _, out = _boots(XCP_ALLOW_INSECURE_PEERS="1")
    assert "XCP_PRIVATE_PEER_CIDRS" in out


def test_a_malformed_declaration_stops_the_gateway():
    started, out = _boots(XCP_PRIVATE_PEER_CIDRS="10.40.0.0/16,nonsense")
    assert not started, "the gateway started with a declaration it could not parse"
    assert "XCP_PRIVATE_PEER_CIDRS" in out


def test_a_bypass_width_declaration_stops_the_gateway():
    started, _ = _boots(XCP_PRIVATE_PEER_CIDRS="0.0.0.0/0")
    assert not started, "a /0 declaration is the blanket flag by another name"


def test_a_bad_bundle_stops_the_gateway():
    tmp = tempfile.mkdtemp()
    try:
        started, out = _boots(XCP_PEER_CA_BUNDLE=str(Path(tmp) / "nope.pem"))
        assert not started, "the gateway started with an unusable trust anchor"
        assert "XCP_PEER_CA_BUNDLE" in out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── who signs the peers ────────────────────────────────────────────────────

def _issue_internal_ca(tmp: Path, san_ip: str = "127.0.0.1",
                       common_name: str = "dc1-gw.internal.example"
                       ) -> tuple[Path, Path, Path]:
    """An internal CA and a leaf certificate, as an enterprise PKI would issue
    them. Returns (ca_bundle, leaf_cert, leaf_key)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Example Corp Internal Root")])
    # The key identifiers are not decoration: OpenSSL's default verification
    # refuses a chain without them ("Missing Authority Key Identifier"), so a
    # CA built without them fails for a reason unrelated to what is being
    # tested -- and would look like the bundle not working.
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca = (x509.CertificateBuilder()
          .subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                         critical=True)
          .add_extension(ca_ski, critical=False)
          .add_extension(x509.KeyUsage(
              digital_signature=True, key_cert_sign=True, crl_sign=True,
              content_commitment=False, key_encipherment=False,
              data_encipherment=False, key_agreement=False,
              encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=29))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(san_ip)),
                 x509.DNSName("dc1-gw.internal.example")]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier
                           .from_issuer_subject_key_identifier(ca_ski),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))

    bundle = tmp / "internal-ca.pem"
    bundle.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_p = tmp / "leaf.pem"
    cert_p.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_p = tmp / "leaf.key"
    key_p.write_bytes(leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    return bundle, cert_p, key_p


class _Record(BaseHTTPRequestHandler):
    def do_GET(self):                           # noqa: N802 - stdlib interface
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"domain":"dc1-gw.internal.example"}')

    def log_message(self, *a):                  # keep the output clean
        pass


class _internal_tls:
    """An HTTPS server whose certificate only an internal CA can verify."""

    def __enter__(self) -> tuple[str, str]:
        self.tmp = Path(tempfile.mkdtemp())
        bundle, cert_p, key_p = _issue_internal_ca(self.tmp)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Record)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return f"https://127.0.0.1:{self.srv.server_address[1]}", str(bundle)

    def __exit__(self, *exc) -> None:
        self.srv.shutdown()
        shutil.rmtree(self.tmp, ignore_errors=True)


def test_an_internal_ca_can_verify_a_peer_certificate():
    """
    The second blocker. The footprint binding in verify_node_record() is a
    pinning construction and does not care who signed, but chain validation ran
    first and ran against the public trust store -- so an internal CA failed
    before pinning was reached.
    """
    from federation.peerfetch import peer_certificate_der
    with _internal_tls() as (url, bundle):
        der = asyncio.run(peer_certificate_der(url, bundle=bundle))
    assert der and isinstance(der, bytes)


def test_the_same_certificate_fails_against_the_public_trust_store():
    """The control for the test above: without the bundle this is unverifiable,
    which is exactly the state a private federation was stuck in."""
    from federation.peerfetch import peer_certificate_der
    with _internal_tls() as (url, _):
        _refuses(Exception, asyncio.run,
                 peer_certificate_der(url, bundle=""))


def test_the_bundle_replaces_rather_than_augments_the_public_roots():
    """
    Augmenting would have been the softer default and the wrong one: setting
    the variable is a statement about who signs your peers, and leaving the
    public roots trusted contradicts it -- a mis-issuance for an internal name
    would be accepted on a FIRST peering, the one moment pinning cannot help.
    """
    from federation.peerfetch import peer_ssl_context
    with _internal_tls() as (_, bundle):
        declared = peer_ssl_context(bundle=bundle)
        system = peer_ssl_context(bundle="")
        assert len(declared.get_ca_certs()) == 1
        assert len(system.get_ca_certs()) > 1, \
            "the control is meaningless if the system store is empty here"


def test_the_record_fetch_uses_the_declared_anchor():
    """Both halves of peering, not just the certificate retrieval."""
    from federation.peerfetch import fetch_node_record
    with _internal_tls() as (url, bundle):
        got = asyncio.run(fetch_node_record(url, bundle=bundle))
    assert got.ok and got.tls


def test_an_oversized_record_is_refused():
    from federation import peerfetch
    orig = peerfetch.MAX_RECORD_BYTES
    peerfetch.MAX_RECORD_BYTES = 4
    try:
        with _internal_tls() as (url, bundle):
            _refuses(peerfetch.PeerFetchError, asyncio.run,
                     peerfetch.fetch_node_record(url, bundle=bundle))
    finally:
        peerfetch.MAX_RECORD_BYTES = orig


def test_the_peer_anchor_does_not_change_upstream_tool_trust():
    """
    Scoping. A peer is an internal party whose signer the operator declares; an
    upstream API is a public party whose signer they do not. Narrowing the
    store for peers must not narrow it for tool calls, or declaring an internal
    CA would break every external tool the organisation reaches.
    """
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("def _upstream_client(")
    j = src.find("\n\n\n", i)
    for leak in ("XCP_PEER_CA_BUNDLE", "peer_verify", "peer_ssl_context"):
        assert leak not in src[i:j], \
            f"the upstream client reads {leak}; peer trust must not scope it"


def _with_bundle(path: str, fn):
    prior = os.environ.get("XCP_PEER_CA_BUNDLE")
    os.environ["XCP_PEER_CA_BUNDLE"] = path
    try:
        return fn()
    finally:
        os.environ.pop("XCP_PEER_CA_BUNDLE", None)
        if prior is not None:
            os.environ["XCP_PEER_CA_BUNDLE"] = prior


def test_an_unreadable_bundle_stops_the_node_starting():
    """
    Falling back to the public store is the failure this refuses: the operator
    believes peers are verified against their own CA while every public root is
    trusted.
    """
    from federation.peerfetch import PeerTrustConfigError, validate_config
    tmp = Path(tempfile.mkdtemp())
    try:
        _with_bundle(str(tmp / "nope.pem"),
                     lambda: _refuses(PeerTrustConfigError, validate_config))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_bundle_with_no_authorities_stops_the_node_starting():
    from federation.peerfetch import PeerTrustConfigError, validate_config
    tmp = Path(tempfile.mkdtemp())
    try:
        empty = tmp / "empty.pem"
        empty.write_text("# no certificates here\n")
        _with_bundle(str(empty),
                     lambda: _refuses(PeerTrustConfigError, validate_config))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_the_unset_bundle_is_not_an_error():
    from federation.peerfetch import trust_summary, validate_config
    prior = os.environ.pop("XCP_PEER_CA_BUNDLE", None)
    try:
        validate_config()
        assert trust_summary()["anchor"] == "system"
    finally:
        if prior is not None:
            os.environ["XCP_PEER_CA_BUNDLE"] = prior


def test_chain_validation_is_not_replaced_by_the_footprint_binding():
    """
    The two checks are layered, not alternatives. peer_ssl_context must leave
    hostname checking and verification on; the footprint proves the record and
    the certificate belong together, not that the certificate is legitimate.
    """
    from federation.peerfetch import peer_ssl_context
    ctx = peer_ssl_context(bundle="")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_the_record_size_cap_agrees_with_the_egress_guard():
    """Duplicated constant; the two must not drift apart."""
    from federation.peerfetch import MAX_RECORD_BYTES
    from security.xcpsec.egress import MAX_FETCH_BYTES
    assert MAX_RECORD_BYTES == MAX_FETCH_BYTES


# ── the posture is observable ──────────────────────────────────────────────

def _triage_findings(health: dict) -> dict[str, str]:
    """Run triage against a stubbed node and index its findings by check."""
    # import_module, not `from ops import triage`: ops/__init__.py re-exports
    # the FUNCTION under that name, so the plain import binds a callable with
    # no _get to stub.
    t = importlib.import_module("ops.triage")
    base = {"ok": True, "posture": "enforce", "protocolVersions": ["1"],
            "rateLimit": {"tiers": 1}, "upstreams": ["research"],
            "cryptoFastPath": True, **health}
    routes = {"/health": base, "/v1/federation/peers": {"summary": {}},
              "/.well-known/xcp-node.json": {"bindings": {"current": {}}}}

    def fake_get(url, timeout=6):
        for path, payload in routes.items():
            if url.endswith(path):
                return 200, payload
        return 404, {}

    real, t._get = t._get, fake_get
    try:
        return {f.check: f"{f.sev.name}: {f.detail} {f.action}"
                for f in t.triage("http://node.test")}
    finally:
        t._get = real


def test_triage_flags_ranges_declared_without_an_internal_anchor():
    """
    The posture most often got half-right: peers reachable and unverifiable.
    Chain validation then fails at the certificate binding, which reads as a
    peer problem rather than a missing setting on this node.
    """
    f = _triage_findings({"privateFederation": {"declaredRanges": 2,
                                                "peerTrustAnchor": "system"}})
    assert "private federation" in f
    assert f["private federation"].startswith("MEDIUM")
    assert "XCP_PEER_CA_BUNDLE" in f["private federation"]


def test_triage_flags_an_anchor_with_nowhere_to_use_it():
    f = _triage_findings({"privateFederation": {"declaredRanges": 0,
                                                "peerTrustAnchor": "declared"}})
    assert f["private federation"].startswith("MEDIUM")
    assert "XCP_PRIVATE_PEER_CIDRS" in f["private federation"]


def test_triage_is_quiet_when_the_posture_is_coherent():
    f = _triage_findings({"privateFederation": {"declaredRanges": 3,
                                                "peerTrustAnchor": "declared"}})
    assert f["private federation"].startswith("OK")


def test_triage_says_nothing_about_a_public_node():
    """A node with no private federation configured must not be nagged."""
    f = _triage_findings({"privateFederation": {"declaredRanges": 0,
                                                "peerTrustAnchor": "system"}})
    assert "private federation" not in f


def test_the_node_reports_what_it_will_accept_as_a_peer():
    """
    An operator should be able to confirm the posture rather than infer it from
    whether peering happens to work.
    """
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    assert '"privateFederation"' in src, "/health must report the posture"
    assert '@app.get("/v1/federation/trust")' in src


def test_the_declared_ranges_are_not_published_unauthenticated():
    """
    Which internal ranges hold gateways is a map of the organisation -- the
    reconnaissance step. /health publishes counts; the ranges need the admin
    token, consistent with how the peer list is handled.
    """
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("async def federation_trust(")
    j = src.find("@app.", i)
    body = src[i:j if j > 0 else len(src)]
    assert "_admin_ok(request)" in body
    assert body.index("_admin_ok(request)") < body.index('declaredRanges": [str(n)'), \
        "the ranges are serialised before the admin check"


# ── end to end: a real gateway peering with a real private peer ────────────
# Everything above tests a part. This section runs the whole path: a production
# -profile gateway reaching a peer on a private address whose certificate only
# an internal CA can verify.
#
# It is here because of a defect class this project has hit four times -- a
# correct, tested library that no running code could reach. Peer fetching was
# just refactored into federation/peerfetch.py, and a wiring mistake there
# leaves every test above passing while peering is broken.

PEER_IP = "10.40.1.5"             # inside the declared range, bound via IP_FREEBIND
PEER_KEY = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
GW_KEY = "0x6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1"
_IP_FREEBIND = 15                  # IP_FREEBIND; absent from the socket module

_ROUTABLE: Optional[bool] = None


def _skip(reason: str) -> None:
    """Skip, in whichever runner is driving."""
    if "pytest" in sys.modules:
        import pytest
        pytest.skip(reason)
    raise _Skipped(reason)


class _Skipped(Exception):
    """Standalone-runner skip. Reported as a skip, not a pass or a failure."""


def _private_address_is_routable() -> bool:
    """
    Whether this host can actually REACH PEER_IP.

    IP_FREEBIND lets a test bind an address the host does not own, but nothing
    routes to it unless an interface is configured for the range -- so on an
    ordinary CI container a connection to it times out. The cases that need a
    connection are skipped there rather than deleted, because they do run
    wherever an internal interface exists, which is every deployment this
    feature is for. The cases that assert a REFUSAL need no connection: the
    egress guard decides before one is attempted, so those run everywhere.
    """
    global _ROUTABLE
    if _ROUTABLE is None:
        import socket
        srv = socket.socket()
        try:
            srv.setsockopt(socket.SOL_IP, _IP_FREEBIND, 1)
            srv.bind((PEER_IP, 0))
            srv.listen(1)
            c = socket.socket()
            c.settimeout(2)
            try:
                c.connect((PEER_IP, srv.getsockname()[1]))
                _ROUTABLE = True
            except OSError:
                _ROUTABLE = False
            finally:
                c.close()
        except OSError:
            _ROUTABLE = False
        finally:
            srv.close()
    return _ROUTABLE


class _FreebindServer(ThreadingHTTPServer):
    """
    Bind an address this host does not own.

    A private federation cannot be exercised on loopback: loopback is refused
    by _never_permitted no matter what is declared, which is deliberate. So the
    peer has to answer on a genuinely private address, and IP_FREEBIND is how a
    test host serves one without an interface configured for it.
    """

    def server_bind(self) -> None:
        try:
            self.socket.setsockopt(__import__("socket").SOL_IP, _IP_FREEBIND, 1)
        except OSError:
            pass
        super().server_bind()


def _peer_record(bundle_dir: Path, cert_pem: bytes) -> bytes:
    """A node record for PEER_IP, with a signed binding to its certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from federation import NodeIdentity, NodeRecord, digest, rotate

    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(Encoding.DER)
    fp = digest(der)
    ident = NodeIdentity.from_key(PEER_KEY)
    bs = rotate(ident, fp, domain=PEER_IP)
    rec = NodeRecord(domain=PEER_IP, node_id=ident.node_id,
                     gateway_url=f"https://{PEER_IP}",
                     operator="Example Corp DC1",
                     bindings=bs.to_dict(), cert_footprint=fp)
    problems = rec.validate()
    assert not problems, f"the test's own record is invalid: {problems}"
    return rec.to_json().encode()


class _private_peer:
    """A peer on a private address, served over an internally-signed certificate."""

    def __enter__(self) -> tuple[str, str]:
        self.tmp = Path(tempfile.mkdtemp())
        bundle, cert_p, key_p = _issue_internal_ca(self.tmp, san_ip=PEER_IP,
                                                   common_name=PEER_IP)
        body = _peer_record(self.tmp, cert_p.read_bytes())

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):               # noqa: N802 - stdlib interface
                if not self.path.endswith("/.well-known/xcp-node.json"):
                    self.send_response(404); self.end_headers(); return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
        self.srv = _FreebindServer((PEER_IP, 0), Handler)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return f"https://{PEER_IP}:{self.srv.server_address[1]}", str(bundle)

    def __exit__(self, *exc) -> None:
        self.srv.shutdown()
        shutil.rmtree(self.tmp, ignore_errors=True)


class _gateway:
    """A real gateway in the production profile, with the private-federation
    settings under test."""

    def __init__(self, **env) -> None:
        self.extra = env

    def __enter__(self):
        import urllib.request
        self.port = 8731
        env = {**os.environ, **_PROD_ENV, **self.extra}
        env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "security")])
        env.update(XCP_NODE_KEY=GW_KEY, XCP_NODE_DOMAIN="dc0-gw.internal.example",
                   XCP_NODE_URL="https://dc0-gw.internal.example",
                   XCP_GLOBAL_RATE="500000")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "core.gateway.xcp_gateway:app",
             "--host", "127.0.0.1", "--port", str(self.port), "--log-level",
             "error"],
            env=env, cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True)
        for _ in range(100):
            if self.proc.poll() is not None:
                raise AssertionError("gateway exited:\n"
                                     + (self.proc.stdout.read() or "")[:1500])
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/health", timeout=2)
                return self
            except Exception:
                __import__("time").sleep(0.2)
        raise AssertionError("gateway did not come up")

    def peer(self, domain: str, gateway_url: str) -> tuple[int, dict]:
        import json as _json
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/federation/peer",
            data=_json.dumps({"domain": domain,
                              "gatewayUrl": gateway_url}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, _json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, _json.loads(e.read() or b"{}")

    def __exit__(self, *exc) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def test_a_production_node_peers_with_a_private_peer_over_an_internal_ca():
    """
    The composition. Neither setting is sufficient alone: the range makes the
    peer reachable, the bundle makes its certificate verifiable, and the
    footprint binding still has to hold on top of both.
    """
    if not _private_address_is_routable():
        _skip(f"nothing on this host routes to {PEER_IP}")
    with _private_peer() as (url, bundle):
        with _gateway(XCP_PRIVATE_PEER_CIDRS="10.40.0.0/16",
                      XCP_PEER_CA_BUNDLE=bundle) as gw:
            status, res = gw.peer(PEER_IP, url)
    assert status == 200, f"peering failed: {status} {res}"
    assert res.get("peered") is True, res
    assert res.get("tlsVerified") is True, \
        f"the certificate binding did not hold: {res}"
    assert res.get("trust") == "verified", res
    assert res.get("mutual") is False, \
        "this path must still grant at most VERIFIED"


def test_without_the_declared_range_the_same_peer_is_unreachable():
    """
    The negative that shows XCP_PRIVATE_PEER_CIDRS is load-bearing, and the
    state a private federation was stuck in before it existed.
    """
    with _private_peer() as (url, bundle):
        with _gateway(XCP_PEER_CA_BUNDLE=bundle) as gw:
            status, res = gw.peer(PEER_IP, url)
    assert status == 400, f"expected a refusal, got {status} {res}"
    assert "permitted address" in str(res), res


def test_without_the_internal_anchor_the_same_peer_cannot_be_verified():
    """
    The negative that shows XCP_PEER_CA_BUNDLE is load-bearing: reachable and
    unverifiable, which is the half-configured posture triage warns about.
    """
    if not _private_address_is_routable():
        _skip(f"nothing on this host routes to {PEER_IP}")
    with _private_peer() as (url, _):
        with _gateway(XCP_PRIVATE_PEER_CIDRS="10.40.0.0/16") as gw:
            status, res = gw.peer(PEER_IP, url)
    assert status == 502, f"expected a verification failure, got {status} {res}"
    assert "certificate" in str(res).lower(), res


class _loopback_peer:
    """
    The same peer, on loopback.

    This exists because the case above is skipped wherever nothing routes to a
    private address, and that would leave the NEW WIRING -- the record fetch
    and the certificate retrieval, both of which just moved into
    federation/peerfetch.py -- unexercised through the real handler. The
    refusal cases prove the egress decision reaches the handler; this proves
    the fetch does, over an internal CA.

    It needs XCP_ALLOW_INSECURE_PEERS to reach loopback, so it runs in the
    development profile. That is the trade: the production profile is covered
    by the case above where the network allows it, and the wiring is covered
    here everywhere.
    """

    def __enter__(self) -> tuple[str, str]:
        self.tmp = Path(tempfile.mkdtemp())
        bundle, cert_p, key_p = _issue_internal_ca(
            self.tmp, san_ip="127.0.0.1", common_name="127.0.0.1")
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        from federation import NodeIdentity, NodeRecord, digest, rotate
        der = x509.load_pem_x509_certificate(
            cert_p.read_bytes()).public_bytes(Encoding.DER)
        fp = digest(der)
        ident = NodeIdentity.from_key(PEER_KEY)
        rec = NodeRecord(domain="127.0.0.1", node_id=ident.node_id,
                         gateway_url="https://127.0.0.1",
                         operator="Example Corp DC1",
                         bindings=rotate(ident, fp, domain="127.0.0.1").to_dict(),
                         cert_footprint=fp)
        assert not rec.validate(), rec.validate()
        body = rec.to_json().encode()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):               # noqa: N802 - stdlib interface
                if not self.path.endswith("/.well-known/xcp-node.json"):
                    self.send_response(404); self.end_headers(); return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return f"https://127.0.0.1:{self.srv.server_address[1]}", str(bundle)

    def __exit__(self, *exc) -> None:
        self.srv.shutdown()
        shutil.rmtree(self.tmp, ignore_errors=True)


def test_the_gateway_fetches_and_binds_a_record_through_an_internal_ca():
    """
    The new wiring, through the real handler: fetch the record over a chain
    only the internal CA can verify, retrieve the certificate, and bind the
    record to it. Before XCP_PEER_CA_BUNDLE, this returned 502 at the fetch.
    """
    with _loopback_peer() as (url, bundle):
        with _gateway(XCP_PROFILE="development", XCP_VERIFY_URL="",
                      XCP_ALLOW_INSECURE_PEERS="1",
                      XCP_PEER_CA_BUNDLE=bundle) as gw:
            status, res = gw.peer("127.0.0.1", url)
    assert status == 200, f"peering failed: {status} {res}"
    assert res.get("peered") is True, res
    assert res.get("tlsVerified") is True, \
        f"the record was not bound to its certificate: {res}"
    assert res.get("trust") == "verified", res


def test_the_gateway_cannot_fetch_the_same_record_without_the_anchor():
    """
    The control. Without the bundle the chain does not verify and the fetch
    fails -- the exact state a private federation with an internal CA was in.
    """
    with _loopback_peer() as (url, _):
        with _gateway(XCP_PROFILE="development", XCP_VERIFY_URL="",
                      XCP_ALLOW_INSECURE_PEERS="1") as gw:
            status, res = gw.peer("127.0.0.1", url)
    assert status == 502, f"expected the fetch to fail, got {status} {res}"


def test_a_peer_outside_the_declared_range_is_refused_while_another_is_allowed():
    """
    A declaration is a scope, not a switch: declaring one datacentre must not
    admit an address in another undeclared private range.
    """
    with _private_peer() as (url, bundle):
        with _gateway(XCP_PRIVATE_PEER_CIDRS="10.41.0.0/16",
                      XCP_PEER_CA_BUNDLE=bundle) as gw:
            status, res = gw.peer(PEER_IP, url)
    assert status == 400, f"10.40.x was reached under a 10.41.x declaration: {res}"
    assert "permitted address" in str(res), res


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = skipped = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except _Skipped as e:
            print(f"  skip {name}: {e}"); skipped += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:140]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
