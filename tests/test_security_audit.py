"""
test_security_audit.py — the findings from the audit, pinned shut.

Six issues were found by auditing the published tree. Each has a test here that
reproduces the attack and asserts it now fails. Written as attacks rather than
as assertions about code, because a test that checks for the presence of a
mitigation passes even when the mitigation is bypassable.

    python tests/test_security_audit.py
"""
from __future__ import annotations

import json, multiprocessing, os, sys, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PORT = 9810
ADMIN = "audit-token-not-a-real-secret"
NODE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


def _run():
    os.environ.update(
        XCP_POSTURE="enforce", XCP_RATE_LIMIT="1", XCP_GLOBAL_RATE="500000",
        XCP_ADMIN_TOKEN=ADMIN, XCP_NODE_KEY=NODE_KEY,
        XCP_NODE_DOMAIN="audit.test", XCP_NODE_URL=f"http://127.0.0.1:{PORT}")
    sys.path.insert(0, str(ROOT))
    import uvicorn
    from core.gateway.xcp_gateway import app
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="error")


_UP = False


def _boot():
    global _UP
    if _UP:
        return
    try:
        multiprocessing.set_start_method("spawn", force=True)
    except RuntimeError:
        pass
    multiprocessing.Process(target=_run, daemon=True).start()
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=2)
            break
        except Exception:
            time.sleep(0.4)
    _UP = True


def _call(path, body=None, headers=None, method=None):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method or ("POST" if data else "GET"),
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


# ── XCP-A-01 (critical): unauthenticated kill switch ───────────────────────

def test_anyone_could_revoke_any_session():
    """One unauthenticated request took down any agent on the node."""
    _boot()
    st, _ = _call("/admin/revoke", {"footprint": "0x" + "ab" * 32})
    assert st == 401, f"admin endpoint answered {st} without a token"


def test_admin_rejects_a_wrong_token():
    _boot()
    st, _ = _call("/admin/revoke", {"footprint": "0x" + "ab" * 32},
                  {"Authorization": "Bearer wrong"})
    assert st == 401


def test_admin_accepts_the_right_token():
    _boot()
    st, _ = _call("/admin/revoke", {"footprint": "0x" + "ab" * 32},
                  {"Authorization": f"Bearer {ADMIN}"})
    assert st == 200


def test_admin_comparison_is_constant_time():
    """A short-circuiting compare leaks the token a character at a time."""
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    assert "compare_digest" in src
    assert "presented == _ADMIN_TOKEN" not in src


def test_admin_is_disabled_when_no_token_is_configured():
    """An admin surface that defaults to open is worse than none."""
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("def _admin_ok(")
    assert "if not _ADMIN_TOKEN:" in src[i:i + 400]
    assert "return False" in src[i:i + 400]


# ── XCP-A-02 (critical): revocation by assertion ───────────────────────────

def test_naming_a_peer_does_not_authorise_revoking_on_its_behalf():
    """
    The endpoint took the originating domain from the body. With the peer list
    public, anyone could name a real peer and revoke any node.
    """
    _boot()
    st, res = _call("/v1/federation/revoke",
                    {"nodeId": "0x" + "ee" * 32, "from": "some-peer.test"})
    assert st in (400, 403, 429), f"a bare claim was accepted with {st}"
    assert res.get("accepted") is not True


def test_an_unsigned_revocation_is_refused():
    _boot()
    st, res = _call("/v1/federation/revoke",
                    {"from": "some-peer.test",
                     "revocation": {"subject": "0x" + "ee" * 32,
                                    "issuer": "0x" + "cc" * 32,
                                    "issuedAt": int(time.time())}})
    assert st in (400, 403, 429) and res.get("accepted") is not True


def test_a_revocation_signed_by_the_wrong_key_is_refused():
    from federation import NodeIdentity, sign_revocation, verify_revocation
    attacker, victim_peer = NodeIdentity.generate(), NodeIdentity.generate()
    doc = sign_revocation(attacker, "0x" + "ee" * 32)
    problems = verify_revocation(doc, victim_peer.node_id)
    assert problems, "a revocation signed by a stranger must not verify"


def test_an_old_revocation_cannot_be_replayed():
    from federation import NodeIdentity, sign_revocation, verify_revocation
    peer = NodeIdentity.generate()
    old = sign_revocation(peer, "0x" + "ee" * 32, now=int(time.time()) - 86400)
    assert any("stale" in p for p in verify_revocation(old, peer.node_id))


# ── XCP-A-03 (high): server-side request forgery ───────────────────────────

def test_cloud_metadata_cannot_be_reached_through_the_peer_endpoint():
    """The classic SSRF target. The gateway sits where the attacker cannot."""
    _boot()
    st, res = _call("/v1/federation/peer",
                    {"domain": "x.test",
                     "gatewayUrl": "http://169.254.169.254/latest/meta-data/"})
    # 400 (egress refused) and 429 (metered) are both refusals; what must never
    # happen is success. The precise reason is asserted at unit level below,
    # so accepting either here does not weaken the check.
    assert st in (400, 403, 429), f"metadata endpoint was reachable ({st})"
    assert st != 200


def test_private_ranges_and_loopback_are_refused():
    from security.xcpsec.egress import check_url, EgressDenied, EgressPolicy
    strict = EgressPolicy(allow_http=True, allow_private=False)
    for url in ("http://127.0.0.1:8080/", "http://10.0.0.5/", "http://[::1]/",
                "http://192.168.1.1/", "http://169.254.169.254/"):
        try:
            check_url(url, strict)
            assert False, f"{url} was permitted"
        except EgressDenied:
            pass


def test_filtering_happens_on_the_resolved_address_not_the_string():
    """A hostname an attacker controls can resolve anywhere they like."""
    from security.xcpsec.egress import check_url, EgressDenied, EgressPolicy
    strict = EgressPolicy(allow_http=True, allow_private=False)
    try:
        check_url("http://localhost.localdomain/", strict)
    except EgressDenied:
        pass                      # resolved to loopback, or did not resolve
    src = (ROOT / "security" / "xcpsec" / "egress.py").read_text()
    assert "getaddrinfo" in src, "must resolve, not pattern-match"


def test_redirects_are_not_followed_into_a_private_range():
    """
    An open redirector on a permitted host would otherwise reach somewhere the
    egress guard never checked.

    Asserted on behaviour rather than on the source text. This test used to
    grep a fixed 2600-character window of the handler for `follow_redirects`,
    which broke the moment peer fetching moved into federation.peerfetch --
    and a fixed window had already masked a real gap once before in this file.
    """
    import asyncio
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from federation.peerfetch import fetch_node_record

    class Redirector(BaseHTTPRequestHandler):
        def do_GET(self):                       # noqa: N802 - stdlib interface
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data")
            self.end_headers()

        def log_message(self, *a):              # keep the test output clean
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        got = asyncio.run(fetch_node_record(f"http://127.0.0.1:{port}"))
        # The redirect is returned to the caller, not followed. The gateway
        # turns any status >= 300 into "must be served directly".
        assert got.status == 302, \
            "the redirect was followed; an open redirector defeats the guard"
        assert b"meta-data" not in got.body
    finally:
        srv.shutdown()


def test_the_peer_fetcher_is_the_only_federation_http_client():
    """
    The companion to the test above. Behaviour tests cover federation.peerfetch;
    this one stops the handler growing a second, unguarded client beside it --
    which is how the first one came to have TLS verification disabled.
    """
    body = _federation_peer_body()
    assert "fetch_node_record(" in body, \
        "peer records must be fetched through federation.peerfetch"
    for direct in ("httpx.AsyncClient(", "httpx.Client(", "urlopen("):
        assert direct not in body, \
            f"the handler builds its own HTTP client ({direct}), bypassing the " \
            "redirect, size and trust-anchor handling in federation.peerfetch"


def test_whitespace_around_the_identity_value_is_not_part_of_the_value():
    """
    FOUND BY DIFFERENTIAL ANALYSIS. "42001;8453;0xab…ab " answered 401 here and
    403 on the Node implementation, and the disagreement was in neither parser
    -- both are strict. Node's HTTP server strips OWS before the application
    sees it, as [RFC9110] 5.5 says a recipient should; uvicorn passes it
    through, so this gateway compared a footprint with a trailing space against
    the one it had registered and reported an unverified session.

    Refusing OWS instead was not available: a parser that never receives the
    whitespace cannot refuse it, so the two implementations could not have
    converged on refusal. What is asserted here is that surrounding whitespace
    makes no difference to the outcome.
    """
    _boot()
    fp = "0x" + "ab" * 32
    _call("/v1/session/open", {"agentId": 42001, "chainId": 8453,
                               "footprint": fp, "tier": "A0xH0"})
    clean = _call("/v1/a2t/call", {},
                  {"XCP-Agent-Identity": f"42001;8453;{fp}"})[0]
    for pad in (f"42001;8453;{fp} ", f" 42001;8453;{fp}",
                f"  42001;8453;{fp}  "):
        got = _call("/v1/a2t/call", {}, {"XCP-Agent-Identity": pad})[0]
        assert got == clean, \
            (f"padding the identity value changed the outcome: {pad!r} gave "
             f"{got}, the same value unpadded gave {clean}")


def test_whitespace_INSIDE_the_identity_is_still_refused():
    """
    The control. Only whitespace around the field value is OWS; a space inside
    a field is part of that field and must not be tolerated, or "42001 " and
    "42001" become the same agent to one parser and not another.
    """
    _boot()
    fp = "0x" + "ab" * 32
    for bad in (f"42001 ;8453;{fp}", f"42001; 8453;{fp}",
                f"42001;8453 ;{fp}"):
        status, res = _call("/v1/a2t/call", {},
                            {"XCP-Agent-Identity": bad})
        # 401 is the identity refusal. 429 also appears, because an unverified
        # caller is metered on the austere anonymous bucket and these probes
        # are precisely the traffic it exists to throttle -- a refusal either
        # way. What must never happen is the call proceeding.
        assert status in (401, 429), \
            f"{bad!r} was not refused: {status} {res}"
        assert status != 200


def test_the_fetch_error_is_not_an_oracle():
    """Echoing the error turned a blind SSRF into an information leak."""
    _boot()
    st, res = _call("/v1/federation/peer",
                    {"domain": "x.test", "gatewayUrl": "https://no-such-host.invalid"})
    blob = json.dumps(res).lower()
    for leak in ("connection refused", "timed out", "getaddrinfo", "traceback",
                 "errno"):
        assert leak not in blob, f"error leaked detail: {leak}"


def test_credentials_in_a_url_are_refused():
    from security.xcpsec.egress import check_url, EgressDenied
    try:
        check_url("https://user:pw@example.com/")
        assert False
    except EgressDenied:
        pass


# ── XCP-A-04 (high): TLS verification was disabled ─────────────────────────

def test_tls_verification_is_not_disabled_anywhere_in_the_gateway():
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    assert "verify=False" not in src, \
        "peering is where trust is established; it cannot skip certificate checks"


# ── XCP-A-05 (medium): topology disclosure ─────────────────────────────────

def test_the_peer_list_requires_an_admin_token():
    _boot()
    st, res = _call("/v1/federation/peers")
    assert st == 200
    assert res.get("peers") == "redacted; requires an admin token"
    st2, res2 = _call("/v1/federation/peers", None,
                      {"Authorization": f"Bearer {ADMIN}"})
    assert isinstance(res2.get("peers"), list)


# ── XCP-A-06 (medium): unmetered endpoints ─────────────────────────────────

def test_every_mutating_endpoint_is_metered():
    import re
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    for m, path, fn in re.findall(r'@app\.(get|post)\("([^"]+)"\)\s*\nasync def (\w+)', src):
        if m != "post":
            continue
        i = src.index(f"async def {fn}(")
        j = src.find("@app.", i)
        body = src[i:j if j > 0 else len(src)]
        assert "_limit(" in body or "_LIMITS.check" in body, \
            f"{path} accepts writes without metering"


# ── independent review findings (GPT-5.6) ──────────────────────────────────

def _federation_peer_body() -> str:
    """The whole handler, sliced to the next route rather than a fixed window."""
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("async def federation_peer(")
    j = src.find("@app.", i)
    return src[i:j if j > 0 else len(src)]



def test_peer_enrolment_binds_the_record_to_a_certificate():
    """
    XCP-B-01 (high). The library had verify_node_record(), which binds a record
    to the certificate the peer actually presented. The HTTP enrolment path
    never called it, so a caller controlling both `domain` and `gatewayUrl`
    could have any record promoted to VERIFIED.
    """
    body = _federation_peer_body()
    assert "verify_node_record(" in body, \
        "enrolment must bind the record to the presented certificate"
    # The retrieval moved into federation.peerfetch, so the invariant is now
    # asserted across the call chain: the handler must delegate to the
    # retrieval function, and that function must take the certificate off a
    # live connection rather than from anything the caller supplied.
    assert "peer_certificate_der(" in body, \
        "the certificate must be retrieved, not assumed"
    from federation import peerfetch
    fetcher = (ROOT / "federation" / "peerfetch.py").read_text()
    assert "getpeercert" in fetcher, \
        "peer_certificate_der must read the certificate off the connection"
    import inspect
    sig = inspect.signature(peerfetch.peer_certificate_der)
    assert "gateway_url" in sig.parameters and "cert" not in sig.parameters, \
        "the certificate must come from the connection, not from a parameter"


def test_plain_http_peering_cannot_reach_verified():
    """No certificate means no binding, so no verified trust."""
    body = _federation_peer_body()
    assert "tls_verified = False" in body
    assert "XCP_ALLOW_INSECURE_PEERS" in body


def test_mutual_peering_cannot_be_self_asserted():
    """
    XCP-B-02 (high). `mutual` came from the request body and passed straight
    into add_verified_peer, so the initiating caller could award itself PEERED
    -- the strongest trust level -- with a boolean.
    """
    body = _federation_peer_body()
    assert 'mutual=bool(body.get("mutual"))' not in body, \
        "mutual trust cannot be asserted by the party seeking it"
    assert "mutual=False" in body


def test_peered_is_strictly_stronger_than_verified():
    """The reason B.2 mattered: PEERED is not a label, it outranks VERIFIED."""
    from federation import PeerTrust
    assert PeerTrust.PEERED.value > PeerTrust.VERIFIED.value


# ── remaining independent-review findings ──────────────────────────────────

def test_production_profile_refuses_to_start_without_its_prerequisites():
    """
    XCP-B-03. Without an external verifier, /v1/session/open mints identity
    bindings from unauthenticated requests, so possession of the endpoint is
    sufficient to assert an identity. A profile claimed and not enforced is
    worse than one never claimed.
    """
    import subprocess, os as _os
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r); sys.path.insert(0, %r);"
         "import xcp_gateway" % (str(ROOT), str(ROOT / "core" / "gateway"))],
        capture_output=True, text=True,
        env={**_os.environ, "XCP_PROFILE": "production",
             "XCP_VERIFY_URL": "", "XCP_ADMIN_TOKEN": ""})
    assert r.returncode != 0, "production profile started without prerequisites"
    assert "cannot enforce it" in (r.stderr + r.stdout)


def test_production_profile_requires_every_control():
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index('if _PROFILE == "production":')
    body = src[i:i + 1800]
    for control in ("XCP_POSTURE", "XCP_VERIFY_URL", "XCP_SECURITY",
                    "XCP_RATE_LIMIT", "XCP_LIMIT_FAIL_OPEN", "XCP_ADMIN_TOKEN",
                    "XCP_ALLOW_INSECURE_PEERS"):
        assert control in body, f"production profile does not require {control}"


def test_delegation_authority_is_not_reported_as_delivery():
    """
    XCP-B-05. The A2A path returned accepted=True, which a caller could read as
    delivery. Authority to delegate says nothing about whether the destination
    authenticated or executed.
    """
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("async def a2a_delegate(")
    j = src.find("@app.", i)
    body = src[i:j]
    assert '"delivered": False' in body
    assert '"accepted": True' not in body


def test_forwarded_credentials_are_bounded_and_destination_bound():
    """XCP-B-06. An unbounded, unspecified pass-through is a confused deputy."""
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    assert "MAX_UPSTREAM_CREDENTIAL" in src
    i = src.index("def _check_upstream_credential(")
    body = src[i:i + 1600]
    assert "413" in body, "oversized credentials must be refused"
    assert "xcp-upstream-audience" in body, "must bind to one destination"
    assert "PRODUCTION" in body, "audience must be mandatory in production"


def test_the_gateway_never_reads_a_forwarded_credential():
    """Bounding it must not become inspecting it."""
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("def _check_upstream_credential(")
    body = src[i:i + 1600]
    for leak in ("json.loads(raw", "b64decode(raw", "audit(", "print(raw"):
        assert leak not in body, f"forwarded credential is being inspected: {leak}"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:130]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
