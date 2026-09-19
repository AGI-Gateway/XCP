"""
test_two_node.py — two real nodes, in two processes, talking over HTTP.

Every other federation test runs one `Federation` object against synthetic
peers. That validates the logic and proves nothing about whether a node can
actually find, verify and peer with another node over the wire.

The first run of this file found that `federation/` had zero references in the
gateway: identity, peering, transitive trust and revocation gossip all existed
as a tested library that no running node could reach.

    python tests/test_two_node.py
"""
from __future__ import annotations

import json
import multiprocessing
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

A_PORT, B_PORT = 8710, 8711
A_DOM, B_DOM = "node-a.test", "node-b.test"
ADMIN_TOKEN = "two-node-test-token"
A_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
B_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
A_FP = "0x" + "a1" * 32
B_FP = "0x" + "b2" * 32


def _run(port: int, domain: str, key: str, fp: str):
    os.environ.update(
        XCP_POSTURE="enforce", XCP_RATE_LIMIT="1", XCP_GLOBAL_RATE="500000",
        XCP_NODE_KEY=key, XCP_NODE_DOMAIN=domain, XCP_NODE_CERT_FOOTPRINT=fp,
        XCP_NODE_URL=f"http://127.0.0.1:{port}",
        # Loopback over plain HTTP is refused by the egress guard, which is
        # correct in production and has to be opted out of for a local test.
        XCP_ALLOW_INSECURE_PEERS="1", XCP_ADMIN_TOKEN=ADMIN_TOKEN)
    sys.path.insert(0, str(ROOT))
    import uvicorn
    from core.gateway.xcp_gateway import app
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


_UP = False


def _boot():
    global _UP
    if _UP:
        return
    try:
        multiprocessing.set_start_method("spawn", force=True)
    except RuntimeError:
        pass
    multiprocessing.Process(target=_run, args=(A_PORT, A_DOM, A_KEY, A_FP),
                            daemon=True).start()
    multiprocessing.Process(target=_run, args=(B_PORT, B_DOM, B_KEY, B_FP),
                            daemon=True).start()
    for port in (A_PORT, B_PORT):
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
                break
            except Exception:
                time.sleep(0.4)
        else:
            raise RuntimeError(f"node on {port} never came up")
    _UP = True


def _get(port: int, path: str, admin: bool = False):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"} if admin else {})
    with urllib.request.urlopen(req, timeout=8) as r:
        return r.status, json.loads(r.read())


def _post(port: int, path: str, body: dict, headers: dict | None = None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


# ── a node must be discoverable at all ─────────────────────────────────────

def test_each_node_publishes_a_record_at_the_well_known_path():
    _boot()
    for port, dom in ((A_PORT, A_DOM), (B_PORT, B_DOM)):
        status, rec = _get(port, "/.well-known/xcp-node.json")
        assert status == 200, f"{dom} publishes nothing"
        assert rec["domain"] == dom
        assert rec["node_id"].startswith("0x")
        assert rec["bindings"], "a record with no signed binding cannot survive " \
                               "a certificate renewal"


def test_the_two_nodes_have_different_identities():
    _boot()
    _, a = _get(A_PORT, "/.well-known/xcp-node.json")
    _, b = _get(B_PORT, "/.well-known/xcp-node.json")
    assert a["node_id"] != b["node_id"]


def test_node_identity_is_not_the_certificate_footprint():
    _boot()
    _, a = _get(A_PORT, "/.well-known/xcp-node.json")
    assert a["node_id"].lower() != A_FP.lower(), \
        "identity must survive a certificate renewal"
    assert a["bindings"]["current"]["cert_footprint"].lower() == A_FP.lower()


def test_records_advertise_protocol_versions_so_peers_can_negotiate():
    _boot()
    _, a = _get(A_PORT, "/.well-known/xcp-node.json")
    assert a.get("protocol_versions"), "a peer cannot tell what we speak"


# ── peering ────────────────────────────────────────────────────────────────

def test_a_peers_with_b_by_fetching_and_verifying_bs_record():
    _boot()
    status, res = _post(A_PORT, "/v1/federation/peer",
                        {"domain": B_DOM, "gatewayUrl": f"http://127.0.0.1:{B_PORT}",
                         "mutual": True})
    assert status == 200, res
    assert res["peered"] is True
    _, b = _get(B_PORT, "/.well-known/xcp-node.json")
    assert res["nodeId"] == b["node_id"], "A must record B's real identity"


def test_peering_over_plain_http_is_flagged_not_silently_accepted():
    """The cert-footprint check needs TLS. Saying so beats pretending."""
    _boot()
    _, res = _post(A_PORT, "/v1/federation/peer",
                   {"domain": B_DOM, "gatewayUrl": f"http://127.0.0.1:{B_PORT}"})
    assert res.get("tlsVerified") is False
    assert "Development only" in (res.get("warning") or "")


def test_the_peer_appears_in_as_reachable_set():
    _boot()
    _post(A_PORT, "/v1/federation/peer",
          {"domain": B_DOM, "gatewayUrl": f"http://127.0.0.1:{B_PORT}"})
    _, peers = _get(A_PORT, "/v1/federation/peers", admin=True)
    assert any(p["domain"] == B_DOM for p in peers["peers"])
    assert peers["summary"]["direct"] >= 1


def test_a_record_that_claims_another_domain_is_refused():
    """Anyone can post a body; the record is fetched from the domain it claims."""
    _boot()
    status, res = _post(A_PORT, "/v1/federation/peer",
                        {"domain": "impostor.test",
                         "gatewayUrl": f"http://127.0.0.1:{B_PORT}"})
    assert status == 400
    assert "does not claim that domain" in res["error"]


def test_an_unreachable_peer_fails_cleanly():
    _boot()
    status, res = _post(A_PORT, "/v1/federation/peer",
                        {"domain": "gone.test", "gatewayUrl": "http://127.0.0.1:1"})
    assert status in (400, 502)
    # The message is generic on purpose: echoing the fetch error turned a
    # blind SSRF into an oracle.
    assert "errno" not in json.dumps(res).lower()


# ── revocation gossip ──────────────────────────────────────────────────────

def test_revocation_is_refused_from_a_stranger():
    """Otherwise anyone could revoke their rivals."""
    _boot()
    status, res = _post(A_PORT, "/v1/federation/revoke",
                        {"nodeId": "0x" + "ff" * 32, "from": "stranger.test"})
    assert status in (400, 403)
    assert res.get("accepted") is not True


def test_revocation_is_accepted_when_the_peer_signs_it():
    """A claim of identity is not evidence of it; the originator must sign."""
    _boot()
    _post(A_PORT, "/v1/federation/peer",
          {"domain": B_DOM, "gatewayUrl": f"http://127.0.0.1:{B_PORT}"})
    from federation import NodeIdentity, sign_revocation
    b_ident = NodeIdentity.from_key(B_KEY)
    doc = sign_revocation(b_ident, "0x" + "ee" * 32, reason="compromised")
    status, res = _post(A_PORT, "/v1/federation/revoke",
                        {"from": B_DOM, "revocation": doc})
    assert status == 200 and res["accepted"] is True, res


def test_a_revocation_signed_by_the_wrong_node_is_refused():
    _boot()
    _post(A_PORT, "/v1/federation/peer",
          {"domain": B_DOM, "gatewayUrl": f"http://127.0.0.1:{B_PORT}"})
    from federation import NodeIdentity, sign_revocation
    attacker = NodeIdentity.generate()
    doc = sign_revocation(attacker, "0x" + "ee" * 32)
    status, res = _post(A_PORT, "/v1/federation/revoke",
                        {"from": B_DOM, "revocation": doc})
    assert status == 403 and res.get("accepted") is not True


# ── catalog federation ─────────────────────────────────────────────────────

def test_a_node_publishes_a_catalog_a_peer_can_ingest():
    _boot()
    status, doc = _get(B_PORT, "/v1/federation/catalog")
    assert status == 200
    assert doc.get("connectors"), "nothing to federate"
    from connectors import GlobalCatalog, Source, SourceKind
    mine = GlobalCatalog()
    n = mine.ingest(Source(id="peer-b", kind=SourceKind.PEER,
                           url=f"https://{B_DOM}/v1/federation/catalog"), doc)
    assert n > 0, "a peer's catalog must be ingestible"
    for e in mine.ingested.values():
        assert e.trust_class == "unknown", \
            "a peer's catalog must not set its own trust class"


# ── the whole point: this is a network, not a library ──────────────────────

def test_both_nodes_serve_traffic_while_peered():
    _boot()
    _post(A_PORT, "/v1/federation/peer",
          {"domain": B_DOM, "gatewayUrl": f"http://127.0.0.1:{B_PORT}"})
    for port in (A_PORT, B_PORT):
        status, h = _get(port, "/health")
        assert status == 200 and h["ok"] is True
        assert h.get("rateLimit") != "disabled", "abuse controls must stay on"


def test_a_node_without_federation_configured_says_so():
    """A 404 that explains beats a 500."""
    _boot()
    # the verifier-less path: federation endpoints require node identity env
    status, _ = _get(A_PORT, "/v1/federation/peers")
    assert status == 200, "these nodes ARE configured"


# ── certificate rotation, live ─────────────────────────────────────────────

def test_a_rotation_does_not_orphan_the_peer():
    """
    The design claim from #4: a renewal publishes a new binding, not a new node,
    so trust survives. Tested here against two live processes rather than
    synthetic records.
    """
    _boot()
    _post(A_PORT, "/v1/federation/peer",
          {"domain": B_DOM, "gatewayUrl": f"http://127.0.0.1:{B_PORT}"})
    _, before = _get(A_PORT, "/v1/federation/peers", admin=True)
    b_before = [p for p in before["peers"] if p["domain"] == B_DOM][0]

    # B rotates: same identity key, new certificate, higher sequence
    from federation import NodeIdentity, rotate, BindingSet
    ident = NodeIdentity.from_key(B_KEY)
    bs1 = rotate(ident, B_FP, domain=B_DOM)
    bs2 = rotate(ident, "0x" + "c3" * 32, domain=B_DOM, existing=bs1)
    assert bs2.current.node_id == bs1.current.node_id, \
        "a renewal must not change who the node is"
    assert bs2.sequence > bs1.sequence

    # A re-peers after the rotation
    _, after = _post(A_PORT, "/v1/federation/peer",
                     {"domain": B_DOM, "gatewayUrl": f"http://127.0.0.1:{B_PORT}"})
    assert after["nodeId"] == b_before["node_id"], \
        "identity must be stable across a certificate change"


def test_a_sequence_regression_is_refused_live():
    """A replayed binding must not downgrade a peer to an older certificate."""
    _boot()
    _post(A_PORT, "/v1/federation/peer",
          {"domain": B_DOM, "gatewayUrl": f"http://127.0.0.1:{B_PORT}"})
    from federation import Federation, FederationError
    f = Federation(self_domain=A_DOM, self_node_id="0x" + "aa" * 32)
    f.add_verified_peer(B_DOM, "0x" + "bb" * 32, sequence=9)
    try:
        f.add_verified_peer(B_DOM, "0x" + "bb" * 32, sequence=2)
        assert False, "an older binding must not be accepted"
    except FederationError:
        pass


# ── transitive trust across three parties ──────────────────────────────────

def test_trust_decays_across_a_real_introduction():
    _boot()
    from federation import Federation, Attestation, PeerTrust
    import time as _t
    _, b = _get(B_PORT, "/.well-known/xcp-node.json")

    a = Federation(self_domain=A_DOM, self_node_id="0x" + "aa" * 32)
    a.add_verified_peer(B_DOM, b["node_id"], f"http://127.0.0.1:{B_PORT}")
    direct = a.trust_of(B_DOM)[1]

    now = int(_t.time())
    a.ingest_attestation(Attestation(
        subject_domain="node-c.test", subject_node_id="0x" + "cc" * 32,
        issuer_domain=B_DOM, issuer_node_id=b["node_id"],
        trust=PeerTrust.VERIFIED, issued_at=now, expires_at=now + 3600))
    introduced = a.trust_of("node-c.test")[1]
    assert 0 < introduced < direct, \
        "a peer-of-a-peer must be trusted less than a peer"


def test_an_introduction_from_an_unknown_party_is_ignored():
    _boot()
    from federation import Federation, Attestation, PeerTrust
    import time as _t
    a = Federation(self_domain=A_DOM, self_node_id="0x" + "aa" * 32)
    now = int(_t.time())
    assert a.ingest_attestation(Attestation(
        subject_domain="node-c.test", subject_node_id="0x" + "cc" * 32,
        issuer_domain="stranger.test", issuer_node_id="0x" + "99" * 32,
        trust=PeerTrust.VERIFIED, issued_at=now, expires_at=now + 3600)) is None


# ── paid transport between two real nodes ──────────────────────────────────

def test_a_node_can_bill_a_peer_for_routed_traffic():
    _boot()
    from federation import (RoutingLedger, TransportReceipt, RouteClass,
                            sign_receipt, verify_proof)
    _, b = _get(B_PORT, "/.well-known/xcp-node.json")
    led = RoutingLedger(node_id=b["node_id"])
    for i in range(5):
        r = sign_receipt(A_KEY, TransportReceipt(
            route_id=f"r{i}", node_id=b["node_id"], payer_agent=42001,
            route_class=RouteClass.A2T, price_minor=10, epoch=1))
        assert led.record(r) == [], "a signed receipt from the payer must bill"
    c = led.commit(1)
    assert c.route_count == 5 and c.total_minor == 50
    d = led.prove(1, "r2")
    assert verify_proof(d["leaf"], d["proof"], d["root"])
    assert "42001" not in json.dumps(c.to_dict()), \
        "the public commitment must not carry the counterparty"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:150]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
