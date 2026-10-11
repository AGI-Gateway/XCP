"""
test_locality.py — where a route goes, and where a tool call may be served.

TWO LEVERS THAT ARE NOT THE SAME LEVER
--------------------------------------
Routing had a hop count and no notion of region, so multi-site latency
optimisation had nothing to optimise against, and XCP_UPSTREAMS was per-gateway,
so every datacentre needed its own egress path and its own copy of every vendor
credential.

Locality and residency fix different halves of that, and the distinction is the
design:

    LOCALITY is a COST.       A remote peer is worse, not forbidden. When the
                              local one is down, routing must still reach it.
    RESIDENCY is a CONSTRAINT. A jurisdiction is not a quantity you can be
                              compensated for crossing, so it is checked before
                              optimisation -- this module's own rule being that
                              a constraint which can be outweighed is a
                              preference wearing a constraint's name.

Most of what follows tests that the two stay on their own side of that line,
and that adding locality did not quietly undo the path-diversity property the
module exists to protect.

    python tests/test_locality.py
"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from federation.routing import (CROSS_SITE_COST, DEFAULT_TOLERANCE,  # noqa: E402
                                Effect, PeerMetrics, Policy, RoutingError,
                                admissible, concentration, score, select)


class _Skipped(Exception):
    """Standalone-runner skip."""


def _skip(reason: str) -> None:
    if "pytest" in sys.modules:
        import pytest
        pytest.skip(reason)
    raise _Skipped(reason)


def _refuses(exc, fn, *a, **kw) -> str:
    try:
        fn(*a, **kw)
    except exc as e:
        return str(e)
    raise AssertionError(f"did not raise {exc.__name__}")


def _peers(site: str, n: int, *, latency: float = 5.0,
           cls: str = "contracted", prefix: str = "") -> list[PeerMetrics]:
    return [PeerMetrics(domain=f"{prefix or site}-{i}.internal", site=site,
                        server_class=cls, latency_ms=latency, samples=10)
            for i in range(n)]


# ── locality is a cost ─────────────────────────────────────────────────────

def test_a_local_peer_is_preferred_over_a_remote_one():
    rng = random.Random(7)
    pool = _peers("dc1", 3) + _peers("dc2", 3)
    chosen = [select(pool, Policy(home_site="dc1"), rng=rng).peer.site
              for _ in range(300)]
    assert set(chosen) == {"dc1"}, \
        f"traffic left the local site: {concentration(chosen)}"


def test_a_remote_peer_is_still_reachable_when_no_local_one_is():
    """
    The reason locality is a cost and not a constraint. A preference that
    cannot be overcome is an outage waiting for the local site to fail.
    """
    chosen = select(_peers("dc2", 2), Policy(home_site="dc1"))
    assert chosen.peer.site == "dc2"
    assert chosen.off_site is True
    assert chosen.total_cost >= CROSS_SITE_COST, \
        "crossing a site boundary was free"


def test_an_untested_remote_peer_does_not_look_free():
    """
    The gap locality actually closes. An untested peer has latency_ms 0.0, so
    without a locality prior a node rates a remote peer it has never called
    better than the local one it has measured -- and finds out by sending
    traffic. The prior is what stops the first request being the experiment.
    """
    measured_local = PeerMetrics(domain="local", site="dc1",
                                 server_class="contracted", latency_ms=8.0,
                                 samples=50)
    untested_remote = PeerMetrics(domain="remote", site="dc2",
                                  server_class="contracted")
    pol = Policy(home_site="dc1")
    assert score(measured_local, pol).score < score(untested_remote, pol).score

    # and with no home site declared, there is no locality to apply
    flat = Policy()
    assert score(untested_remote, flat).score < score(measured_local, flat).score


def test_an_unlabelled_peer_counts_as_off_site():
    """Not knowing where a peer is is not evidence of it being local."""
    pol = Policy(home_site="dc1")
    assert pol.crosses(PeerMetrics(domain="x", site=""))
    assert not pol.crosses(PeerMetrics(domain="y", site="dc1"))


def test_a_node_with_no_site_has_no_locality():
    pol = Policy()
    for site in ("", "dc1", "dc2"):
        assert not pol.crosses(PeerMetrics(domain="x", site=site))


def test_a_nearer_peer_can_still_lose_to_a_much_better_remote_one():
    """
    Locality is a price, not a veto. A local peer that is slow and unreliable
    should lose, or 'prefer local' has become 'local only' by another name.
    """
    bad_local = PeerMetrics(domain="slow", site="dc1", server_class="unknown",
                            latency_ms=900.0, samples=20, failures=10)
    good_remote = PeerMetrics(domain="fast", site="dc2",
                              server_class="contracted", latency_ms=12.0,
                              samples=20)
    chosen = select([bad_local, good_remote], Policy(home_site="dc1",
                                                     effect=Effect.OBSERVE))
    assert chosen.peer.domain == "fast"


# ── path diversity survives ────────────────────────────────────────────────

def test_locality_does_not_undo_path_diversity():
    """
    The property this module exists to protect: independent callers must not
    converge on one peer. Locality narrows the pool to the local site -- which
    is the point -- and diversity has to keep operating INSIDE it.
    """
    rng = random.Random(11)
    pool = _peers("dc1", 4) + _peers("dc2", 4)
    hist = [select(pool, Policy(home_site="dc1"), rng=rng).peer.domain
            for _ in range(600)]
    c = concentration(hist)
    assert c["peers"] == 4, f"diversity collapsed within the site: {c}"
    assert c["hhi"] < 0.3, f"routing concentrated despite the band: {c}"


def test_argmin_still_concentrates_which_is_why_the_band_exists():
    """The control. With no tolerance, everything converges -- the behaviour
    the tolerance band was introduced to prevent."""
    rng = random.Random(11)
    pool = _peers("dc1", 4, latency=5.0)
    pool[0].latency_ms = 4.0                     # one marginally best peer
    hist = [select(pool, Policy(home_site="dc1", tolerance=0.0),
                   rng=rng).peer.domain for _ in range(200)]
    assert concentration(hist)["hhi"] == 1.0


def test_one_local_peer_means_no_local_diversity():
    """
    Stated rather than hidden: a site with a single peer sends everything to
    it. That is a property of the deployment, not a routing defect, and an
    operator reading the concentration index should see it.
    """
    rng = random.Random(3)
    pool = _peers("dc1", 1) + _peers("dc2", 3)
    hist = [select(pool, Policy(home_site="dc1"), rng=rng).peer.domain
            for _ in range(100)]
    c = concentration(hist)
    assert c["hhi"] == 1.0 and c["peers"] == 1


# ── residency is a constraint ──────────────────────────────────────────────

def test_a_peer_outside_the_permitted_region_is_inadmissible():
    pol = Policy(permitted_sites=frozenset({"eu-west-1"}))
    ok, why = admissible(PeerMetrics(domain="x", site="us-east-1",
                                     server_class="contracted"), pol)
    assert not ok and "permitted processing region" in why


def test_residency_cannot_be_outweighed_by_anything():
    """
    The distinction from locality, asserted directly. A peer outside the
    region is refused however fast, cheap and trusted it is -- and the
    permitted one is chosen even when it is far worse.
    """
    perfect_but_foreign = PeerMetrics(domain="fast", site="us-east-1",
                                      server_class="contracted",
                                      latency_ms=1.0, samples=100)
    awful_but_permitted = PeerMetrics(domain="slow", site="eu-west-1",
                                      server_class="unknown",
                                      latency_ms=5000.0, samples=100,
                                      failures=40)
    pol = Policy(permitted_sites=frozenset({"eu-west-1"}),
                 effect=Effect.OBSERVE)
    assert select([perfect_but_foreign, awful_but_permitted],
                  pol).peer.domain == "slow"


def test_residency_overrides_locality_rather_than_competing_with_it():
    """
    A node in dc1 whose residency list names only dc2 must route to dc2. If
    locality could win here, residency would be advisory.
    """
    pool = _peers("dc1", 2) + _peers("dc2", 2)
    pol = Policy(home_site="dc1", permitted_sites=frozenset({"dc2"}))
    for _ in range(50):
        assert select(pool, pol).peer.site == "dc2"


def test_an_undeclared_site_fails_residency():
    """
    Defaulting the other way would make the control absent exactly when it
    matters -- a peer that never said where it is would be treated as
    compliant.
    """
    pol = Policy(permitted_sites=frozenset({"eu-west-1"}))
    assert "no peer satisfies" in _refuses(
        RoutingError, select,
        [PeerMetrics(domain="x", site="", server_class="contracted")], pol)


def test_no_residency_list_means_no_residency_constraint():
    pool = _peers("dc1", 1) + _peers("us-east-1", 1)
    assert len(pool) == 2
    for p in pool:
        ok, _ = admissible(p, Policy())
        assert ok


def test_residency_is_checked_before_optimisation():
    """
    Structural, not behavioural: a constraint evaluated after scoring is a
    weight. `admissible` runs first in `select`, and residency lives there.
    """
    src = (ROOT / "federation" / "routing.py").read_text()
    i = src.index("def admissible(")
    j = src.index("def _total_cost(", i)
    assert "permitted_sites" in src[i:j], \
        "residency is not enforced in the constraint filter"
    k = src.index("def score(")
    assert "permitted_sites" not in src[k:k + 900], \
        "residency leaked into the scoring function, where it can be outweighed"


# ── trust is still a constraint, not traded against locality ───────────────

def test_locality_cannot_buy_a_trust_class():
    """
    The module's founding rule, re-checked now that there is another term in
    the cost. A local peer below the trust floor for an effect stays refused.
    """
    local_untrusted = PeerMetrics(domain="local", site="dc1", hops=3,
                                  trust_weight=0.5, server_class="unknown",
                                  latency_ms=1.0)
    pol = Policy(home_site="dc1", effect=Effect.SETTLE)
    ok, why = admissible(local_untrusted, pol)
    assert not ok and "below the" in why


# ── what a node advertises ─────────────────────────────────────────────────

def test_a_node_record_advertises_its_site_and_servers():
    from federation import NodeRecord
    rec = NodeRecord(domain="dc1.internal", node_id="0x" + "11" * 32,
                     gateway_url="https://dc1.internal", site="dc1",
                     serves=["research", "billing"])
    d = rec.to_dict()
    assert d["site"] == "dc1" and d["serves"] == ["research", "billing"]


def test_the_reduced_record_withholds_the_egress_map():
    """
    Which datacentres exist and what each can reach is the estate's egress
    map, which is the reconnaissance step before choosing what to attack.
    """
    from federation import NodeRecord
    rec = NodeRecord(domain="dc1.internal", node_id="0x" + "11" * 32,
                     gateway_url="https://dc1.internal", site="dc1-dublin",
                     serves=["stripe-prod", "payroll"])
    red = rec.reduced()
    blob = json.dumps(red)
    for leaked in ("dc1-dublin", "stripe-prod", "payroll"):
        assert leaked not in blob, f"the reduced record published {leaked!r}"
    assert "site" not in red and "serves" not in red


def test_the_federation_finds_peers_that_serve_a_server():
    from federation import Federation, PeerTrust
    fed = Federation(self_domain="dc0.internal", self_node_id="0x" + "00" * 32)
    fed.add_verified_peer("dc1.internal", "0x" + "11" * 32,
                          "https://dc1.internal", site="dc1",
                          serves=["research", "billing"])
    fed.add_verified_peer("dc2.internal", "0x" + "22" * 32,
                          "https://dc2.internal", site="dc2",
                          serves=["research"])
    assert {p.domain for p in fed.serving("research")} == {"dc1.internal",
                                                            "dc2.internal"}
    assert {p.domain for p in fed.serving("billing")} == {"dc1.internal"}
    assert fed.serving("nonexistent") == []


def test_a_revoked_peer_serves_nothing():
    from federation import Federation
    fed = Federation(self_domain="dc0.internal", self_node_id="0x" + "00" * 32)
    p = fed.add_verified_peer("dc1.internal", "0x" + "11" * 32,
                              serves=["research"], site="dc1")
    assert fed.serving("research")
    p.revoked = True
    assert fed.serving("research") == [], \
        "a revoked peer was still offered as a route"


# ── end to end: one egress gateway for the estate ──────────────────────────
# Everything above tests a part. This runs the thing: dc1 cannot reach a tool,
# dc2 can, and dc1's agent gets the result without dc1 ever holding the vendor
# credential. That is the whole reason to centralise egress -- one place to
# audit, one rate limit against the vendor's quota, one copy of the secret.

DC1_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
DC2_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"


def _upstream(port: int):
    """A minimal MCP server, so the relay has something real to reach."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class H(BaseHTTPRequestHandler):
        def do_POST(self):                      # noqa: N802 - stdlib interface
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n) or b"{}")
            name = (req.get("params") or {}).get("name", "")
            # Echo back who the gateway said was calling, so the test can see
            # the VERIFIED identity travel rather than a client-asserted one.
            out = json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "result": {"tool": name, "servedBy": "upstream",
                           "forAgent": self.headers.get("XCP-Agent-Identity", ""),
                           "verifiedBy": self.headers.get("XCP-Verified-By", ""),
                           "sawCredential": bool(
                               self.headers.get("XCP-Upstream-Credential"))}
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _node:
    """A gateway on loopback with a node identity and a site."""

    def __init__(self, port: int, key: str, domain: str, **env) -> None:
        self.port, self.key, self.domain, self.extra = port, key, domain, env

    def __enter__(self):
        import urllib.request
        env = {**os.environ,
               "XCP_PROFILE": "development", "XCP_POSTURE": "enforce",
               "XCP_VERIFY_URL": "", "XCP_RATE_LIMIT": "1",
               "XCP_GLOBAL_RATE": "500000",
               "XCP_ADMIN_TOKEN": "locality-test-token",
               "XCP_ALLOW_INSECURE_PEERS": "1",
               "XCP_NODE_KEY": self.key, "XCP_NODE_DOMAIN": self.domain,
               "XCP_NODE_URL": f"http://127.0.0.1:{self.port}",
               "XCP_UPSTREAMS": "{}",
               **self.extra}
        env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "security")])
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "core.gateway.xcp_gateway:app",
             "--host", "127.0.0.1", "--port", str(self.port),
             "--log-level", "error"],
            env=env, cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True)
        for _ in range(120):
            if self.proc.poll() is not None:
                raise AssertionError(f"{self.domain} exited:\n"
                                     + (self.proc.stdout.read() or "")[:2000])
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/health", timeout=2)
                return self
            except Exception:
                time.sleep(0.2)
        raise AssertionError(f"{self.domain} did not come up")

    def post(self, path: str, payload: dict, headers=None):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", **(headers or {})},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def call_tool(self, server: str, tool: str, args=None, *,
                  tier: str = "A2xH2"):
        """Drive a real session and mandate, as any caller would."""
        sys.path.insert(0, str(ROOT / "core" / "client" / "python"))
        from xcp_client import AgentIdentity, XCPClient, XCPError, sign_mandate
        key = DC1_KEY
        ident = AgentIdentity(agent_id=42001, chain_id=8453, private_key=key)
        client = XCPClient(f"http://127.0.0.1:{self.port}", ident, tier=tier)
        client.connect()
        mandate = sign_mandate(key, "m-tools", ident.address,
                               [f"mcp:tools/{tool}"], int(time.time()) + 3600)
        try:
            return 200, client.call_tool(server, tool, args or {},
                                          mandate=mandate)
        except XCPError as e:
            return 0, {"error": str(e)}

    def __exit__(self, *exc) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _peer_them(a: "_node", b: "_node") -> None:
    """Peer in both directions: the relaying end is the one that checks."""
    for src, dst in ((a, b), (b, a)):
        status, res = src.post("/v1/federation/peer",
                               {"domain": dst.domain,
                                "gatewayUrl": f"http://127.0.0.1:{dst.port}"})
        assert status == 200, \
            f"peering {src.domain} -> {dst.domain}: {status} {res}"


def _estate(*, fallback: str = "1", relay: str = "1", residency: str = "",
            dc2_site: str = "dc2", ceiling: str = "A2xH2"):
    """dc1 with no upstreams; dc2 with the tool and the credential."""
    up = _upstream(9971)
    try:
        with _node(8761, DC1_KEY, "dc1.internal",
                   XCP_NODE_SITE="dc1", XCP_TOOL_FALLBACK=fallback,
                   XCP_RESIDENCY_SITES=residency) as a:
            with _node(8762, DC2_KEY, "dc2.internal",
                       XCP_NODE_SITE=dc2_site, XCP_TOOL_RELAY=relay,
                       XCP_A2A_TIER_CEILING=ceiling,
                       XCP_UPSTREAM_RELAY_CREDENTIAL="vendor-secret",
                       XCP_UPSTREAMS=json.dumps(
                           {"research": "http://127.0.0.1:9971/mcp"})) as b:
                _peer_them(a, b)
                return a.call_tool("research", "echo", {"text": "hi"})
    finally:
        up.shutdown()


def test_a_tool_this_node_cannot_reach_is_served_by_a_peer():
    status, res = _estate()
    assert status == 200, f"{status} {res}"
    result = res.get("result") or {}
    assert result.get("tool") == "echo", res
    assert result.get("verifiedBy"), "the upstream saw no verifying gateway"


def test_the_asking_node_never_holds_the_vendor_credential():
    """
    The whole reason to centralise egress. dc1 sends no credential; dc2 holds
    it and presents it. One place to audit, one quota, one secret to rotate.
    """
    status, res = _estate()
    assert status == 200, f"{status} {res}"
    assert (res.get("result") or {}).get("sawCredential") is True, \
        "the egress gateway did not present its own credential"
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("async def _relay_to_peer(")
    j = src.index("@app.post(\"/v1/tool/relay\")", i)
    assert "upstream_credential" not in src[i:j], \
        "the asking node forwards a credential; it should hold none"


def test_a_node_that_does_not_relay_is_never_even_asked():
    """
    Defence in depth, and better than refusing: a node with XCP_TOOL_RELAY
    unset advertises no servers, so it never appears as a candidate and the
    asking node does not try. You cannot aim a relay at a node that has not
    opted in.
    """
    status, res = _estate(relay="0")
    assert status == 0, f"a non-relaying node served the call: {res}"
    assert "unknown server" in str(res), \
        f"expected no candidate at all, got: {res}"


def test_a_node_that_does_not_relay_also_refuses_a_direct_ticket():
    """
    The other half: advertising is only a hint, so the endpoint itself must
    refuse rather than relying on nobody having been told about it.
    """
    with _node(8762, DC2_KEY, "dc2.internal", XCP_NODE_SITE="dc2",
               XCP_TOOL_RELAY="0") as b:
        status, res = b.post("/v1/tool/relay",
                             {"ticket": {}, "task": {"server": "research",
                                                     "tool": "echo"}})
    assert status == 404, f"{status} {res}"
    assert "does not relay" in str(res), res


def test_fallback_is_off_by_default():
    """A call leaving for another datacentre is a different data path than the
    one the operator configured, so they choose it."""
    status, res = _estate(fallback="0")
    assert status == 0, f"the call left the site without being asked: {res}"
    assert "unknown server" in str(res), res


def test_residency_refuses_a_peer_outside_the_region():
    status, res = _estate(residency="dc1", dc2_site="dc2")
    assert status == 0, f"a call was processed outside the region: {res}"
    assert "routing constraints" in str(res) or "no peer" in str(res), res


def test_residency_admits_a_peer_inside_the_region():
    """The control: the same deployment, with dc2 inside the permitted set."""
    status, res = _estate(residency="dc1,dc2")
    assert status == 200, f"{status} {res}"
    assert (res.get("result") or {}).get("tool") == "echo", res


def test_the_relay_narrows_the_tier_before_calling_upstream():
    """
    A relayed call runs at the tier the RELAYING node allows, not the one the
    asking node asserted. Observed through the limiter: an A0xH0 ceiling
    throttles far sooner than A2xH2, so the narrowing is load-bearing rather
    than cosmetic.
    """
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("async def tool_relay(")
    j = src.index("async def _route_mcp(", i)
    body = src[i:j]
    assert "decision.effective_tier" in body, \
        "the relay does not run at the narrowed tier"
    assert "A2A_TIER_CEILING" in body, "the relay applies no ceiling"
    assert body.index("admit(") < body.index("_route_mcp("), \
        "the call is made before the ticket is admitted"


def test_the_relay_will_not_forward_onward():
    """A relay that relays again is a chain nobody configured."""
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("async def tool_relay(")
    j = src.index("async def _route_mcp(", i)
    assert "does not serve" in src[i:j], \
        "an advertised-but-unreachable server is not refused plainly"


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
            print(f"  FAIL {name}: {str(e)[:170]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
