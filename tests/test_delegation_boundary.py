"""
test_delegation_boundary.py — an agent in one datacentre asking one in another.

WHAT THIS FILE IS ABOUT
-----------------------
/v1/a2a/delegate authorised a delegation and returned `accepted: True`, which a
caller could reasonably read as delivery. Independent review found it (B.4.5),
the handler's own comment admitted "here we echo an accepted delegation", and
the fix at the time was to stop making the claim. §9.3 of the draft now requires
the destination to authenticate independently.

That was a correction to a false claim. The capability did not exist. These
tests are mostly about the one property that makes it safe:

    AUTHORITY NARROWS AT A BOUNDARY AND NEVER WIDENS.

A ticket says what the originating gateway verified. The destination decides
what that is worth here, and the answer is never more than the origin claimed.
An originating datacentre cannot lift an agent above the destination's own
ceiling, which is the same invariant the OAuth bridge and the lattice's
entitlements already enforce one layer down.

    python tests/test_delegation_boundary.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from federation.delegation import (                                # noqa: E402
    DEFAULT_MAX_HOPS, DEFAULT_TICKET_TTL, Admission, DelegationError,
    DelegationHop, DelegationTicket, admit, canonical_tier, extend,
    format_tier, mint, narrow_tier, parse_tier, task_digest, widens)

try:
    from eth_account import Account
    _ETH = True
except ImportError:                                               # pragma: no cover
    _ETH = False


class _Skipped(Exception):
    """Standalone-runner skip."""


def _skip(reason: str) -> None:
    if "pytest" in sys.modules:
        import pytest
        pytest.skip(reason)
    raise _Skipped(reason)


def _need_eth() -> None:
    if not _ETH:
        _skip("eth-account required to sign delegation tickets")


def _refuses(exc, fn, *a, **kw) -> str:
    try:
        fn(*a, **kw)
    except exc as e:
        return str(e)
    raise AssertionError(f"{getattr(fn, '__name__', fn)} did not raise "
                         f"{exc.__name__}")


TASK = {"job": "summarize", "doc": "q3-report.pdf"}


def _ticketed(*, tier: str = "A2xH2", audience: str = "dc2.internal",
              task=TASK, hops=None, max_hops: int = DEFAULT_MAX_HOPS,
              cluster: str = "", ttl: int = DEFAULT_TICKET_TTL, now=None):
    """An origin node and a ticket it signed."""
    _need_eth()
    from federation.identity import node_id_from_address
    origin = Account.create()
    origin_id = node_id_from_address(origin.address)
    t = mint(origin.key.hex(), origin_node=origin_id,
             origin_domain="dc1.internal", audience=audience,
             agent_id=42001, chain_id=8453, footprint="0x" + "ab" * 32,
             asserted_tier=tier, scope="a2a:delegate/agent-b", task=task,
             peer="agent-b", cluster_id=cluster, hops=hops or [],
             max_hops=max_hops, ttl=ttl, now=now)
    return origin, origin_id, t


def _dest_id() -> str:
    from federation.identity import node_id_from_address
    return node_id_from_address(Account.create().address)


def _admit(t, *, ceiling="A2xH2", audience="dc2.internal", self_id=None,
           task=TASK, peer=True, cluster=None, expected_cluster="",
           now=None) -> Admission:
    return admit(t, audience=audience, self_node_id=self_id or _dest_id(),
                 ceiling=ceiling, task=task, origin_is_peer=peer,
                 origin_in_cluster=cluster, expected_cluster_id=expected_cluster,
                 now=now)


# ── the invariant ──────────────────────────────────────────────────────────

def test_authority_narrows_at_a_boundary():
    _, _, t = _ticketed(tier="A2xH2")
    d = _admit(t, ceiling="A1xH1")
    assert d.admitted and d.effective_tier == "A1xH1" and d.narrowed


def test_authority_never_widens_at_a_boundary():
    """
    The one that matters. A low-tier agent at the origin must not become a
    high-tier one at the destination, whatever the destination's ceiling is.
    """
    _, _, t = _ticketed(tier="A0xH0")
    for ceiling in ("A0xH0", "A1xH1", "A2xH2", "A2xH0", "A0xH2"):
        d = _admit(t, ceiling=ceiling)
        assert d.admitted, d.problems
        assert d.effective_tier == "A0xH0", \
            f"a ceiling of {ceiling} LIFTED an A0xH0 agent to {d.effective_tier}"
        assert not widens("A0xH0", d.effective_tier)


def test_narrowing_is_per_leg_not_per_cell():
    """
    The two legs mean different things -- what backs the agent, what backs the
    human -- so a destination that caps one has said nothing about the other.
    """
    assert narrow_tier("A2xH2", "A1xH2") == "A1xH2"
    assert narrow_tier("A2xH2", "A2xH0") == "A2xH0"
    assert narrow_tier("A2xH0", "A0xH2") == "A0xH0"
    assert narrow_tier("A0xH0", "A2xH2") == "A0xH0"


def test_narrowing_is_idempotent_and_commutative():
    """Two gateways applying the same ceilings in either order must agree, or
    a delegation's authority would depend on the route it took."""
    cells = [format_tier(a, h) for a in range(3) for h in range(3)]
    for x in cells:
        for y in cells:
            assert narrow_tier(x, y) == narrow_tier(y, x)
            assert narrow_tier(x, narrow_tier(x, y)) == narrow_tier(x, y)


def test_an_unparseable_tier_is_not_a_tier():
    for bad in ("", "A2", "A2H2", "A3xH1", "AxxHy", "a2xh2x", None):
        _refuses(DelegationError, parse_tier, bad)
    # and the canonical spelling matches the lattice's own
    assert canonical_tier("a2xh1") == "A2xH1"


def test_the_ticket_carries_the_tier_in_the_lattices_own_spelling():
    """
    assertedTier is a SIGNED field compared against trust.tiers cell strings.
    Normalising it with .upper() produced "A2XH2", which compares unequal to
    "A2xH2" -- it first showed up as a ticket reporting it had been narrowed
    when nothing had been.
    """
    _, _, t = _ticketed(tier="a2xh2")
    assert t.asserted_tier == "A2xH2"
    assert not _admit(t, ceiling="A2xH2").narrowed


def test_every_lattice_cell_survives_a_round_trip():
    from trust.tiers import AgentTier, HumanTier, resolve
    for a in AgentTier:
        for h in HumanTier:
            cell = resolve(a, h).cell
            assert canonical_tier(cell) == cell, \
                f"the lattice cell {cell!r} is not what delegation produces"


# ── who signed it ──────────────────────────────────────────────────────────

def test_a_ticket_from_a_stranger_is_refused():
    """The premise: a stranger's assertion about an agent nobody here verified."""
    _, _, t = _ticketed()
    d = _admit(t, peer=False)
    assert not d.admitted
    assert any("not a verified peer" in p for p in d.problems)


def test_a_ticket_not_signed_by_the_node_it_names_is_refused():
    _need_eth()
    from federation.identity import node_id_from_address
    impostor = Account.create()
    victim_id = node_id_from_address(Account.create().address)
    t = mint(impostor.key.hex(), origin_node=victim_id,
             origin_domain="dc1.internal", audience="dc2.internal",
             agent_id=1, chain_id=8453, footprint="0x" + "ab" * 32,
             asserted_tier="A2xH2", scope="s", task=TASK)
    d = _admit(t)
    assert not d.admitted
    assert any("not signed by the node it claims" in p for p in d.problems)


def test_an_unsigned_ticket_is_refused():
    _, _, t = _ticketed()
    t.signature = ""
    assert any("unsigned" in p for p in _admit(t).problems)


def test_a_tampered_ticket_is_refused():
    _, _, t = _ticketed(tier="A0xH0")
    for field, value in (("asserted_tier", "A2xH2"), ("agent_id", 99),
                         ("scope", "a2a:delegate/elsewhere"),
                         ("audience", "dc9.internal"), ("max_hops", 99),
                         ("task", task_digest({"job": "exfiltrate"})),
                         ("footprint", "0x" + "cd" * 32)):
        bad = DelegationTicket.from_dict(t.to_dict())
        setattr(bad, field, value)
        d = _admit(bad, audience=bad.audience)
        assert not d.admitted, f"tampering with {field} was not detected"


def test_rewriting_the_path_is_detected():
    """
    The path is signed, not just its length. A hop that could rewrite history
    would hide where a delegation had been, and the loop check is only as good
    as the path it reads.
    """
    _, _, t = _ticketed()
    bad = DelegationTicket.from_dict(t.to_dict())
    bad.hops = [DelegationHop(node_id="0x" + "11" * 32, domain="dc9.internal")]
    assert not _admit(bad).admitted


def test_extending_a_ticket_leaves_it_unsigned():
    """
    A path is only trustworthy if each entry was signed by the node that added
    it, so extend() deliberately returns an unsigned ticket. A caller that
    appends and forwards produces something admit() refuses.
    """
    _, _, t = _ticketed()
    onward = extend(t, node_id="0x" + "22" * 32, domain="dc2.internal")
    assert onward.depth == t.depth + 1
    assert onward.signature == ""
    assert not _admit(onward).admitted


# ── what a ticket is for ───────────────────────────────────────────────────

def test_a_ticket_authorises_one_task_not_a_shape_of_task():
    _, _, t = _ticketed(task=TASK)
    assert _admit(t, task=TASK).admitted
    d = _admit(t, task={"job": "exfiltrate", "doc": "q3-report.pdf"})
    assert not d.admitted
    assert any("not the task the ticket authorises" in p for p in d.problems)


def test_the_task_digest_is_canonical_not_byte_wise():
    """
    Two honest parties may serialise the same object differently. A digest over
    whichever bytes arrived would fail for them while a canonical one fails
    only for a changed task.
    """
    assert task_digest({"a": 1, "b": 2}) == task_digest({"b": 2, "a": 1})
    assert task_digest({"a": 1}) != task_digest({"a": 2})
    assert task_digest(None) == task_digest({})


def test_a_ticket_is_bound_to_one_destination():
    _, _, t = _ticketed(audience="dc2.internal")
    assert _admit(t, audience="dc2.internal").admitted
    d = _admit(t, audience="dc3.internal")
    assert not d.admitted
    assert any("different destination" in p for p in d.problems)


def test_a_ticket_expires():
    _, _, t = _ticketed()
    d = _admit(t, now=int(time.time()) + 3600)
    assert not d.admitted and any("expired" in p for p in d.problems)


def test_an_origin_cannot_mint_an_unbounded_ticket():
    _, _, t = _ticketed(ttl=86400)
    d = _admit(t)
    assert any("does not bound replay" in p for p in d.problems), d.problems


def test_a_ticket_must_name_a_destination():
    _need_eth()
    origin = Account.create()
    _refuses(DelegationError, mint, origin.key.hex(), origin_node="0x" + "11" * 32,
             origin_domain="dc1", audience="  ", agent_id=1, chain_id=1,
             footprint="0x" + "ab" * 32, asserted_tier="A0xH0", scope="s",
             task=TASK)


# ── bounds ─────────────────────────────────────────────────────────────────

def test_the_hop_budget_is_the_originators_and_no_hop_can_raise_it():
    _, origin_id, t = _ticketed(max_hops=1)
    assert _admit(t).admitted
    onward = extend(t, node_id=_dest_id(), domain="dc2.internal")
    d = admit(onward, audience="dc2.internal", self_node_id=_dest_id(),
              task=TASK, origin_is_peer=True)
    assert any("budget exhausted" in p for p in d.problems), d.problems


def test_a_loop_is_refused():
    """
    A cycle would let two datacentres pass a delegation back and forth until
    the budget ran out, each believing the other had checked it.
    """
    _, origin_id, t = _ticketed()
    d = _admit(t, self_id=origin_id)
    assert not d.admitted
    assert any("refusing a loop" in p for p in d.problems)


def test_a_node_already_on_the_path_is_refused():
    mid = _dest_id()
    _, _, t = _ticketed(hops=[DelegationHop(node_id=mid, domain="dc2.internal")])
    assert any("refusing a loop" in p for p in _admit(t, self_id=mid).problems)


def test_max_hops_below_one_is_refused():
    _need_eth()
    origin = Account.create()
    _refuses(DelegationError, mint, origin.key.hex(),
             origin_node="0x" + "11" * 32, origin_domain="dc1",
             audience="dc2", agent_id=1, chain_id=1,
             footprint="0x" + "ab" * 32, asserted_tier="A0xH0", scope="s",
             task=TASK, max_hops=0)


# ── clusters ───────────────────────────────────────────────────────────────

def test_a_closed_cluster_refuses_a_non_member_origin():
    _, _, t = _ticketed(cluster="0x" + "aa" * 32)
    d = _admit(t, cluster=False, expected_cluster="0x" + "aa" * 32)
    assert not d.admitted
    assert any("not a member" in p for p in d.problems)


def test_a_ticket_naming_another_cluster_is_refused():
    _, _, t = _ticketed(cluster="0x" + "aa" * 32)
    d = _admit(t, cluster=True, expected_cluster="0x" + "bb" * 32)
    assert not d.admitted
    assert any("different cluster" in p for p in d.problems)


def test_membership_is_not_a_condition_outside_a_closed_cluster():
    _, _, t = _ticketed()
    assert _admit(t, cluster=None).admitted


# ── diagnostics ────────────────────────────────────────────────────────────

def test_a_refused_ticket_still_reports_what_it_would_have_been_granted():
    """An operator reading an audit line needs to see the tier, or a refusal
    tells them nothing about whether the ceiling is the problem."""
    _, _, t = _ticketed(tier="A2xH2")
    d = _admit(t, peer=False, ceiling="A1xH1")
    assert not d.admitted
    assert d.effective_tier == "A1xH1"


def test_all_problems_are_reported_not_just_the_first():
    """A ticket wrong in three ways should say so once, rather than three
    round trips of fixing one thing at a time."""
    _, _, t = _ticketed(audience="dc9.internal")
    d = _admit(t, audience="dc2.internal", peer=False,
               task={"job": "other"})
    assert len(d.problems) >= 3, d.problems


# ── end to end: two real gateways ──────────────────────────────────────────

ORIGIN_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
DEST_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"


class _node:
    """A gateway on loopback with a node identity, for delegation over HTTP."""

    def __init__(self, port: int, key: str, domain: str, **env) -> None:
        self.port, self.key, self.domain, self.extra = port, key, domain, env

    def __enter__(self):
        import urllib.request
        env = {**os.environ,
               "XCP_PROFILE": "development", "XCP_POSTURE": "enforce",
               "XCP_VERIFY_URL": "", "XCP_RATE_LIMIT": "1",
               "XCP_GLOBAL_RATE": "500000",
               "XCP_ADMIN_TOKEN": "dele-test-token",
               # Loopback over plain HTTP is refused by the egress guard,
               # which is correct in production and has to be opted out of to
               # peer two gateways on one machine.
               "XCP_ALLOW_INSECURE_PEERS": "1",
               "XCP_NODE_KEY": self.key, "XCP_NODE_DOMAIN": self.domain,
               "XCP_NODE_URL": f"http://127.0.0.1:{self.port}",
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

    def delegate(self, *, peer_did: str = "did:8004:8453:0xAGENTB",
                 destination: str = "", task=None, tier: str = "A2xH2"):
        """
        Delegate through the real session and mandate path.

        /v1/a2a/delegate requires a verified session and a mandate covering the
        scope, like any governed action -- minting a cross-boundary ticket is
        not a side door around the gate. So this drives the same client the
        demo does rather than hand-rolling headers, which would test a path no
        caller actually takes.
        """
        sys.path.insert(0, str(ROOT / "core" / "client" / "python"))
        from xcp_client import AgentIdentity, XCPClient, XCPError, sign_mandate
        # A well-known Anvil/Hardhat test key -- never used in production.
        agent_key = ("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7"
                     "a8412f4603b6b78690d")
        ident = AgentIdentity(agent_id=42001, chain_id=8453,
                              private_key=agent_key)
        # A high tier at the ORIGIN, so narrowing at the destination is
        # observable rather than a no-op: an A0xH0 agent is already at the
        # floor and no ceiling could narrow it.
        client = XCPClient(f"http://127.0.0.1:{self.port}", ident, tier=tier)
        client.connect()
        scope = f"a2a:delegate/{peer_did}"
        mandate = sign_mandate(agent_key, "m-a2a", ident.address, [scope],
                               int(time.time()) + 3600)
        try:
            return 200, client.delegate(peer_did, task, mandate=mandate,
                                        destination=destination)
        except XCPError as e:
            return 0, {"error": str(e)}

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

    def __exit__(self, *exc) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _peer_them(a: "_node", b: "_node") -> None:
    """
    Peer a and b with each other, in BOTH directions.

    Peering is directional: `a` fetching and verifying `b`'s record makes b a
    peer of a and says nothing about what b knows. The destination is the one
    that checks whether a ticket's origin is a peer, so a one-way peering
    leaves delegation refused with "the originating node is not a verified
    peer" -- correct, and a real deployment fact: both ends must peer before
    work can cross the boundary.
    """
    for src, dst in ((a, b), (b, a)):
        status, res = src.post("/v1/federation/peer",
                               {"domain": dst.domain,
                                "gatewayUrl": f"http://127.0.0.1:{dst.port}"})
        assert status == 200, \
            f"peering {src.domain} -> {dst.domain} failed: {status} {res}"


def _deliver(ceiling: str = "A2xH2", *, accept: str = "1",
             peer_first: bool = True):
    """Run a delegation from dc1 to dc2 and return dc1's response."""
    _need_eth()
    with _node(8751, ORIGIN_KEY, "dc1.internal",
               XCP_UPSTREAMS='{"research":"http://127.0.0.1:9999/mcp"}') as a:
        with _node(8752, DEST_KEY, "dc2.internal", XCP_A2A_ACCEPT=accept,
                   XCP_A2A_TIER_CEILING=ceiling) as b:
            if peer_first:
                _peer_them(a, b)
            return a.delegate(destination="dc2.internal", task=TASK)


def test_a_delegation_crosses_a_real_boundary_and_is_delivered():
    """
    The capability. Not that the delegation was authorised -- that already
    worked -- but that a second gateway authenticated it independently and
    answered.
    """
    status, res = _deliver()
    assert status == 200, f"{status} {res}"
    assert res.get("authorized") is True
    assert res.get("delivered") is True, \
        f"nothing was delivered: {res.get('destinationDecision')}"
    d = res.get("destinationDecision") or {}
    assert d.get("admitted") is True, d
    assert d.get("effectiveTier"), d


def test_the_destination_narrows_what_the_origin_asserted():
    """
    The origin says what it verified; the destination decides what that is
    worth here. End to end, over HTTP, between two processes.
    """
    status, res = _deliver(ceiling="A0xH0")
    assert status == 200, f"{status} {res}"
    d = res.get("destinationDecision") or {}
    assert d.get("admitted") is True, d
    assert d.get("effectiveTier") == "A0xH0", d
    assert d.get("narrowed") is True, d
    assert d.get("ceiling") == "A0xH0", d


def test_a_destination_that_does_not_accept_delegations_says_so():
    """Off by default: executing work on another datacentre's say-so is an
    operator's decision, not something inherited from an upgrade."""
    status, res = _deliver(accept="0")
    assert status == 200
    assert res.get("delivered") is True, \
        "a refusal we heard is still a delivery"
    assert "does not accept" in str(res.get("destinationDecision")), res


def test_delegating_to_a_node_that_is_not_a_peer_is_not_delivered():
    status, res = _deliver(peer_first=False)
    assert status == 200
    assert res.get("delivered") is False
    assert "not a peer" in str(res.get("destinationDecision")), res


def test_delegating_with_no_destination_claims_nothing():
    """The original behaviour, preserved: a caller may authorise a delegation
    it will carry itself, and the response must not imply delivery."""
    _need_eth()
    with _node(8751, ORIGIN_KEY, "dc1.internal") as a:
        status, res = a.delegate(task=TASK)
    assert status == 200, f"{status} {res}"
    assert res.get("authorized") is True and res.get("delivered") is False
    assert "nothing was delivered" in res.get("note", "")


def test_a_ticket_minted_for_one_node_is_refused_by_another():
    """
    Lateral replay, end to end. The ticket dc1 minted for dc2 is presented
    directly to a third node, which refuses it on the audience.
    """
    _need_eth()
    with _node(8751, ORIGIN_KEY, "dc1.internal") as a:
        with _node(8752, DEST_KEY, "dc2.internal", XCP_A2A_ACCEPT="1") as b:
            _peer_them(a, b)
            _, res = a.delegate(destination="dc2.internal", task=TASK)
            ticket = res.get("ticket")
            assert ticket, res
        # dc3 holds the same identity as dc2 for the sake of the test but a
        # different domain, so only the audience differs.
        with _node(8753, DEST_KEY, "dc3.internal", XCP_A2A_ACCEPT="1") as c:
            status, out = c.post("/v1/a2a/accept",
                                 {"ticket": ticket, "task": TASK})
    assert status == 403, f"a ticket for dc2 was redeemed at dc3: {out}"
    assert any("different destination" in p for p in out.get("problems", [])), out


def test_the_accept_endpoint_refuses_a_malformed_ticket():
    _need_eth()
    with _node(8752, DEST_KEY, "dc2.internal", XCP_A2A_ACCEPT="1") as b:
        status, out = b.post("/v1/a2a/accept", {"ticket": {"nonsense": True}})
    assert status in (400, 403), out
    assert out.get("admitted") is False


def test_the_gateway_asserts_the_verified_tier_not_a_claimed_one():
    """
    The ticket's assertedTier must come from the session binding, not from
    anything the caller said about itself — otherwise a caller mints its own
    authority by asking for it.
    """
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("def _mint_ticket(")
    j = src.index("async def _deliver_ticket(", i)
    body = src[i:j]
    assert 'getattr(ctx.binding, "tier"' in body, \
        "the asserted tier does not come from the verified binding"
    assert "body.get(" not in body, \
        "the ticket reads something from the request body as authority"


def test_the_accept_path_checks_the_charter_this_node_holds():
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("async def a2a_accept(")
    j = src.find("@app.", i)
    body = src[i:j if j > 0 else len(src)]
    assert "_CLUSTER.charter.cluster_id" in body
    assert "A2A_TIER_CEILING" in body, "the destination's ceiling is not applied"
    assert "_PeerTrust.VERIFIED" in body, \
        "the origin's trust level is not checked"


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
