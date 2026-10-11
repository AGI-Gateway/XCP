"""
test_cluster.py — private cluster membership, with no chain involved.

WHAT THIS FILE IS ABOUT
-----------------------
Clusters existed only in NodeRegistry.sol. `NodeRecord.cluster_id` said so in a
comment that was also an admission -- "membership root is on-chain, roster is
not" -- so an organisation federating three of its own datacentres could not use
clusters without deploying and paying for a contract.

federation/cluster.py is the off-chain equivalent. Most of what follows tests
the two properties that make it worth having rather than the happy path:

  · the root commits to the member set WITHOUT publishing it, including for a
    one-member cluster, where a plain Merkle root would simply BE the member's
    node id;
  · removal works by re-issuing at a higher epoch, so a removed node's still
    perfectly valid proof stops verifying against the root its former peers
    hold -- with no revocation list and nothing to wait out.

And one compatibility property, asserted rather than claimed: the root is the
same root NodeRegistry.verifyMembership computes, so an organisation can run
privately now and anchor the identical charter on-chain later.

    python tests/test_cluster.py
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

from federation.cluster import (                                  # noqa: E402
    AUTHORITY_ENV, CHARTER_ENV, CLAIM_ENV, MIN_EPOCH_ENV, MIN_LEAVES,
    ClusterCharter, ClusterError, MemberSet, MembershipClaim, build_member_set,
    cluster_id_from_name, digest, issue_claim, load_posture, membership_proof,
    membership_root, sign_charter, verify_charter, verify_member,
    verify_membership_proof)

try:
    from eth_account import Account
    _ETH = True
except ImportError:                                              # pragma: no cover
    _ETH = False


class _Skipped(Exception):
    """Standalone-runner skip. Reported as a skip, not a pass or a failure."""


def _skip(reason: str) -> None:
    if "pytest" in sys.modules:
        import pytest
        pytest.skip(reason)
    raise _Skipped(reason)


def _need_eth() -> None:
    if not _ETH:
        _skip("eth-account required to sign charters")


def _refuses(exc, fn, *a, **kw) -> str:
    try:
        fn(*a, **kw)
    except exc as e:
        return str(e)
    raise AssertionError(f"{getattr(fn, '__name__', fn)} did not raise "
                         f"{exc.__name__}")


CID = cluster_id_from_name("acme-internal")


def _ids(n: int) -> list[str]:
    return ["0x" + ("%02x" % (i + 1)) * 32 for i in range(n)]


def _cluster(n: int = 3, *, epoch: int = 1, open: bool = False):
    """An authority, a member set and a signed charter."""
    _need_eth()
    auth = Account.create()
    ms = build_member_set(CID, _ids(n))
    charter = sign_charter(auth.key.hex(), ms, epoch=epoch, open=open)
    return auth, ms, charter


# ── a root, never a roster ─────────────────────────────────────────────────

def test_the_charter_carries_no_member_ids():
    """
    The whole construction. Asserted on the serialised charter rather than left
    to review, because this is the property an operator is trusting when they
    hand the same file to every node.
    """
    _, ms, charter = _cluster(3)
    blob = charter.to_json()
    for node_id in ms.node_ids:
        assert node_id[2:] not in blob, "the charter published a member id"
    for pad in ms.pads:
        assert pad[2:] not in blob, "the charter published a pad leaf"
    # Asserted on the parsed key set, not on substrings: "membership_root"
    # contains the substring "members", and a grep-shaped test here would have
    # failed for that rather than for anything real.
    assert set(json.loads(blob)) == {
        "cluster_id", "membership_root", "policy_hash", "epoch", "not_before",
        "not_after", "authority", "open", "spec_version", "signature"}, \
        "the charter grew a field — check it is not a roster"


def test_a_one_member_cluster_root_is_not_that_member():
    """
    A Merkle root over a single leaf IS that leaf, so a one-member cluster
    would publish its only member's node id as the root -- the roster, in the
    field that exists to avoid publishing it. The tree is padded instead.
    """
    only = _ids(1)[0]
    ms = build_member_set(CID, [only])
    assert ms.root.lower() != only.lower()
    assert len(ms.leaves) >= MIN_LEAVES
    assert len(ms.pads) == 1
    # and the member still proves membership
    assert verify_membership_proof(only, ms.proof_for(only), ms.root)


def test_the_pad_leaf_is_indistinguishable_from_a_member():
    """If pads were structured, the tree's shape would leak the real count."""
    ms = build_member_set(CID, _ids(1))
    pad = ms.pads[0]
    assert pad.startswith("0x") and len(pad) == 66
    assert pad not in ms.node_ids


def test_every_member_proves_membership():
    _, ms, charter = _cluster(5)
    for node_id in ms.node_ids:
        claim = issue_claim(ms, node_id, epoch=charter.epoch)
        assert verify_member(charter, claim, expected_node_id=node_id) == []


def test_a_non_member_cannot_prove_membership():
    _, ms, charter = _cluster(3)
    outsider = "0xee" + "ee" * 31
    _refuses(ClusterError, issue_claim, ms, outsider, 1)


def test_a_member_cannot_present_another_members_claim():
    """
    Otherwise a non-member replays any member's claim and is admitted as them.
    The claim has to be about the node that presented it.
    """
    _, ms, charter = _cluster(3)
    a, b = ms.node_ids[0], ms.node_ids[1]
    claim_a = issue_claim(ms, a, epoch=1)
    problems = verify_member(charter, claim_a, expected_node_id=b)
    assert problems and "different node" in problems[0]


def test_an_invented_proof_does_not_verify():
    _, ms, charter = _cluster(4)
    forged = MembershipClaim(cluster_id=CID, node_id=ms.node_ids[0], epoch=1,
                             proof=[ms.node_ids[1], ms.node_ids[2]])
    assert verify_member(charter, forged, expected_node_id=ms.node_ids[0])


def test_a_claim_for_another_cluster_is_refused():
    _, ms, charter = _cluster(3)
    claim = issue_claim(ms, ms.node_ids[0], epoch=1)
    claim.cluster_id = cluster_id_from_name("someone-else")
    problems = verify_member(charter, claim, expected_node_id=ms.node_ids[0])
    assert problems and "different cluster" in problems[0]


def test_a_malformed_member_id_is_refused():
    for bad in ("", "0x", "nothex", "0x1234", "1" * 64):
        _refuses(ClusterError, build_member_set, CID, [bad])


def test_duplicate_members_are_refused():
    dup = _ids(1) * 2
    _refuses(ClusterError, build_member_set, CID, dup)


def test_an_empty_cluster_is_refused():
    _refuses(ClusterError, build_member_set, CID, [])
    _refuses(ClusterError, membership_root, [])


# ── removal ────────────────────────────────────────────────────────────────

def test_removal_takes_effect_without_a_revocation_list():
    """
    The reason this design is worth having. The removed node keeps a proof that
    is still internally valid; it simply no longer verifies against the root
    its former peers hold. Nothing is distributed, nothing expires.
    """
    auth, ms, _ = _cluster(3)
    gone = ms.node_ids[0]
    old_claim = issue_claim(ms, gone, epoch=1)

    ms2 = build_member_set(CID, ms.node_ids[1:])
    charter2 = sign_charter(auth.key.hex(), ms2, epoch=2)

    assert verify_member(charter2, old_claim, expected_node_id=gone)
    # and the members who remain are undisturbed
    for node_id in ms2.node_ids:
        assert verify_member(charter2, issue_claim(ms2, node_id, epoch=2),
                             expected_node_id=node_id) == []


def test_lying_about_the_epoch_does_not_restore_membership():
    """
    The epoch check is a clear diagnostic, not the defence. A removed node that
    claims the current epoch is still refused, by the proof.
    """
    auth, ms, _ = _cluster(3)
    gone = ms.node_ids[0]
    old_proof = issue_claim(ms, gone, epoch=1).proof

    ms2 = build_member_set(CID, ms.node_ids[1:])
    charter2 = sign_charter(auth.key.hex(), ms2, epoch=2)

    forged = MembershipClaim(cluster_id=CID, node_id=gone, epoch=2,
                             proof=old_proof)
    problems = verify_member(charter2, forged, expected_node_id=gone)
    assert problems and "does not verify" in problems[0], \
        f"the epoch check was the only thing stopping this: {problems}"


def test_a_stale_epoch_says_why():
    """A diagnostic worth having: 'the member set has changed' is actionable,
    'proof does not verify' on its own is not."""
    auth, ms, _ = _cluster(3)
    claim = issue_claim(ms, ms.node_ids[0], epoch=1)
    charter2 = sign_charter(auth.key.hex(), ms, epoch=7)
    problems = verify_member(charter2, claim,
                             expected_node_id=ms.node_ids[0])
    assert problems and "epoch" in problems[0]


def test_a_rolled_back_charter_is_refused_under_a_pinned_floor():
    """
    Raising the epoch is how removal takes effect, so reinstating an older
    charter file would re-admit a removed node. An operator pins the floor.
    """
    auth, ms, charter1 = _cluster(3, epoch=1)
    assert verify_charter(charter1, expected_authority=auth.address,
                          min_epoch=1) == []
    problems = verify_charter(charter1, expected_authority=auth.address,
                              min_epoch=2)
    assert problems and "rolled-back" in problems[0]


# ── the charter is a signed statement ──────────────────────────────────────

def test_a_charter_verifies_against_its_authority():
    auth, _, charter = _cluster(3)
    assert verify_charter(charter, expected_cluster_id=CID,
                          expected_authority=auth.address) == []


def test_a_charter_from_another_authority_is_refused():
    """
    Without this, anyone mints a charter naming any cluster id and a node that
    merely checks the signature verifies it happily.
    """
    _need_eth()
    impostor = Account.create()
    ms = build_member_set(CID, _ids(2))
    forged = sign_charter(impostor.key.hex(), ms, epoch=1)
    problems = verify_charter(forged, expected_authority=Account.create().address)
    assert problems and "not the expected authority" in problems[0]
    # the signature itself is perfectly good — that is the point
    assert verify_charter(forged, expected_authority=impostor.address) == []


def test_a_tampered_charter_is_refused():
    auth, ms, charter = _cluster(3)
    for field, value in (("membership_root", "0x" + "ab" * 32),
                         ("epoch", 99), ("open", True),
                         ("cluster_id", cluster_id_from_name("other")),
                         ("policy_hash", "0x" + "cd" * 32)):
        bad = ClusterCharter.from_dict(charter.to_dict())
        setattr(bad, field, value)
        problems = verify_charter(bad, expected_authority=auth.address)
        assert problems, f"tampering with {field} was not detected"


def test_an_unsigned_charter_is_refused():
    auth, ms, charter = _cluster(3)
    charter.signature = ""
    problems = verify_charter(charter, expected_authority=auth.address)
    assert problems and "unsigned" in problems[0]


def test_a_malformed_signature_is_refused():
    auth, _, charter = _cluster(3)
    charter.signature = "0xdeadbeef"
    assert verify_charter(charter, expected_authority=auth.address)


def test_an_expired_charter_is_not_a_membership_statement():
    _need_eth()
    auth = Account.create()
    ms = build_member_set(CID, _ids(2))
    old = sign_charter(auth.key.hex(), ms, epoch=1, ttl=60,
                       now=int(time.time()) - 3600)
    problems = verify_charter(old, expected_authority=auth.address)
    assert problems and "expired" in problems[0]


def test_an_epoch_below_one_is_refused():
    _need_eth()
    auth = Account.create()
    ms = build_member_set(CID, _ids(2))
    _refuses(ClusterError, sign_charter, auth.key.hex(), ms, epoch=0)


def test_a_charter_round_trips_through_json():
    auth, _, charter = _cluster(3)
    revived = ClusterCharter.from_dict(json.loads(charter.to_json()))
    assert revived == charter
    assert verify_charter(revived, expected_authority=auth.address) == []


def test_a_charter_missing_required_fields_is_refused():
    _refuses(ClusterError, ClusterCharter.from_dict, {"clusterId": CID})


def test_a_malformed_claim_is_refused():
    for bad in ({}, {"clusterId": CID}, {"clusterId": CID, "nodeId": "0x1"},
                "not-an-object"):
        _refuses(ClusterError, MembershipClaim.from_dict, bad)


def test_the_cluster_id_is_derived_so_two_sites_agree():
    """Configured independently from the same name, two datacentres must arrive
    at the same id — otherwise they are silently in different clusters."""
    assert cluster_id_from_name("acme-internal") == \
           cluster_id_from_name("  ACME-Internal  ")
    assert cluster_id_from_name("a") != cluster_id_from_name("b")
    _refuses(ClusterError, cluster_id_from_name, "   ")


# ── open clusters ──────────────────────────────────────────────────────────

def test_an_open_cluster_makes_membership_advisory():
    """Matches NodeRegistry's `open` flag: the public-federation case, where a
    cluster is a label rather than a gate."""
    _, _, closed = _cluster(3, open=False)
    _, _, opened = _cluster(3, open=True)
    from federation.cluster import ClusterPosture
    assert ClusterPosture(charter=closed).closed
    assert not ClusterPosture(charter=opened).closed
    assert not ClusterPosture().closed and not ClusterPosture().configured


# ── the root is the on-chain root ──────────────────────────────────────────

def _solidity_verify(node_id: str, proof: list[str], root: str) -> bool:
    """
    A transcription of NodeRegistry.verifyMembership's loop:

        bytes32 h = nodeId;
        for (uint256 i = 0; i < proof.length; i++) {
            h = h < proof[i] ? keccak256(abi.encodePacked(h, proof[i]))
                             : keccak256(abi.encodePacked(proof[i], h));
        }
        return h == c.membershipRoot;

    Written out independently rather than calling the module under test, so
    this is a differential check between two implementations and not a tautology.
    """
    h = bytes.fromhex(node_id[2:])
    for p in proof:
        q = bytes.fromhex(p[2:])
        lo, hi = (h, q) if h < q else (q, h)
        h = bytes.fromhex(digest(lo + hi)[2:])
    return "0x" + h.hex() == root.lower()


def test_the_off_chain_root_is_the_on_chain_root():
    """
    The migration story, asserted rather than claimed: an organisation can
    federate privately now and anchor the identical charter root with
    upsertCluster later, and the proofs issued here verify unchanged.
    """
    for n in (1, 2, 3, 4, 5, 8, 9, 17):
        ms = build_member_set(CID, _ids(n))
        for node_id in ms.node_ids:
            proof = ms.proof_for(node_id)
            assert verify_membership_proof(node_id, proof, ms.root), \
                f"off-chain verification failed at n={n}"
            assert _solidity_verify(node_id, proof, ms.root), \
                f"the Solidity loop disagrees at n={n} — an anchored root " \
                f"would reject proofs issued off-chain"


def test_the_two_merkle_implementations_in_the_tree_agree():
    """
    cluster.py reimplements the tree rather than importing federation.transport,
    so that a change made for billing cannot silently change who is a member.
    Deliberate duplication needs a test that they have not drifted.
    """
    from federation.transport import merkle_root as transport_root
    for n in (2, 3, 5, 8):
        leaves = _ids(n)
        assert membership_root(leaves) == transport_root(leaves), \
            f"the membership and receipt trees disagree at n={n}"


def test_a_proof_is_shorter_than_the_roster():
    """The point of a Merkle proof: verification cost is logarithmic, so a
    large cluster does not mean a large record."""
    ms = build_member_set(CID, _ids(64))
    assert len(ms.proof_for(ms.node_ids[0])) <= 7


# ── what a node loads ──────────────────────────────────────────────────────

class _configured:
    """A charter and claim on disk, with the environment pointing at them."""

    def __init__(self, *, members: int = 3, epoch: int = 1, open: bool = False,
                 authority: str = "", min_epoch: str = "", claim_for: int = 0,
                 write_claim: bool = True) -> None:
        self.kw = dict(members=members, epoch=epoch, open=open,
                       authority=authority, min_epoch=min_epoch,
                       claim_for=claim_for, write_claim=write_claim)

    def __enter__(self):
        _need_eth()
        self.tmp = Path(tempfile.mkdtemp())
        self.auth = Account.create()
        self.ms = build_member_set(CID, _ids(self.kw["members"]))
        self.charter = sign_charter(self.auth.key.hex(), self.ms,
                                    epoch=self.kw["epoch"],
                                    open=self.kw["open"])
        (self.tmp / "charter.json").write_text(self.charter.to_json())
        if self.kw["write_claim"]:
            claim = issue_claim(self.ms, self.ms.node_ids[self.kw["claim_for"]],
                                epoch=self.kw["epoch"])
            (self.tmp / "claim.json").write_text(
                json.dumps(claim.to_dict()) + "\n")
        self._prior = {k: os.environ.get(k) for k in
                       (CHARTER_ENV, CLAIM_ENV, AUTHORITY_ENV, MIN_EPOCH_ENV)}
        os.environ[CHARTER_ENV] = str(self.tmp / "charter.json")
        if self.kw["write_claim"]:
            os.environ[CLAIM_ENV] = str(self.tmp / "claim.json")
        else:
            os.environ.pop(CLAIM_ENV, None)
        os.environ[AUTHORITY_ENV] = self.kw["authority"] or self.auth.address
        if self.kw["min_epoch"]:
            os.environ[MIN_EPOCH_ENV] = self.kw["min_epoch"]
        else:
            os.environ.pop(MIN_EPOCH_ENV, None)
        return self

    def __exit__(self, *exc) -> None:
        for k, v in self._prior.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)


def test_a_node_loads_a_valid_charter_and_its_own_claim():
    with _configured() as c:
        posture = load_posture()
    assert posture.configured and posture.closed
    assert posture.charter.cluster_id == CID
    assert posture.claim is not None


def test_an_unconfigured_node_has_no_cluster():
    for k in (CHARTER_ENV, CLAIM_ENV, AUTHORITY_ENV, MIN_EPOCH_ENV):
        os.environ.pop(k, None)
    posture = load_posture()
    assert not posture.configured and not posture.closed


def test_a_charter_from_the_wrong_authority_stops_the_node():
    _need_eth()
    with _configured(authority=Account.create().address):
        msg = _refuses(ClusterError, load_posture)
    assert "authority" in msg


def test_a_missing_charter_file_stops_the_node():
    os.environ[CHARTER_ENV] = "/nonexistent/charter.json"
    try:
        assert "readable" in _refuses(ClusterError, load_posture)
    finally:
        os.environ.pop(CHARTER_ENV, None)


def test_a_charter_that_is_not_json_stops_the_node():
    tmp = Path(tempfile.mkdtemp())
    try:
        bad = tmp / "charter.json"
        bad.write_text("this is not a charter")
        os.environ[CHARTER_ENV] = str(bad)
        _refuses(ClusterError, load_posture)
    finally:
        os.environ.pop(CHARTER_ENV, None)
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_rolled_back_charter_stops_the_node_when_the_floor_is_pinned():
    with _configured(epoch=1, min_epoch="3"):
        assert "rolled-back" in _refuses(ClusterError, load_posture)


def test_a_claim_that_does_not_verify_stops_the_node():
    """
    A node that cannot prove its own membership cannot expect peers to accept
    it, so it says so at startup rather than failing peer by peer later.
    """
    with _configured() as c:
        claim = json.loads((c.tmp / "claim.json").read_text())
        claim["proof"] = ["0x" + "99" * 32]
        (c.tmp / "claim.json").write_text(json.dumps(claim))
        assert "own membership" in _refuses(ClusterError, load_posture)


def test_a_charter_without_a_claim_still_loads():
    """A node may verify peers without itself being a member — a hub that
    gates a cluster it does not belong to."""
    with _configured(write_claim=False):
        posture = load_posture()
    assert posture.configured and posture.claim is None


def test_the_posture_summary_never_carries_the_root():
    """
    /health is unauthenticated. The root is a commitment to the member set, so
    it belongs behind the admin token with everything else that maps the
    organisation.
    """
    with _configured() as c:
        posture = load_posture()
    blob = json.dumps(posture.summary())
    assert posture.charter.membership_root[2:] not in blob
    assert "proof" not in blob
    assert posture.charter.cluster_id in blob     # the id itself is fine
    # the admin view does carry it, which is the point of gating that endpoint
    assert posture.charter.membership_root[2:] in json.dumps(posture.detail())


# ── the authority's CLI ────────────────────────────────────────────────────

def _run_cli(*args, key: str = "") -> subprocess.CompletedProcess:
    env = {**os.environ}
    env["PYTHONPATH"] = str(ROOT)
    if key:
        env["XCP_CLUSTER_AUTHORITY_KEY"] = key
    else:
        env.pop("XCP_CLUSTER_AUTHORITY_KEY", None)
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "cluster-charter.py"), *args],
        capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))


def test_the_cli_issues_a_distributable_charter_and_per_member_proofs():
    _need_eth()
    auth = Account.create()
    tmp = Path(tempfile.mkdtemp())
    try:
        ids = _ids(3)
        r = _run_cli("issue", "--name", "acme-internal", "--epoch", "1",
                     "--out", str(tmp), *sum([["--member", i] for i in ids], []),
                     key=auth.key.hex())
        assert r.returncode == 0, r.stdout + r.stderr
        charter = ClusterCharter.from_dict(json.loads(
            (tmp / "charter.json").read_text()))
        assert verify_charter(charter, expected_authority=auth.address) == []
        for node_id in ids:
            p = tmp / f"membership-{node_id[2:14]}.json"
            assert p.is_file(), f"no proof issued for {node_id}"
            claim = MembershipClaim.from_dict(json.loads(p.read_text()))
            assert verify_member(charter, claim,
                                 expected_node_id=node_id) == []
        # members.json is the roster and must stay with the authority
        roster = MemberSet.from_dict(json.loads((tmp / "members.json").read_text()))
        assert sorted(roster.node_ids) == sorted(ids)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_the_cli_refuses_to_run_without_the_authority_key():
    r = _run_cli("issue", "--name", "x", "--epoch", "1",
                 "--member", _ids(1)[0], "--out", "/tmp/nope")
    assert r.returncode != 0
    assert "XCP_CLUSTER_AUTHORITY_KEY" in r.stdout + r.stderr


def test_the_cli_keeps_the_root_stable_when_the_member_set_is_unchanged():
    """
    Re-issuing to bump a policy hash must not mint a fresh pad leaf, change the
    root and invalidate every member's proof for no reason anyone asked for.
    """
    _need_eth()
    auth = Account.create()
    tmp = Path(tempfile.mkdtemp())
    try:
        one = _ids(1)[0]
        a = _run_cli("issue", "--name", "solo", "--epoch", "1", "--member", one,
                     "--out", str(tmp), key=auth.key.hex())
        assert a.returncode == 0, a.stdout + a.stderr
        root1 = json.loads((tmp / "charter.json").read_text())["membership_root"]
        b = _run_cli("issue", "--name", "solo", "--epoch", "2", "--member", one,
                     "--out", str(tmp), "--members-in", str(tmp / "members.json"),
                     key=auth.key.hex())
        assert b.returncode == 0, b.stdout + b.stderr
        root2 = json.loads((tmp / "charter.json").read_text())["membership_root"]
        assert root1 == root2, "re-issuing changed the root and broke every proof"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_the_cli_verifies_what_it_issued():
    _need_eth()
    auth = Account.create()
    tmp = Path(tempfile.mkdtemp())
    try:
        ids = _ids(2)
        _run_cli("issue", "--name", "acme-internal", "--epoch", "1",
                 "--out", str(tmp), *sum([["--member", i] for i in ids], []),
                 key=auth.key.hex())
        r = _run_cli("verify", "--charter", str(tmp / "charter.json"),
                     "--membership", str(tmp / f"membership-{ids[0][2:14]}.json"),
                     "--authority", auth.address)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "verifies" in r.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── the gateway enforces it ────────────────────────────────────────────────

def test_the_gateway_record_publishes_the_claim_and_not_the_charter():
    """
    A node serving its own charter would invite peers to judge it by the very
    document it chose. It publishes its cluster id and proof; the charter is
    the verifier's side.
    """
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("_NODE_RECORD = NodeRecord(")
    j = src.index("_FED = Federation(", i)
    body = src[i:j]
    assert "membership=" in body and "cluster_id=" in body
    # The record may name the charter to read its cluster id off it; what it
    # must not do is serialise the charter into the published record. Checked
    # as the specific thing rather than by banning the word, which the
    # surrounding comment uses.
    for leak in ("charter.to_dict()", "charter=", "membership_root"):
        assert leak not in body, \
            f"the published record carries {leak} — the charter is the " \
            f"verifier's side and must not be served"


def test_the_gateway_enforces_membership_on_the_peering_path():
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("async def federation_peer(")
    j = src.find("@app.", i)
    body = src[i:j if j > 0 else len(src)]
    assert "verify_member(" in body, "peering does not check membership"
    assert "_CLUSTER.charter" in body, \
        "membership must be checked against THIS node's charter"
    assert "rec.membership" in body
    # the check must come before the peer is recorded
    assert body.index("verify_member(") < body.index("add_verified_peer("), \
        "the peer is recorded before its membership is checked"


def test_the_gateway_refuses_to_start_on_a_charter_it_cannot_verify():
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    i = src.index("_CLUSTER = None")
    body = src[i:i + 1400]
    assert "ClusterError" in body and "Refusing to start" in body


def test_the_gateway_refuses_a_claim_belonging_to_another_node():
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    assert "XCP_CLUSTER_MEMBERSHIP is a claim for node" in src, \
        "a membership file copied from another datacentre must be caught"


# ── end to end: a real gateway admitting and refusing real peers ───────────
# Everything above this line tests a part, and the four tests just above are
# source greps -- the weak form. This project has four times shipped a correct,
# tested library that no running code could reach, so the enforcement gets an
# integration test through the real handler.
#
# The peer's TLS and gateway-launch helpers come from test_private_federation,
# which already solved both. Imported rather than duplicated; both files stay
# runnable standalone.

sys.path.insert(0, str(ROOT / "tests"))


def _peer_serving(record_json: bytes, cert_p: Path, key_p: Path):
    """
    An HTTPS node-record server on loopback.

    Takes the certificate rather than issuing one, because the record has to be
    bound to the certificate this server will actually present — the gateway
    checks exactly that, and issuing inside here meant building the record
    against a certificate that was about to be replaced.
    """
    import ssl
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):                       # noqa: N802 - stdlib interface
            if not self.path.endswith("/.well-known/xcp-node.json"):
                self.send_response(404); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(record_json)))
            self.end_headers()
            self.wfile.write(record_json)

        def log_message(self, *a):
            pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"https://127.0.0.1:{srv.server_address[1]}"


def _peer_record(cert_pem: bytes, node_key: str, *, claim=None) -> bytes:
    """A valid node record for 127.0.0.1, optionally carrying a claim."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from federation import NodeIdentity, NodeRecord, rotate
    from federation.node import digest as node_digest

    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(Encoding.DER)
    fp = node_digest(der)
    ident = NodeIdentity.from_key(node_key)
    rec = NodeRecord(domain="127.0.0.1", node_id=ident.node_id,
                     gateway_url="https://127.0.0.1", operator="DC peer",
                     bindings=rotate(ident, fp, domain="127.0.0.1").to_dict(),
                     cert_footprint=fp,
                     cluster_id=claim.cluster_id if claim else "",
                     membership=claim.to_dict() if claim else None)
    assert not rec.validate(), rec.validate()
    return rec.to_json().encode()


PEER_NODE_KEY = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"


def _peer_node_id() -> str:
    from federation import NodeIdentity
    return NodeIdentity.from_key(PEER_NODE_KEY).node_id


def _attempt_peering(*, member: bool, open_cluster: bool = False,
                     removed: bool = False, wrong_node: bool = False):
    """
    Stand up a closed-cluster gateway and a peer, and try to peer.

    Returns (status, response). The peer's node id is a real derived id, so the
    member set it goes into is the real thing rather than a placeholder.
    """
    _need_eth()
    from test_private_federation import _gateway, _issue_internal_ca

    peer_id = _peer_node_id()
    auth = Account.create()
    others = _ids(2)

    # The member set the GATEWAY's charter commits to. When `removed`, the
    # charter has moved to epoch 2 with a root that excludes the peer.
    roster = list(others) if (removed or not member) else [peer_id, *others]
    gw_ms = build_member_set(CID, roster)
    gw_charter = sign_charter(auth.key.hex(), gw_ms,
                              epoch=2 if removed else 1, open=open_cluster)

    # The claim the PEER presents. When removed, it is the genuine proof the
    # authority really issued from the earlier member set — still internally
    # valid, simply no longer in the root this gateway holds.
    claim = None
    if member:
        src_ms = build_member_set(CID, [peer_id, *others]) if removed else gw_ms
        claim = issue_claim(src_ms, others[0] if wrong_node else peer_id,
                            epoch=1)

    tmp = Path(tempfile.mkdtemp())
    srv = None
    try:
        (tmp / "charter.json").write_text(gw_charter.to_json())
        bundle, cert_p, key_p = _issue_internal_ca(
            tmp, san_ip="127.0.0.1", common_name="127.0.0.1")
        body = _peer_record(cert_p.read_bytes(), PEER_NODE_KEY, claim=claim)
        srv, url = _peer_serving(body, cert_p, key_p)
        with _gateway(XCP_PROFILE="development", XCP_VERIFY_URL="",
                      XCP_ALLOW_INSECURE_PEERS="1",
                      XCP_PEER_CA_BUNDLE=str(bundle),
                      XCP_CLUSTER_CHARTER=str(tmp / "charter.json"),
                      XCP_CLUSTER_AUTHORITY=auth.address) as gw:
            return gw.peer("127.0.0.1", url)
    finally:
        if srv is not None:
            srv.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_member_peers_into_a_closed_cluster():
    status, res = _attempt_peering(member=True)
    assert status == 200, f"a member was refused: {status} {res}"
    assert res.get("peered") is True, res
    assert res.get("clusterMember") == CID, res
    assert res.get("trust") == "verified", \
        "membership is not a trust level and must not promote a peer"


def test_a_non_member_is_refused_by_a_closed_cluster():
    status, res = _attempt_peering(member=False)
    assert status == 403, f"a non-member was admitted: {status} {res}"
    assert "membership" in str(res).lower(), res


def test_a_removed_member_is_refused_with_no_revocation_involved():
    """
    The property the whole design rests on, end to end: the peer presents a
    genuine proof the authority really issued, and this gateway refuses it
    because its own charter has moved on.
    """
    status, res = _attempt_peering(member=True, removed=True)
    assert status == 403, f"a removed member was re-admitted: {status} {res}"


def test_a_claim_for_a_different_node_is_refused():
    status, res = _attempt_peering(member=True, wrong_node=True)
    assert status == 403, f"a replayed claim was accepted: {status} {res}"


def test_an_open_cluster_admits_a_node_with_no_claim():
    status, res = _attempt_peering(member=False, open_cluster=True)
    assert status == 200, f"an open cluster refused a non-member: {status} {res}"
    assert res.get("clusterMember") is None


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
            print(f"  FAIL {name}: {str(e)[:160]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
