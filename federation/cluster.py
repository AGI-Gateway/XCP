"""
federation.cluster — a private federation's membership, with no chain required.

WHY THIS MODULE EXISTS
----------------------
`NodeRecord.cluster_id` carried a comment that was also an admission:

    cluster_id: str = ""   # membership root is on-chain, roster is not

Clusters existed only in `NodeRegistry.sol`: `upsertCluster(clusterId,
membershipRoot, policyHash, open)` publishes a root and `verifyMembership`
checks a Merkle proof against it. The design is right -- a cluster commits to
its member set without publishing a roster, so an outsider learns that the
cluster exists and nothing about who is in it. But it was reachable only by
deploying and paying for a contract, which an organisation federating three of
its own datacentres has no reason to do. There was no off-chain equivalent
anywhere, so a private federation could not use clusters at all.

This is that equivalent: the same root-not-roster construction, signed by the
organisation's own authority key instead of anchored to a chain.

THE ROOT IS THE SAME ROOT
-------------------------
`membership_root` here is byte-compatible with `NodeRegistry.verifyMembership`:
sorted-pair keccak over raw node_id leaves, which is what the Solidity loop
computes. So an organisation can run privately now and anchor the very same
charter root with `upsertCluster` later, or run both at once with one root, and
a proof issued here verifies on-chain unchanged. The test suite asserts this
against a reimplementation of the Solidity loop rather than trusting the
comment.

WHOSE CHARTER DECIDES
---------------------
A peering node verifies an incoming member's proof against the root in the
charter IT holds -- never against a charter the claimant supplies. That single
choice removes charter substitution as an attack: there is no "which charter do
we believe" question, because only one of them is ours. A peer's claim carries
a proof and the epoch it was issued against, nothing that could override us.

It also makes removal work, which is the hard part of any membership scheme.
To remove a node, the authority publishes a charter with a higher epoch and a
root that excludes it. The removed node still holds a perfectly valid proof,
and that proof no longer verifies against the root its former peers hold. No
revocation list, no gossip, no expiry to wait out.

WHAT THIS DOES NOT DO
---------------------
It is not an authorisation system. Membership says a node belongs to a cluster;
what members may then do is the policy document `policy_hash` commits to, and
the trust lattice and mandates still decide every call. A member is a peer, not
a privileged one.

Status: XCP is a draft proposal.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_utils import keccak as _keccak
    _ETH = True
except ImportError:                                   # pragma: no cover
    _ETH = False

CLUSTER_SPEC_VERSION = "0.1-draft"

#: Default charter lifetime. Long enough not to be operational toil, short
#: enough that a charter nobody maintains stops being a membership statement.
DEFAULT_CHARTER_TTL = 180 * 86400

#: A Merkle root over a single leaf IS that leaf, so a one-member cluster would
#: publish its only member's node_id as the root. Trees are padded to at least
#: this many leaves with random values, which changes nothing for either
#: verifier -- a pad leaf is just a leaf -- and stops the root being a member id.
MIN_LEAVES = 2


def digest(data: bytes) -> str:
    if _ETH:
        return "0x" + _keccak(data).hex()
    return "0x" + hashlib.sha3_256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


class ClusterError(Exception):
    pass


def cluster_id_from_name(name: str) -> str:
    """
    A cluster's identifier, derived from a name the operator chooses.

    Derived rather than random so two datacentres configured independently
    arrive at the same id from the same name, and so the id is reproducible
    when the same cluster is later anchored on-chain.
    """
    if not name.strip():
        raise ClusterError("a cluster needs a name")
    return digest(("xcp-cluster:" + name.strip().lower()).encode("utf-8"))


# ── the Merkle half: a root, never a roster ────────────────────────────────
# Deliberately a local reimplementation rather than an import from
# federation.transport. That module's tree commits to billing receipts, and
# coupling membership to it would mean a change made for billing could silently
# change who is a member. The test suite asserts the two agree.

def _pair(a: str, b: str) -> str:
    lo, hi = sorted([a, b])
    return digest(bytes.fromhex(lo[2:]) + bytes.fromhex(hi[2:]))


def _normalise(leaf: str) -> str:
    if not leaf.startswith("0x") or len(leaf) != 66:
        raise ClusterError(f"a member id must be 0x and 32 bytes, got {leaf!r}")
    return leaf.lower()


def membership_root(leaves: list[str]) -> str:
    """Sorted-pair keccak, identical to NodeRegistry.verifyMembership's loop."""
    if not leaves:
        raise ClusterError("a cluster with no members has no root")
    level = sorted(_normalise(x) for x in leaves)
    while len(level) > 1:
        level = [_pair(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
    return level[0]


def membership_proof(leaves: list[str], target: str) -> list[str]:
    level = sorted(_normalise(x) for x in leaves)
    t = _normalise(target)
    if t not in level:
        raise ClusterError("that node is not in this member set")
    proof: list[str] = []
    idx = level.index(t)
    while len(level) > 1:
        sib = idx ^ 1
        if sib < len(level):
            proof.append(level[sib])
        level = [_pair(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
        idx //= 2
    return proof


def verify_membership_proof(node_id: str, proof: list[str], root: str) -> bool:
    h = _normalise(node_id)
    for p in proof:
        h = _pair(h, _normalise(p))
    return h == root.lower()


@dataclass
class MemberSet:
    """
    The authority's private side: who is in, and each member's proof.

    This object never leaves the authority. What leaves is the charter (a root)
    and, to each member, that member's own proof.
    """
    cluster_id: str
    node_ids: list[str] = field(default_factory=list)
    pads: list[str] = field(default_factory=list)

    @property
    def leaves(self) -> list[str]:
        return [*self.node_ids, *self.pads]

    @property
    def root(self) -> str:
        return membership_root(self.leaves)

    def proof_for(self, node_id: str) -> list[str]:
        return membership_proof(self.leaves, node_id)

    def to_dict(self) -> dict[str, Any]:
        """For the authority's own storage. NOT for publication."""
        return {"clusterId": self.cluster_id, "nodeIds": list(self.node_ids),
                "pads": list(self.pads)}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "MemberSet":
        return MemberSet(cluster_id=d["clusterId"],
                         node_ids=list(d.get("nodeIds") or []),
                         pads=list(d.get("pads") or []))


def build_member_set(cluster_id: str, node_ids: list[str]) -> MemberSet:
    """
    Build a member set, padding to MIN_LEAVES so the root is never a member id.

    The pads are random 32-byte values held with the member list. They are
    indistinguishable from node ids in the tree, which is the point: the tree's
    shape tells an observer nothing about how many real members there are.
    """
    ids = [_normalise(n) for n in node_ids]
    if not ids:
        raise ClusterError("a cluster needs at least one member")
    if len(set(ids)) != len(ids):
        raise ClusterError("duplicate member ids")
    pads = ["0x" + secrets.token_bytes(32).hex()
            for _ in range(max(0, MIN_LEAVES - len(ids)))]
    return MemberSet(cluster_id=cluster_id, node_ids=ids, pads=pads)


# ── the signed half: a charter ─────────────────────────────────────────────

@dataclass
class ClusterCharter:
    """
    A signed statement: *this cluster currently has this member set, under this
    policy, as of this epoch.*

    Carries no roster, by construction. `to_dict()` contains no member id, and
    a test asserts that rather than leaving it to review.
    """
    cluster_id: str
    membership_root: str
    policy_hash: str
    epoch: int
    not_before: int
    not_after: int
    authority: str                   # the signing address
    #: False means only members may peer. True makes membership advisory, which
    #: matches NodeRegistry's `open` flag and is the public-federation case.
    open: bool = False
    spec_version: str = CLUSTER_SPEC_VERSION
    signature: str = ""

    def payload(self) -> dict[str, Any]:
        return {"clusterId": self.cluster_id,
                "membershipRoot": self.membership_root,
                "policyHash": self.policy_hash, "epoch": self.epoch,
                "notBefore": self.not_before, "notAfter": self.not_after,
                "open": self.open}

    def active(self, now: Optional[int] = None) -> bool:
        n = now or int(time.time())
        return self.not_before <= n <= self.not_after

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ClusterCharter":
        known = set(ClusterCharter.__dataclass_fields__)
        missing = {"cluster_id", "membership_root", "epoch", "authority"} - set(
            _snake(k) for k in d)
        if missing:
            raise ClusterError(f"charter is missing {sorted(missing)}")
        return ClusterCharter(**{_snake(k): v for k, v in d.items()
                                 if _snake(k) in known})


_CAMEL = {"clusterId": "cluster_id", "membershipRoot": "membership_root",
          "policyHash": "policy_hash", "notBefore": "not_before",
          "notAfter": "not_after", "specVersion": "spec_version"}


def _snake(k: str) -> str:
    return _CAMEL.get(k, k)


def _typed(payload: dict[str, Any], chain_id: int) -> dict:
    return {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"},
                             {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}],
            "ClusterCharter": [
                {"name": "clusterId", "type": "string"},
                {"name": "membershipRoot", "type": "string"},
                {"name": "policyHash", "type": "string"},
                {"name": "epoch", "type": "uint64"},
                {"name": "notBefore", "type": "uint64"},
                {"name": "notAfter", "type": "uint64"},
                {"name": "open", "type": "bool"}],
        },
        "primaryType": "ClusterCharter",
        "domain": {"name": "XCPClusterCharter", "version": "1",
                   "chainId": chain_id},
        "message": payload,
    }


def sign_charter(authority_key: str, member_set: MemberSet, *,
                 policy_hash: str = "0x" + "00" * 32, epoch: int,
                 open: bool = False, ttl: int = DEFAULT_CHARTER_TTL,
                 now: Optional[int] = None,
                 chain_id: int = 8453) -> ClusterCharter:
    """
    Sign a charter for a member set.

    `epoch` is the operator's, not generated here: raising it is how a removal
    takes effect, so it has to be a deliberate act with a number the operator
    can see and compare, not something this function increments behind them.
    """
    if not _ETH:
        raise ClusterError("eth-account required to sign a cluster charter")
    if epoch < 1:
        raise ClusterError("epoch starts at 1")
    acct = Account.from_key(authority_key)
    n = now or int(time.time())
    c = ClusterCharter(
        cluster_id=member_set.cluster_id, membership_root=member_set.root,
        policy_hash=policy_hash, epoch=epoch, not_before=n, not_after=n + ttl,
        authority=acct.address, open=open)
    sig = Account.sign_message(
        encode_typed_data(full_message=_typed(c.payload(), chain_id)),
        private_key=authority_key).signature.hex()
    c.signature = sig if sig.startswith("0x") else "0x" + sig
    return c


def verify_charter(charter: ClusterCharter, *, expected_cluster_id: str = "",
                   expected_authority: str = "", min_epoch: int = 0,
                   now: Optional[int] = None,
                   chain_id: int = 8453) -> list[str]:
    """
    Check a charter. Returns problems; empty means this really is the named
    authority's current statement about this cluster.
    """
    problems: list[str] = []
    n = now or int(time.time())

    if expected_cluster_id and \
            charter.cluster_id.lower() != expected_cluster_id.lower():
        problems.append("charter is for a different cluster")
    if expected_authority and \
            charter.authority.lower() != expected_authority.lower():
        # Without this, anyone may mint a charter naming any cluster id and a
        # node that merely checks the signature verifies it happily.
        problems.append(
            f"charter is signed by {charter.authority}, not the expected "
            f"authority")
    if not charter.active(n):
        problems.append("charter is expired or not yet valid")
    if charter.epoch < min_epoch:
        # Same downgrade defence the certificate bindings carry. Without it a
        # removed member replays the charter that still includes them.
        problems.append(
            f"charter epoch {charter.epoch} is older than {min_epoch} — "
            "refusing a rolled-back charter")
    try:
        _normalise(charter.membership_root)
    except ClusterError as e:
        problems.append(str(e))
    if not charter.signature:
        problems.append("charter is unsigned")
    elif _ETH:
        try:
            rec = Account.recover_message(
                encode_typed_data(
                    full_message=_typed(charter.payload(), chain_id)),
                signature=bytes.fromhex(charter.signature[2:]))
        except Exception as e:                      # noqa: BLE001
            problems.append(f"charter signature is malformed: {type(e).__name__}")
        else:
            if rec.lower() != charter.authority.lower():
                problems.append("charter signature does not match its authority")
    return problems


# ── what a member presents ─────────────────────────────────────────────────

@dataclass
class MembershipClaim:
    """
    What a node publishes in its own record: *I am a member of this cluster,
    here is my proof.*

    It carries no charter. A peer verifies the proof against the root in the
    charter the PEER holds, so a claim cannot assert the ground it is judged
    against.
    """
    cluster_id: str
    node_id: str
    epoch: int
    proof: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"clusterId": self.cluster_id, "nodeId": self.node_id,
                "epoch": self.epoch, "proof": list(self.proof)}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "MembershipClaim":
        if not isinstance(d, dict):
            raise ClusterError("membership claim must be an object")
        try:
            proof = [str(p) for p in (d.get("proof") or [])]
            return MembershipClaim(
                cluster_id=str(d["clusterId"]), node_id=str(d["nodeId"]),
                epoch=int(d["epoch"]), proof=proof)
        except (KeyError, TypeError, ValueError) as e:
            raise ClusterError(f"malformed membership claim: {e}")


def issue_claim(member_set: MemberSet, node_id: str, epoch: int) -> MembershipClaim:
    """The authority's per-member handout."""
    return MembershipClaim(cluster_id=member_set.cluster_id,
                           node_id=_normalise(node_id), epoch=epoch,
                           proof=member_set.proof_for(node_id))


def verify_member(charter: ClusterCharter, claim: MembershipClaim, *,
                  expected_node_id: str = "") -> list[str]:
    """
    Check a claim against OUR charter. Returns problems; empty means this node
    is a member of this cluster as our charter currently defines it.

    The charter itself must already have been verified -- this checks
    membership, not the charter's authenticity, and the gateway verifies the
    charter once at startup rather than on every peering.
    """
    problems: list[str] = []
    if claim.cluster_id.lower() != charter.cluster_id.lower():
        problems.append("claim is for a different cluster")
    if expected_node_id and claim.node_id.lower() != expected_node_id.lower():
        # The claim must be about the node that presented it. Otherwise a
        # non-member replays any member's claim and is admitted as them.
        problems.append("claim is for a different node than the one presenting it")
    if claim.epoch < charter.epoch:
        problems.append(
            f"claim proves membership of epoch {claim.epoch}, and this cluster "
            f"is at epoch {charter.epoch} — the member set has changed since")
    try:
        ok = verify_membership_proof(claim.node_id, claim.proof,
                                     charter.membership_root)
    except ClusterError as e:
        problems.append(str(e))
    else:
        if not ok:
            problems.append("membership proof does not verify against this "
                            "cluster's root")
    return problems


# ── proving membership to a peer, right now ────────────────────────────────
# A claim on its own is a BEARER credential: it is a static document, and
# anyone who obtains one can present it as their own. That is tolerable inside
# a node record, where the claim sits alongside the identity it describes and a
# peer checks both. It is not tolerable as the thing that unlocks a gated
# resource, because then possession alone is access.
#
# So an access request is a claim plus a signature from the key the claim names,
# over a payload bound to WHO is being asked and WHEN. Replaying it elsewhere
# fails on the audience; replaying it later fails on the expiry. This is the
# same shape as the per-request credentials the trust firewall already mints for
# agents -- short-lived, and bound to the exact thing being requested.

ACCESS_TTL = 60


@dataclass
class AccessRequest:
    """A member proving, to one named audience, that it is a member right now."""
    claim: MembershipClaim
    audience: str                    # the domain being asked
    issued_at: int
    expires_at: int
    signature: str = ""

    def payload(self) -> dict[str, Any]:
        return {"clusterId": self.claim.cluster_id, "nodeId": self.claim.node_id,
                "epoch": self.claim.epoch, "proofRoot": _proof_digest(self.claim),
                "audience": self.audience.lower(),
                "issuedAt": self.issued_at, "expiresAt": self.expires_at}

    def expired(self, now: Optional[int] = None) -> bool:
        return (now or int(time.time())) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {"claim": self.claim.to_dict(), "audience": self.audience,
                "issuedAt": self.issued_at, "expiresAt": self.expires_at,
                "signature": self.signature}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "AccessRequest":
        if not isinstance(d, dict):
            raise ClusterError("access request must be an object")
        try:
            return AccessRequest(
                claim=MembershipClaim.from_dict(d["claim"]),
                audience=str(d["audience"]), issued_at=int(d["issuedAt"]),
                expires_at=int(d["expiresAt"]),
                signature=str(d.get("signature") or ""))
        except ClusterError:
            raise
        except (KeyError, TypeError, ValueError) as e:
            raise ClusterError(f"malformed access request: {e}")


def _proof_digest(claim: MembershipClaim) -> str:
    """
    The proof, committed to by digest rather than signed element by element.

    Without this the signature would cover the claim's identity but not its
    proof, so a member could sign once and then swap in any proof it liked --
    including a stale one for a node that has since been removed.
    """
    return digest(canonical([claim.cluster_id, claim.node_id, claim.epoch,
                             list(claim.proof)]))


def _typed_access(payload: dict[str, Any], chain_id: int) -> dict:
    return {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"},
                             {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}],
            "ClusterAccess": [
                {"name": "clusterId", "type": "string"},
                {"name": "nodeId", "type": "string"},
                {"name": "epoch", "type": "uint64"},
                {"name": "proofRoot", "type": "string"},
                {"name": "audience", "type": "string"},
                {"name": "issuedAt", "type": "uint64"},
                {"name": "expiresAt", "type": "uint64"}],
        },
        "primaryType": "ClusterAccess",
        "domain": {"name": "XCPClusterAccess", "version": "1",
                   "chainId": chain_id},
        "message": payload,
    }


def sign_access_request(node_key: str, claim: MembershipClaim, *,
                        audience: str, ttl: int = ACCESS_TTL,
                        now: Optional[int] = None,
                        chain_id: int = 8453) -> AccessRequest:
    """
    Mint a short-lived proof of membership for one audience.

    The key must be the node's own long-lived identity key -- the same one that
    signs its certificate bindings. A member that signs with anything else is
    not proving it is the node its claim names.
    """
    if not _ETH:
        raise ClusterError("eth-account required to sign an access request")
    if not audience.strip():
        raise ClusterError("an access request must name its audience")
    n = now or int(time.time())
    req = AccessRequest(claim=claim, audience=audience.strip().lower(),
                        issued_at=n, expires_at=n + max(1, ttl))
    sig = Account.sign_message(
        encode_typed_data(full_message=_typed_access(req.payload(), chain_id)),
        private_key=node_key).signature.hex()
    req.signature = sig if sig.startswith("0x") else "0x" + sig
    return req


def verify_access_request(charter: ClusterCharter, req: AccessRequest, *,
                          audience: str, now: Optional[int] = None,
                          max_ttl: int = ACCESS_TTL,
                          chain_id: int = 8453) -> list[str]:
    """
    Check an access request against OUR charter. Returns problems; empty means
    this really is a current member of this cluster, asking us.
    """
    problems: list[str] = []
    n = now or int(time.time())

    if req.audience.lower() != audience.strip().lower():
        # Without this a request minted for one node is replayed at every other
        # node in the cluster, so one captured credential opens all of them.
        problems.append("access request was minted for a different audience")
    if req.expired(n):
        problems.append("access request has expired")
    if req.issued_at > n + 5:
        problems.append("access request is issued in the future")
    if req.expires_at - req.issued_at > max_ttl:
        # A member could otherwise mint itself a year-long credential and make
        # the expiry meaningless, which is the only thing bounding replay.
        problems.append(
            f"access request lives longer than {max_ttl}s; refusing a "
            f"credential whose expiry does not bound replay")

    problems.extend(verify_member(charter, req.claim))

    if not req.signature:
        problems.append("access request is unsigned")
    elif _ETH:
        try:
            rec = Account.recover_message(
                encode_typed_data(
                    full_message=_typed_access(req.payload(), chain_id)),
                signature=bytes.fromhex(req.signature[2:]))
        except Exception as e:                      # noqa: BLE001
            problems.append(f"access signature is malformed: {type(e).__name__}")
        else:
            # The signature has to come from the key the CLAIM names, which is
            # what makes this proof of possession rather than a second bearer
            # token. node_id is keccak(address), so the recovered address is
            # checked by deriving the id it would produce.
            from .identity import node_id_from_address
            if node_id_from_address(rec).lower() != req.claim.node_id.lower():
                problems.append(
                    "access request is not signed by the node its claim names")
    return problems


# ── what a node loads at startup ───────────────────────────────────────────

CHARTER_ENV = "XCP_CLUSTER_CHARTER"
CLAIM_ENV = "XCP_CLUSTER_MEMBERSHIP"
AUTHORITY_ENV = "XCP_CLUSTER_AUTHORITY"
MIN_EPOCH_ENV = "XCP_CLUSTER_MIN_EPOCH"


@dataclass
class ClusterPosture:
    """This node's cluster configuration, after validation."""
    charter: Optional[ClusterCharter] = None
    claim: Optional[MembershipClaim] = None

    @property
    def configured(self) -> bool:
        return self.charter is not None

    @property
    def closed(self) -> bool:
        """True when only members may peer."""
        return self.charter is not None and not self.charter.open

    def summary(self) -> dict[str, Any]:
        """Counts and ids only -- never the root, which is a commitment to the
        member set and has no business on an unauthenticated endpoint."""
        if self.charter is None:
            return {"configured": False}
        return {"configured": True, "clusterId": self.charter.cluster_id,
                "epoch": self.charter.epoch,
                "closed": self.closed,
                "selfIsMember": self.claim is not None}

    def detail(self) -> dict[str, Any]:
        if self.charter is None:
            return {"configured": False}
        return {"configured": True, "charter": self.charter.to_dict(),
                "claim": self.claim.to_dict() if self.claim else None,
                "closed": self.closed}


def load_posture(*, now: Optional[int] = None) -> ClusterPosture:
    """
    Read and validate the charter and this node's own claim from the
    environment. Raises ClusterError rather than degrading.

    A node that cannot validate its own charter must not start. Starting
    without it would mean a closed cluster silently accepting any peer, which
    is the one outcome the charter exists to prevent.
    """
    path = os.getenv(CHARTER_ENV, "").strip()
    if not path:
        return ClusterPosture()
    if not os.path.isfile(path):
        raise ClusterError(f"{CHARTER_ENV}={path!r} is not a readable file")
    try:
        charter = ClusterCharter.from_dict(json.loads(
            open(path, encoding="utf-8").read()))
    except ClusterError:
        raise
    except Exception as e:                          # noqa: BLE001
        raise ClusterError(f"{CHARTER_ENV}={path!r} is not a valid charter: {e}")

    problems = verify_charter(
        charter, expected_authority=os.getenv(AUTHORITY_ENV, "").strip(),
        min_epoch=int(os.getenv(MIN_EPOCH_ENV, "0") or 0), now=now)
    if problems:
        raise ClusterError(f"cluster charter did not verify: {problems[0]}")

    claim = None
    cpath = os.getenv(CLAIM_ENV, "").strip()
    if cpath:
        if not os.path.isfile(cpath):
            raise ClusterError(f"{CLAIM_ENV}={cpath!r} is not a readable file")
        try:
            claim = MembershipClaim.from_dict(json.loads(
                open(cpath, encoding="utf-8").read()))
        except ClusterError:
            raise
        except Exception as e:                      # noqa: BLE001
            raise ClusterError(f"{CLAIM_ENV}={cpath!r} is not a valid claim: {e}")
        own = verify_member(charter, claim)
        if own:
            raise ClusterError(
                f"this node's own membership does not verify: {own[0]}. A node "
                f"that cannot prove its own membership cannot expect peers to "
                f"accept it")
    return ClusterPosture(charter=charter, claim=claim)


__all__ = ["CLUSTER_SPEC_VERSION", "DEFAULT_CHARTER_TTL", "MIN_LEAVES",
           "ACCESS_TTL", "ClusterError", "ClusterCharter", "MemberSet",
           "MembershipClaim", "AccessRequest", "ClusterPosture",
           "cluster_id_from_name", "membership_root",
           "membership_proof", "verify_membership_proof", "build_member_set",
           "sign_charter", "verify_charter", "issue_claim", "verify_member",
           "sign_access_request", "verify_access_request",
           "load_posture", "digest", "canonical",
           "CHARTER_ENV", "CLAIM_ENV", "AUTHORITY_ENV", "MIN_EPOCH_ENV"]
