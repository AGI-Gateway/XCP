"""
federation.transport — paying nodes to route agentic traffic.

WHY THIS EXISTS
---------------
Federation currently asks operators to run infrastructure for other people's
agents out of goodwill. That works for a demo and fails at scale. This gives
routing a price, so operating a node is a business rather than a favour:

    an agent's workflow routes through node N to reach a tool
    N supplies transport, session verification and mandate enforcement
    N earns for it

That also fixes the Sybil problem transitive trust cannot solve on its own. If
identities are free, a thousand fake nodes vouching for each other defeats decay.
If joining requires a bond that is slashable on *proven* misbehaviour, identity
costs something — without a central gatekeeper deciding who may join.

THE HARD PART IS NOT PAYMENT, IT IS ACCOUNTING PRIVACY
------------------------------------------------------
To pay per route you must count routes. Counting routes in public leaks the
topology: who talks to whom, at what volume, with which counterparties. No
enterprise will accept that, and a federation only enterprises cannot join is not
a federation.

So the boundary is drawn deliberately:

    ON-CHAIN (public)                  OFF-CHAIN (private)
    ─────────────────────────────      ──────────────────────────────
    node identity + bond               who routed to whom
    per-epoch commitment root          individual receipts
    route count, total amount          per-counterparty volumes
    revocations, slashes               scopes, timing, payloads

A node publishes one commitment per epoch: a Merkle root over its receipts plus
the totals it is claiming. Settlement happens against the root. Any individual
route can be proven to the chain *if challenged*, and otherwise never appears.

FRAUD: YOU CANNOT INVENT TRAFFIC SOMEBODY ELSE MUST SIGN
---------------------------------------------------------
The obvious attack on pay-per-route is fabricating routes. The defence is that a
billable receipt carries the **payer's** signature, not the node's. A node can
only claim what a counterparty actually signed for.

Claiming is optimistic — a node posts a root and is paid after a challenge
window — because putting every route on-chain would be both expensive and the
privacy leak this design exists to avoid. Three fraud proofs are checkable by
anyone:

    · a receipt in the claimed tree whose payer signature does not verify
    · totals that do not match the tree
    · a route id claimed in two epochs

Each is a cryptographic claim, not a judgement call, which is what makes slashing
defensible rather than political.

Status: XCP and ERC-8004x are draft proposals. Staking real value is a regulated
activity in most jurisdictions — see federation/README.md before deploying this
with anything of value at stake.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Iterable, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_utils import keccak as _keccak
    _ETH = True
except ImportError:                                   # pragma: no cover
    _ETH = False

TRANSPORT_SPEC_VERSION = "0.1-draft"
EPOCH_SECONDS = 3600                 # commitments are hourly by default
CHALLENGE_WINDOW = 7 * 86400         # a claim is contestable for a week
GENESIS = "0x" + "00" * 32


def digest(data: bytes) -> str:
    if _ETH:
        return "0x" + _keccak(data).hex()
    return "0x" + hashlib.sha3_256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


class TransportError(Exception):
    pass


class RouteClass(str, Enum):
    """
    What a node actually did, which is what it may charge for. Deliberately
    coarse: finer classes would let an observer infer workload shape from a
    public price list.
    """
    A2T = "a2t"          # agent -> tool
    A2A = "a2a"          # agent <-> agent
    T2T = "t2t"          # tool -> tool chaining
    WRAP = "wrap"        # served through a generated API wrapper
    RELAY = "relay"      # forwarded to a peer node


# ── the unit of account ────────────────────────────────────────────────────

@dataclass
class TransportReceipt:
    """
    One routed call, signed by the PAYER. The node cannot mint these: that is the
    whole anti-fraud property.
    """
    route_id: str                 # unique; double-claiming it is provable fraud
    node_id: str                  # who routed
    payer_agent: int              # who owes
    route_class: RouteClass
    price_minor: int
    currency: str = "USDC"
    epoch: int = 0
    ts: int = 0
    # NOT part of the public commitment — kept locally for dispute only
    scope: str = ""
    peer_hint: str = ""
    payer_address: str = ""
    signature: str = ""

    def billable_payload(self) -> dict[str, Any]:
        """
        Exactly what the payer signs, and the only fields that reach the Merkle
        tree. Scope and counterparty are deliberately excluded: a leaf should not
        reveal what the agent was doing, even to someone who later obtains it.
        """
        return {"routeId": self.route_id, "nodeId": self.node_id,
                "payerAgent": self.payer_agent, "class": self.route_class.value,
                "priceMinor": self.price_minor, "currency": self.currency,
                "epoch": self.epoch}

    @property
    def leaf(self) -> str:
        return digest(canonical(self.billable_payload()))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["route_class"] = self.route_class.value
        return d


def _typed(payload: dict[str, Any], chain_id: int) -> dict:
    return {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"},
                             {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}],
            "TransportReceipt": [
                {"name": "routeId", "type": "string"},
                {"name": "nodeId", "type": "string"},
                {"name": "payerAgent", "type": "uint256"},
                {"name": "class", "type": "string"},
                {"name": "priceMinor", "type": "uint256"},
                {"name": "currency", "type": "string"},
                {"name": "epoch", "type": "uint64"}],
        },
        "primaryType": "TransportReceipt",
        "domain": {"name": "XCPTransport", "version": "1", "chainId": chain_id},
        "message": payload,
    }


def sign_receipt(private_key: str, receipt: TransportReceipt,
                 chain_id: int = 8453) -> TransportReceipt:
    """Payer authorises one route. Without this the node has nothing to claim."""
    if not _ETH:
        raise TransportError("eth-account required to sign transport receipts")
    acct = Account.from_key(private_key)
    sig = Account.sign_message(
        encode_typed_data(full_message=_typed(receipt.billable_payload(), chain_id)),
        private_key=private_key).signature.hex()
    receipt.payer_address = acct.address
    receipt.signature = sig if sig.startswith("0x") else "0x" + sig
    return receipt


def verify_receipt(receipt: TransportReceipt, chain_id: int = 8453,
                   expected_node: str = "") -> list[str]:
    problems: list[str] = []
    if receipt.price_minor < 0:
        problems.append("negative price")
    if not receipt.route_id:
        problems.append("no route id")
    if expected_node and receipt.node_id != expected_node:
        problems.append("receipt is for a different node")
    if not receipt.signature:
        problems.append("unsigned — a node cannot bill for a route nobody authorised")
    elif _ETH:
        try:
            rec = Account.recover_message(
                encode_typed_data(
                    full_message=_typed(receipt.billable_payload(), chain_id)),
                signature=receipt.signature)
            if receipt.payer_address and rec.lower() != receipt.payer_address.lower():
                problems.append("signature does not match the declared payer")
        except Exception as e:
            problems.append(f"signature failed to recover: {e}")
    return problems


# ── Merkle commitment ──────────────────────────────────────────────────────

def _pair(a: str, b: str) -> str:
    lo, hi = sorted([a, b])
    return digest(bytes.fromhex(lo[2:]) + bytes.fromhex(hi[2:]))


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return GENESIS
    level = sorted(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_pair(level[i], level[i + 1]) if i + 1 < len(level)
                       else level[i])
        level = nxt
    return level[0]


def merkle_proof(leaves: list[str], target: str) -> list[str]:
    level = sorted(leaves)
    if target not in level:
        raise TransportError("leaf not in the tree")
    proof: list[str] = []
    idx = level.index(target)
    while len(level) > 1:
        sib = idx ^ 1
        if sib < len(level):
            proof.append(level[sib])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_pair(level[i], level[i + 1]) if i + 1 < len(level)
                       else level[i])
        idx //= 2
        level = nxt
    return proof


def verify_proof(leaf: str, proof: list[str], root: str) -> bool:
    h = leaf
    for p in proof:
        h = _pair(h, p)
    return h == root


# ── what actually goes on-chain ────────────────────────────────────────────

@dataclass
class EpochCommitment:
    """
    The entire public footprint of an epoch's traffic. Note what is absent:
    no counterparties, no scopes, no timing, no per-route anything.
    """
    node_id: str
    epoch: int
    root: str
    route_count: int
    total_minor: int
    currency: str = "USDC"
    spec_version: str = TRANSPORT_SPEC_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def commitment_digest(self) -> str:
        return digest(canonical(self.to_dict()))

    def reveals(self) -> dict[str, Any]:
        """
        Stated explicitly so the residual leak is not a surprise: volume is
        visible. See `bucket_count` for the mitigation.
        """
        return {"public": ["node identity", "epoch", "route count",
                           "total amount", "currency"],
                "private": ["counterparties", "scopes", "timing",
                            "per-route prices", "payloads"],
                "residualLeak": "route_count is a volume signal over time"}


def bucket_count(n: int, bucket: int = 100) -> int:
    """
    Round a route count up to a bucket before publishing. Trades a little
    accounting precision for meaningfully less volume signal — a node claiming
    'between 900 and 1000 routes' leaks far less than one claiming 947.
    """
    if bucket <= 1:
        return n
    return ((n + bucket - 1) // bucket) * bucket


# ── the node's local ledger ────────────────────────────────────────────────

@dataclass
class RoutingLedger:
    """
    A node's private accounting. Receipts live here and nowhere public; only
    commitments leave.
    """
    node_id: str
    chain_id: int = 8453
    receipts: dict[int, list[TransportReceipt]] = field(default_factory=dict)
    claimed_routes: set[str] = field(default_factory=set)
    committed: dict[int, EpochCommitment] = field(default_factory=dict)

    @staticmethod
    def epoch_of(ts: Optional[int] = None, size: int = EPOCH_SECONDS) -> int:
        return int((ts or time.time()) // size)

    def record(self, receipt: TransportReceipt) -> list[str]:
        """Accept a signed receipt into the current epoch. Refuses fraud early."""
        problems = verify_receipt(receipt, self.chain_id, expected_node=self.node_id)
        if problems:
            return problems
        if receipt.route_id in self.claimed_routes:
            return ["route id already claimed — double-billing is provable fraud"]
        if receipt.epoch in self.committed:
            return [f"epoch {receipt.epoch} is already committed"]
        ep = receipt.epoch or self.epoch_of()
        receipt.epoch = ep
        self.receipts.setdefault(ep, []).append(receipt)
        self.claimed_routes.add(receipt.route_id)
        return []

    def commit(self, epoch: int, bucket: int = 1) -> EpochCommitment:
        """Close an epoch and produce the only artifact that goes public."""
        rs = self.receipts.get(epoch, [])
        if not rs:
            raise TransportError(f"nothing to commit for epoch {epoch}")
        if epoch in self.committed:
            raise TransportError(f"epoch {epoch} already committed")
        c = EpochCommitment(
            node_id=self.node_id, epoch=epoch,
            root=merkle_root([r.leaf for r in rs]),
            route_count=bucket_count(len(rs), bucket),
            total_minor=sum(r.price_minor for r in rs),
            currency=rs[0].currency)
        self.committed[epoch] = c
        return c

    def prove(self, epoch: int, route_id: str) -> dict[str, Any]:
        """
        Disclose ONE route, only when challenged. This is the escape hatch that
        lets a claim be audited without publishing the ledger.
        """
        rs = self.receipts.get(epoch, [])
        target = next((r for r in rs if r.route_id == route_id), None)
        if target is None:
            raise TransportError("no such route in that epoch")
        leaves = [r.leaf for r in rs]
        return {"receipt": target.billable_payload(),
                "signature": target.signature,
                "payerAddress": target.payer_address,
                "leaf": target.leaf,
                "proof": merkle_proof(leaves, target.leaf),
                "root": merkle_root(leaves)}

    def earnings(self, epoch: Optional[int] = None) -> dict[str, Any]:
        eps = [epoch] if epoch is not None else list(self.receipts)
        rs = [r for e in eps for r in self.receipts.get(e, [])]
        from collections import Counter
        return {"routes": len(rs),
                "totalMinor": sum(r.price_minor for r in rs),
                "byClass": dict(Counter(r.route_class.value for r in rs))}


# ── fraud proofs: anyone can check, nobody has to be trusted ───────────────

def prove_bad_signature(disclosure: dict[str, Any], chain_id: int = 8453) -> bool:
    """True if a disclosed receipt's payer signature does not verify."""
    if not _ETH:
        raise TransportError("eth-account required")
    try:
        rec = Account.recover_message(
            encode_typed_data(full_message=_typed(disclosure["receipt"], chain_id)),
            signature=disclosure["signature"])
    except Exception:
        return True
    return rec.lower() != str(disclosure.get("payerAddress", "")).lower()


def prove_not_in_tree(disclosure: dict[str, Any]) -> bool:
    """True if a disclosed leaf does not actually sit under the claimed root."""
    return not verify_proof(disclosure["leaf"], disclosure["proof"],
                            disclosure["root"])


def prove_double_claim(a: EpochCommitment, b: EpochCommitment,
                       disclosure_a: dict[str, Any],
                       disclosure_b: dict[str, Any]) -> bool:
    """True if the same route id was billed in two different epochs."""
    if a.epoch == b.epoch:
        return False
    ra, rb = disclosure_a["receipt"], disclosure_b["receipt"]
    return (ra.get("routeId") == rb.get("routeId")
            and verify_proof(disclosure_a["leaf"], disclosure_a["proof"], a.root)
            and verify_proof(disclosure_b["leaf"], disclosure_b["proof"], b.root))


def prove_total_mismatch(commitment: EpochCommitment,
                         all_receipts: Iterable[TransportReceipt]) -> bool:
    """True if the claimed total does not match the disclosed receipt set."""
    rs = list(all_receipts)
    if merkle_root([r.leaf for r in rs]) != commitment.root:
        return False                      # different set; not this proof's job
    return sum(r.price_minor for r in rs) != commitment.total_minor


__all__ = [
    "TransportReceipt", "EpochCommitment", "RoutingLedger", "RouteClass",
    "sign_receipt", "verify_receipt", "merkle_root", "merkle_proof",
    "verify_proof", "bucket_count", "prove_bad_signature", "prove_not_in_tree",
    "prove_double_claim", "prove_total_mismatch", "TransportError",
    "EPOCH_SECONDS", "CHALLENGE_WINDOW", "TRANSPORT_SPEC_VERSION",
]
