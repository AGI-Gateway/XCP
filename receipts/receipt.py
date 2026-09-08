"""
receipts.receipt — proof-of-delivery for agent↔agent settlement.

The problem this solves: agent A wants to pay agent B for work, and neither has
a prior relationship. A can't release funds on a promise; B won't work without
assurance of payment. Escrow alone doesn't help, because releasing escrow still
requires somebody to decide whether the work happened.

Receipts make that decision *evidence-based*. Three artifacts bind together:

  1. TaskSpec    — what was commissioned, hashed before work begins. Both sides
                   commit to the same task digest, so neither can move the goal.
  2. CallChain   — a tamper-evident hash chain of the tool calls that produced
                   the work. Appending is cheap; reordering, removing or editing
                   a call breaks the chain. This rides on XCP's existing audit
                   records, so it costs nothing extra to produce.
  3. Receipt     — the payee signs (EIP-712) task digest + call-chain root +
                   output digest + amount. The payer countersigns to accept.

WHAT THIS PROVES — and what it does not
---------------------------------------
Provable, cryptographically:
  · the work was *performed* — these calls, in this order, by this agent id
  · the deliverable is *exactly* this artifact (output digest binding)
  · both parties committed to *this* task, at this price, before work started
  · nobody altered the record afterwards

NOT provable:
  · that the output is *good*. Semantic quality is not a cryptographic property.

So receipts convert "did they do the work?" (unanswerable at a distance) into
"does the evidence match the commitment?" (mechanically checkable), and leave
acceptance as an explicit decision — but a decision made against a verifiable
evidence bundle a third-party arbiter can re-check offline.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_utils import keccak as _keccak
    _ETH = True
except ImportError:                                   # pragma: no cover
    _ETH = False

RECEIPT_SPEC_VERSION = "0.1-draft"


def digest(data: bytes) -> str:
    """keccak256 when the crypto stack is present, sha3-256 as a stand-in."""
    if _ETH:
        return "0x" + _keccak(data).hex()
    return "0x" + hashlib.sha3_256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding — the basis of every digest here."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


class ReceiptError(Exception):
    pass


# ── 1. the commitment ──────────────────────────────────────────────────────

@dataclass
class TaskSpec:
    """What was commissioned. Hashed *before* work starts; both sides hold it."""
    task_id: str
    payer_agent: int
    payee_agent: int
    description: str
    acceptance: list[str] = field(default_factory=list)   # human/agent-readable criteria
    amount_minor: int = 0
    currency: str = "USDC"
    rail: str = "x402"                                    # x402 | ap2 | mpp | acp
    deadline: int = 0                                     # unix seconds
    chain_id: int = 8453
    spec_version: str = RECEIPT_SPEC_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def task_digest(self) -> str:
        return digest(canonical(self.to_dict()))

    def expired(self, now: Optional[int] = None) -> bool:
        return bool(self.deadline) and (now or int(time.time())) > self.deadline


# ── 2. the evidence ────────────────────────────────────────────────────────

@dataclass
class CallRecord:
    """One governed action. Mirrors what the gateway already audits."""
    seq: int
    agent_id: int
    scope: str                  # e.g. "mcp:tools/research.fetch"
    tool: str
    args_digest: str
    result_digest: str
    ts: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def record_digest(self) -> str:
        return digest(canonical(self.to_dict()))


GENESIS = "0x" + "00" * 32


class CallChain:
    """
    Append-only hash chain over CallRecords:

        h_0 = GENESIS
        h_i = keccak(h_{i-1} || record_digest_i)

    Reordering, deleting or editing any call changes the root. Building the
    chain is O(1) per call, so it can run inline in the gateway.
    """

    def __init__(self, records: Optional[list[CallRecord]] = None) -> None:
        self._records: list[CallRecord] = []
        self._head = GENESIS
        for r in records or []:
            self.append(r)

    @staticmethod
    def _link(prev: str, rec_digest: str) -> str:
        return digest(bytes.fromhex(prev[2:]) + bytes.fromhex(rec_digest[2:]))

    def append(self, record: CallRecord) -> str:
        if record.seq != len(self._records):
            raise ReceiptError(
                f"out-of-order call: expected seq {len(self._records)}, got {record.seq}")
        self._head = self._link(self._head, record.record_digest)
        self._records.append(record)
        return self._head

    def record(self, agent_id: int, scope: str, tool: str,
               args: Any, result: Any, ts: Optional[int] = None) -> str:
        """Convenience: hash args/result and append."""
        return self.append(CallRecord(
            seq=len(self._records), agent_id=agent_id, scope=scope, tool=tool,
            args_digest=digest(canonical(args)),
            result_digest=digest(canonical(result)),
            ts=ts or int(time.time())))

    @property
    def root(self) -> str:
        return self._head

    @property
    def records(self) -> list[CallRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)

    def verify(self) -> bool:
        """Recompute the chain from scratch; True iff nothing was tampered with."""
        h = GENESIS
        for i, r in enumerate(self._records):
            if r.seq != i:
                return False
            h = self._link(h, r.record_digest)
        return h == self._head

    def scopes_used(self) -> list[str]:
        return sorted({r.scope for r in self._records})

    def to_dict(self) -> dict[str, Any]:
        return {"root": self.root, "count": len(self._records),
                "records": [r.to_dict() for r in self._records]}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "CallChain":
        chain = CallChain([CallRecord(**r) for r in d.get("records", [])])
        if d.get("root") and chain.root != d["root"]:
            raise ReceiptError("call chain root does not match its records")
        return chain


# ── 3. the receipt ─────────────────────────────────────────────────────────

@dataclass
class Receipt:
    """Payee's signed assertion of delivery, bound to the commitment."""
    task_digest: str
    call_chain_root: str
    output_digest: str
    payee_agent: int
    amount_minor: int
    delivered_at: int
    call_count: int
    chain_id: int = 8453
    spec_version: str = RECEIPT_SPEC_VERSION
    payee_address: str = ""
    signature: str = ""
    # acceptance (payer countersignature)
    accepted_by: int = 0
    acceptor_address: str = ""
    acceptance_sig: str = ""

    def signing_payload(self) -> dict[str, Any]:
        return {
            "taskDigest": self.task_digest,
            "callChainRoot": self.call_chain_root,
            "outputDigest": self.output_digest,
            "payeeAgent": self.payee_agent,
            "amountMinor": self.amount_minor,
            "deliveredAt": self.delivered_at,
            "callCount": self.call_count,
        }

    @property
    def receipt_digest(self) -> str:
        return digest(canonical(self.signing_payload()))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _typed(payload: dict[str, Any], chain_id: int, primary: str) -> dict:
    fields = [
        {"name": "taskDigest", "type": "string"},
        {"name": "callChainRoot", "type": "string"},
        {"name": "outputDigest", "type": "string"},
        {"name": "payeeAgent", "type": "uint256"},
        {"name": "amountMinor", "type": "uint256"},
        {"name": "deliveredAt", "type": "uint64"},
        {"name": "callCount", "type": "uint32"},
    ]
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            primary: fields,
        },
        "primaryType": primary,
        "domain": {"name": "XCPReceipt", "version": "1", "chainId": chain_id},
        "message": payload,
    }


def build_receipt(task: TaskSpec, chain: CallChain, output: Any,
                  delivered_at: Optional[int] = None) -> Receipt:
    """Assemble an unsigned receipt from the commitment and the evidence."""
    if not chain.verify():
        raise ReceiptError("call chain failed verification — refusing to build a receipt")
    return Receipt(
        task_digest=task.task_digest,
        call_chain_root=chain.root,
        output_digest=digest(canonical(output)),
        payee_agent=task.payee_agent,
        amount_minor=task.amount_minor,
        delivered_at=delivered_at or int(time.time()),
        call_count=len(chain),
        chain_id=task.chain_id,
    )


def sign_receipt(private_key: str, receipt: Receipt) -> Receipt:
    """Payee signs delivery (EIP-712)."""
    if not _ETH:
        raise ReceiptError("eth-account required to sign receipts")
    typed = _typed(receipt.signing_payload(), receipt.chain_id, "Delivery")
    acct = Account.from_key(private_key)
    sig = Account.sign_message(encode_typed_data(full_message=typed),
                               private_key=private_key).signature.hex()
    receipt.payee_address = acct.address
    receipt.signature = sig if sig.startswith("0x") else "0x" + sig
    return receipt


def accept_receipt(private_key: str, receipt: Receipt, payer_agent: int) -> Receipt:
    """Payer countersigns acceptance — this is what releases escrow."""
    if not _ETH:
        raise ReceiptError("eth-account required to accept receipts")
    typed = _typed(receipt.signing_payload(), receipt.chain_id, "Acceptance")
    acct = Account.from_key(private_key)
    sig = Account.sign_message(encode_typed_data(full_message=typed),
                               private_key=private_key).signature.hex()
    receipt.accepted_by = payer_agent
    receipt.acceptor_address = acct.address
    receipt.acceptance_sig = sig if sig.startswith("0x") else "0x" + sig
    return receipt


def verify_receipt(receipt: Receipt, task: TaskSpec,
                   chain: Optional[CallChain] = None,
                   expected_payee_address: str = "",
                   now: Optional[int] = None) -> list[str]:
    """
    Check a receipt against its commitment. Returns a list of problems — empty
    means the evidence is internally consistent and correctly signed.

    This verifies provenance and integrity. It does NOT judge output quality.
    """
    problems: list[str] = []
    now = now or int(time.time())

    if receipt.task_digest != task.task_digest:
        problems.append("receipt is bound to a different task than the one presented")
    if receipt.payee_agent != task.payee_agent:
        problems.append("payee agent does not match the task")
    if receipt.amount_minor != task.amount_minor:
        problems.append(
            f"amount mismatch: receipt {receipt.amount_minor} vs task {task.amount_minor}")
    if task.deadline and receipt.delivered_at > task.deadline:
        problems.append("delivered after the deadline")
    if receipt.delivered_at > now + 300:
        problems.append("delivery timestamp is in the future")

    if chain is not None:
        if not chain.verify():
            problems.append("call chain is inconsistent (tampered or reordered)")
        if chain.root != receipt.call_chain_root:
            problems.append("call chain root does not match the receipt")
        if len(chain) != receipt.call_count:
            problems.append("call count does not match the chain")
        if len(chain) == 0:
            problems.append("no calls recorded — nothing evidences the work")

    if not receipt.signature:
        problems.append("receipt is unsigned")
    elif _ETH:
        try:
            typed = _typed(receipt.signing_payload(), receipt.chain_id, "Delivery")
            rec = Account.recover_message(encode_typed_data(full_message=typed),
                                          signature=receipt.signature)
            if receipt.payee_address and rec.lower() != receipt.payee_address.lower():
                problems.append("signature does not match the declared payee address")
            if expected_payee_address and rec.lower() != expected_payee_address.lower():
                problems.append("signer is not the expected payee")
        except Exception as e:
            problems.append(f"signature failed to recover: {e}")

    if receipt.acceptance_sig and _ETH:
        try:
            typed = _typed(receipt.signing_payload(), receipt.chain_id, "Acceptance")
            rec = Account.recover_message(encode_typed_data(full_message=typed),
                                          signature=receipt.acceptance_sig)
            if receipt.acceptor_address and rec.lower() != receipt.acceptor_address.lower():
                problems.append("acceptance signature does not match the acceptor address")
        except Exception as e:
            problems.append(f"acceptance signature failed to recover: {e}")

    return problems


# ── evidence bundle: what a third party checks ─────────────────────────────

def evidence_bundle(task: TaskSpec, chain: CallChain, receipt: Receipt,
                    output_ref: str = "") -> dict[str, Any]:
    """
    A self-contained, offline-verifiable record of the transaction. This is what
    you hand an arbiter, an auditor, or a counterparty's compliance team.
    `output_ref` is an optional pointer (URL, CID) to the artifact itself — the
    digest in the receipt is what binds it.
    """
    return {
        "specVersion": RECEIPT_SPEC_VERSION,
        "task": task.to_dict(),
        "callChain": chain.to_dict(),
        "receipt": receipt.to_dict(),
        "outputRef": output_ref,
    }


def verify_bundle(bundle: dict[str, Any], now: Optional[int] = None) -> list[str]:
    """Re-verify an evidence bundle from scratch. Empty list = consistent."""
    try:
        task = TaskSpec(**bundle["task"])
        chain = CallChain.from_dict(bundle["callChain"])
        receipt = Receipt(**bundle["receipt"])
    except ReceiptError as e:
        return [str(e)]
    except Exception as e:
        return [f"malformed bundle: {e}"]
    return verify_receipt(receipt, task, chain, now=now)


__all__ = [
    "TaskSpec", "CallRecord", "CallChain", "Receipt",
    "build_receipt", "sign_receipt", "accept_receipt", "verify_receipt",
    "evidence_bundle", "verify_bundle", "digest", "canonical",
    "ReceiptError", "RECEIPT_SPEC_VERSION", "GENESIS",
]
