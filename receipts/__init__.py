"""
receipts — proof-of-delivery and evidence-conditioned settlement for XCP.

    from receipts import TaskSpec, CallChain, build_receipt, sign_receipt, open_escrow

Receipts prove the work was *performed* and the deliverable is *exactly this
artifact*. They do not prove the output is good — quality is not a cryptographic
property. What they change is that acceptance becomes a decision made against
verifiable evidence, and a third party can re-check it offline.
"""
from .receipt import (TaskSpec, CallRecord, CallChain, Receipt, build_receipt,
                      sign_receipt, accept_receipt, verify_receipt,
                      evidence_bundle, verify_bundle, digest, canonical,
                      ReceiptError, RECEIPT_SPEC_VERSION, GENESIS)
from .escrow import (Escrow, State, Event, open_escrow, requires_receipt,
                     EscrowError, TERMINAL)

__all__ = [
    "TaskSpec", "CallRecord", "CallChain", "Receipt", "build_receipt",
    "sign_receipt", "accept_receipt", "verify_receipt", "evidence_bundle",
    "verify_bundle", "digest", "canonical", "ReceiptError",
    "RECEIPT_SPEC_VERSION", "GENESIS",
    "Escrow", "State", "Event", "open_escrow", "requires_receipt",
    "EscrowError", "TERMINAL",
]
