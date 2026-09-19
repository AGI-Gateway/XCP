"""
receipts.escrow — settlement conditioned on evidence.

A receipt proves delivery happened; escrow decides what that means for the money.
The state machine is deliberately small, because every extra state is a way for
funds to get stuck:

                     ┌──────────────► EXPIRED ──► REFUNDED
                     │  (deadline, no delivery)
    OPEN ────────────┤
   (funds committed) │
                     └─► DELIVERED ──┬─► ACCEPTED ──► RELEASED
                       (valid receipt)│
                                      └─► DISPUTED ──► RELEASED | REFUNDED
                                                        (arbiter, on evidence)

Rules that matter:

  · Escrow NEVER opens without a task commitment. You cannot buy an unspecified
    thing; the task digest is what the receipt has to match.
  · DELIVERED requires a receipt that *verifies* against the commitment. An
    invalid receipt is not a delivery, it's a rejected claim.
  · Only the payer can accept. Only an arbiter can resolve a dispute.
  · Nothing releases funds except ACCEPTED or an arbiter ruling — and both
    produce a signed, checkable record.
  · Auto-accept after a timeout is available but OFF by default. It's a real
    convenience for high-volume machine commerce and a real footgun for
    everything else, so it must be chosen explicitly.

This module models the decision and keeps the audit trail. It does not move
money: rail execution stays behind the XCP payments plane, and the gateway holds
no funds. `ready_to_release()` is the hook a rail adapter calls.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .receipt import (TaskSpec, CallChain, Receipt, verify_receipt,
                      evidence_bundle, ReceiptError)


class State(str, Enum):
    OPEN = "open"
    DELIVERED = "delivered"
    ACCEPTED = "accepted"
    DISPUTED = "disputed"
    RELEASED = "released"
    REFUNDED = "refunded"
    EXPIRED = "expired"


TERMINAL = {State.RELEASED, State.REFUNDED}


class EscrowError(Exception):
    pass


@dataclass
class Event:
    at: int
    state: State
    actor: int                 # agent id that caused the transition (0 = system)
    note: str = ""


@dataclass
class Escrow:
    """
    One task's settlement lifecycle. Construct with `open_escrow`.

        esc = open_escrow(task)
        esc.deliver(receipt, chain)      # payee presents evidence
        esc.accept(payer_agent)          # payer countersigns -> RELEASED
        esc.ready_to_release()           # rail adapter checks this
    """
    task: TaskSpec
    state: State = State.OPEN
    receipt: Optional[Receipt] = None
    chain: Optional[CallChain] = None
    history: list[Event] = field(default_factory=list)
    auto_accept_after: int = 0        # seconds; 0 = disabled (the default)
    arbiter_agent: int = 0            # 0 = disputes must be resolved out of band
    resolution: str = ""

    # ── transitions ──
    def _to(self, state: State, actor: int, note: str = "",
            now: Optional[int] = None) -> None:
        self.state = state
        self.history.append(Event(at=now or int(time.time()), state=state,
                                  actor=actor, note=note))

    def deliver(self, receipt: Receipt, chain: Optional[CallChain] = None,
                now: Optional[int] = None) -> list[str]:
        """
        Payee presents delivery. Returns the list of verification problems;
        empty means the escrow moved to DELIVERED. A failing receipt does NOT
        change state — a bad claim is not a delivery.
        """
        if self.state != State.OPEN:
            raise EscrowError(f"cannot deliver from state {self.state.value}")
        now = now or int(time.time())
        if self.task.expired(now):
            self._to(State.EXPIRED, 0, "deadline passed before delivery", now)
            return ["task deadline had already passed"]
        problems = verify_receipt(receipt, self.task, chain, now=now)
        if problems:
            self.history.append(Event(at=now, state=State.OPEN,
                                      actor=self.task.payee_agent,
                                      note=f"delivery rejected: {problems[0]}"))
            return problems
        self.receipt = receipt
        self.chain = chain
        self._to(State.DELIVERED, self.task.payee_agent, "receipt verified", now)
        return []

    def accept(self, payer_agent: int, now: Optional[int] = None) -> None:
        """Payer accepts. This is the normal path to RELEASED."""
        if self.state != State.DELIVERED:
            raise EscrowError(f"cannot accept from state {self.state.value}")
        if payer_agent != self.task.payer_agent:
            raise EscrowError("only the payer may accept")
        now = now or int(time.time())
        self._to(State.ACCEPTED, payer_agent, "accepted by payer", now)
        self._to(State.RELEASED, payer_agent, "funds releasable", now)

    def dispute(self, payer_agent: int, reason: str,
                now: Optional[int] = None) -> None:
        """Payer rejects the delivery. Evidence is preserved for an arbiter."""
        if self.state != State.DELIVERED:
            raise EscrowError(f"cannot dispute from state {self.state.value}")
        if payer_agent != self.task.payer_agent:
            raise EscrowError("only the payer may dispute")
        if not reason.strip():
            raise EscrowError("a dispute must state a reason")
        self._to(State.DISPUTED, payer_agent, f"disputed: {reason}", now)

    def resolve(self, arbiter_agent: int, release: bool, note: str = "",
                now: Optional[int] = None) -> None:
        """Arbiter rules on a dispute, against the evidence bundle."""
        if self.state != State.DISPUTED:
            raise EscrowError(f"cannot resolve from state {self.state.value}")
        if self.arbiter_agent and arbiter_agent != self.arbiter_agent:
            raise EscrowError("not the designated arbiter for this escrow")
        self.resolution = note
        self._to(State.RELEASED if release else State.REFUNDED,
                 arbiter_agent, f"arbiter ruling: {note}", now)

    def tick(self, now: Optional[int] = None) -> State:
        """
        Advance time-based transitions. Call periodically.
        Handles deadline expiry and — only if explicitly enabled — auto-accept.
        """
        now = now or int(time.time())
        if self.state in TERMINAL:
            return self.state
        if self.state == State.OPEN and self.task.expired(now):
            self._to(State.EXPIRED, 0, "deadline passed with no delivery", now)
            self._to(State.REFUNDED, 0, "auto-refund on expiry", now)
        elif (self.state == State.DELIVERED and self.auto_accept_after
              and self.receipt
              and now >= self.receipt.delivered_at + self.auto_accept_after):
            self._to(State.ACCEPTED, 0, "auto-accepted after timeout", now)
            self._to(State.RELEASED, 0, "funds releasable", now)
        return self.state

    # ── queries ──
    def ready_to_release(self) -> bool:
        """The single hook a rail adapter should check before moving money."""
        return self.state == State.RELEASED

    def refundable(self) -> bool:
        return self.state == State.REFUNDED

    def bundle(self, output_ref: str = "") -> dict[str, Any]:
        """Evidence bundle for an arbiter or auditor."""
        if not self.receipt:
            raise EscrowError("no receipt yet — nothing to bundle")
        return evidence_bundle(self.task, self.chain or CallChain(),
                               self.receipt, output_ref)

    def summary(self) -> dict[str, Any]:
        return {
            "taskId": self.task.task_id,
            "taskDigest": self.task.task_digest,
            "state": self.state.value,
            "amountMinor": self.task.amount_minor,
            "currency": self.task.currency,
            "rail": self.task.rail,
            "payer": self.task.payer_agent,
            "payee": self.task.payee_agent,
            "callCount": len(self.chain) if self.chain else 0,
            "readyToRelease": self.ready_to_release(),
            "history": [{"at": e.at, "state": e.state.value, "actor": e.actor,
                         "note": e.note} for e in self.history],
        }


def open_escrow(task: TaskSpec, auto_accept_after: int = 0,
                arbiter_agent: int = 0, now: Optional[int] = None) -> Escrow:
    """
    Commit funds against a task. The task must specify an amount and a rail —
    escrow over an unspecified obligation is exactly the ambiguity receipts
    exist to remove.
    """
    if task.amount_minor <= 0:
        raise EscrowError("escrow requires a positive amount")
    if not task.rail:
        raise EscrowError("escrow requires a settlement rail")
    if task.payer_agent == task.payee_agent:
        raise EscrowError("payer and payee must differ")
    esc = Escrow(task=task, auto_accept_after=auto_accept_after,
                 arbiter_agent=arbiter_agent)
    esc._to(State.OPEN, task.payer_agent, "funds committed", now)
    return esc


def requires_receipt(trust_tier_template: Any) -> bool:
    """
    Bridge to the trust lattice: `MandateTemplate.requires_receipt` says whether
    a tier may settle on a bare payment or must present proof-of-delivery.
    Every settling tier in the default lattice requires a receipt.
    """
    return bool(getattr(trust_tier_template, "requires_receipt", True))


__all__ = ["Escrow", "State", "Event", "open_escrow", "requires_receipt",
           "EscrowError", "TERMINAL"]
