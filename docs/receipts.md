# Receipts & Settlement

**Proof-of-delivery for agents that have never met.**

Agent A wants to pay agent B for work, with no prior relationship. A can't
release funds on a promise; B won't work without assurance of payment. Escrow
alone doesn't help, because releasing escrow still needs somebody to decide
whether the work happened.

Receipts make that decision **evidence-based**.

## Three artifacts

```
TaskSpec  →  CallChain  →  Receipt
commit       evidence      signed delivery
```

**TaskSpec** — what was commissioned, hashed *before* work begins. Both sides
hold the same task digest, so neither can move the goal.

**CallChain** — a tamper-evident hash chain of the tool calls that produced the
work. `h_i = keccak(h_{i-1} ‖ record_digest_i)`. Appending is O(1); reordering,
deleting or editing any call changes the root. It rides on the audit records the
gateway already produces, so it costs nothing extra.

**Receipt** — the payee signs (EIP-712) task digest + call-chain root + output
digest + amount. The payer countersigns to accept.

## What this proves — and what it doesn't

!!! success "Provable, cryptographically"
    - the work was **performed** — these calls, in this order, by this agent id
    - the deliverable is **exactly this artifact** (output digest binding)
    - both parties committed to **this task, at this price**, before work started
    - nobody altered the record afterwards

!!! failure "Not provable"
    That the output is **good**. Semantic quality is not a cryptographic property.

So receipts convert *"did they do the work?"* — unanswerable at a distance —
into *"does the evidence match the commitment?"*, which is mechanically
checkable. Acceptance stays an explicit decision, but one made against an
evidence bundle a third-party arbiter can re-verify offline.

## The escrow state machine

```
                     ┌──────────────► EXPIRED ──► REFUNDED
                     │  (deadline, no delivery)
    OPEN ────────────┤
   (funds committed) │
                     └─► DELIVERED ──┬─► ACCEPTED ──► RELEASED
                       (valid receipt)│
                                      └─► DISPUTED ──► RELEASED | REFUNDED
                                                        (arbiter, on evidence)
```

Rules that matter:

- Escrow never opens without a task commitment.
- `DELIVERED` requires a receipt that **verifies**. An invalid receipt is not a
  delivery, it's a rejected claim — state does not advance.
- Only the payer can accept. Only an arbiter can resolve a dispute.
- Nothing releases funds except acceptance or an arbiter ruling.
- **Auto-accept after a timeout is off by default.** It's a real convenience for
  high-volume machine commerce and a real footgun for everything else, so it has
  to be chosen explicitly.

This module models the decision and keeps the audit trail. It does **not** move
money — rail execution stays behind the payments plane, and the gateway holds no
funds. `ready_to_release()` is the hook a rail adapter calls.

## Usage

```python
from receipts import (TaskSpec, CallChain, build_receipt, sign_receipt,
                      accept_receipt, open_escrow)

task = TaskSpec(task_id="brief-07", payer_agent=1001, payee_agent=2002,
                description="Summarise 20 filings into a briefing",
                acceptance=["covers all 20", "under 2 pages"],
                amount_minor=25_000, currency="USDC", rail="x402",
                deadline=int(time.time()) + 3600)
esc = open_escrow(task, arbiter_agent=7777)

chain = CallChain()
chain.record(agent_id=2002, scope="mcp:tools/research.fetch", tool="fetch",
             args={"filing": "10-K"}, result={"pages": 40})

receipt = sign_receipt(payee_key, build_receipt(task, chain, output))
esc.deliver(receipt, chain)      # [] means verified
esc.accept(task.payer_agent)     # → RELEASED
esc.ready_to_release()           # True — the rail adapter may now settle
```

Verify someone else's bundle from the command line:

```bash
xcp receipt bundle.json
```

Run the demo:

```bash
python examples/settlement.py
```

## Integration with the trust lattice

Every settling tier in the default [lattice](trust-lattice.md) sets
`requires_receipt = True`. That invariant is tested: a tier cannot settle
without a proof-of-delivery obligation.

The [Trust Firewall](trust-firewall.md) carries the same obligation from the
counterparty's trust class — settlement toward an `attested` or `contracted`
server always inherits `requireReceipt`.
