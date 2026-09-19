# Receipts

Proof-of-delivery and evidence-conditioned settlement.

```python
from receipts import (TaskSpec, CallChain, build_receipt, sign_receipt,
                      accept_receipt, open_escrow)

task = TaskSpec(task_id="brief-07", payer_agent=1001, payee_agent=2002,
                description="Summarise 20 filings", amount_minor=25_000,
                rail="x402", deadline=deadline)
esc = open_escrow(task, arbiter_agent=7777)

chain = CallChain()
chain.record(2002, "mcp:tools/research.fetch", "fetch", args, result)

r = sign_receipt(payee_key, build_receipt(task, chain, output))
esc.deliver(r, chain)          # [] means verified
esc.accept(task.payer_agent)   # → RELEASED
```

## What it proves

**Provable**: the work was performed (these calls, this order, this agent), the
deliverable is exactly this artifact, both parties committed to this task at
this price before work started, and nobody altered the record.

**Not provable**: that the output is *good*. Quality is not a cryptographic
property. Acceptance stays an explicit decision — but one made against evidence
an arbiter can re-check offline.

## Invariants (tested)

- A receipt that fails verification is **not a delivery** — escrow does not advance.
- Delivery alone never releases funds; acceptance or an arbiter ruling does.
- Auto-accept after a timeout is **off by default**.
- Every settling tier in the trust lattice requires a receipt.
- Editing, reordering or deleting any call breaks the chain root.

`xcp receipt <bundle.json>` verifies a bundle from the command line.

Full docs: [docs/receipts.md](../docs/receipts.md) ·
demo: `python examples/settlement.py`
