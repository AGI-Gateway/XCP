# Privacy — retention, erasure, and the tension between them

XCP deliberately holds personal data. The trust lattice is **built** on knowing
which human an agent acts for: `H1` is a verified individual, `H2` adds
entitlements — groups, cost centre, approval limit. Receipts then tie that
principal to specific actions in a tamper-evident chain.

That collides with the right to erasure, and the collision is real rather than
rhetorical: `receipts.CallChain` is designed so that removing a record changes
the root. **The property that makes the audit trustworthy is the property that
makes it undeletable.**

Two wrong answers are common. This module exists to avoid both.

- Delete everything on request, including financial records the operator is
  legally obliged to keep.
- Refuse all erasure citing "immutability", which is not a lawful basis.

## The resolution: crypto-shredding

Never put personal data *in* the immutable structure. Encrypt it under a key
belonging to one subject, and commit to the **ciphertext**:

```
leaf = H(ciphertext)     stable forever — the chain never breaks
plaintext                readable only with the subject's key
```

Erasure destroys the key. The ciphertext remains, now indistinguishable from
noise; the chain still verifies and everyone who recorded that root is still
correct. What is lost is exactly what should be lost.

```python
from privacy import KeyRing, seal, unseal, erase

ring = KeyRing()
sealed = seal(ring, "sub_ab12", {"tool": "fetch", "args": {...}})
chain.append(CallRecord(..., args_digest=sealed.commitment))

erase(ring, "sub_ab12", held=[("call_chain", created_at)])
unseal(ring, sealed)     # ShredError — irreversible, including for us
chain.verify()           # still True; the root is unchanged
```

!!! warning "Hashing alone does not discharge an erasure obligation"
    A hash of personal data is **still personal data** when it is linkable —
    anyone with a candidate value can confirm a match. Hashing is
    pseudonymisation, not anonymisation. That is why erasure here destroys
    *keys* rather than relying on `args_digest`.

## Erasure is not absolute, and the response must say so

Under GDPR Art. 17(3), erasure does not apply where processing is necessary for
a legal obligation or to defend legal claims. A settled payment record is
usually in that category.

An erasure report therefore states three things — most implementations manage
only the first:

1. what **was** erased
2. what was **not**
3. the lawful basis for keeping it, and the date it goes anyway

```
  Erased:
    - call_chain, entitlements
  Retained, and why:
    - settlement_receipt (legal_obligation) until 2033-09-11
    - security_audit (legitimate_interest) until 2027-03-12

  This erasure is PARTIAL.
```

"No" without a basis and an end date is not a defensible answer to a data
subject. Neither is a silent partial deletion that leaves them believing more was
removed than actually was.

## What is held

```bash
xcp privacy map          # the Art. 30 record of processing
xcp privacy retention    # what is erasable and what is not
xcp privacy erase --subject sub_ab12
```

| class | subject | basis | days | erasable |
|---|---|---|---:|---|
| `session_binding` | human | contract | 7 | yes |
| `entitlements` | human | contract | 1 | yes |
| `call_chain` | human | contract | 90 | yes |
| `security_audit` | human | legitimate interest | 180 | **no** |
| `settlement_receipt` | human | legal obligation | 2555 | **no** |
| `unsettled_receipt` | human | contract | 90 | yes |
| `node_record` | operator | legitimate interest | — | yes |
| `catalog` | none | legitimate interest | — | yes |
| `credential` | human | contract | — | **never stored** |

Anything not in this table should not be stored. If a new field does not fit a
class, that is a signal to reconsider collecting it.

Two deliberate choices: `entitlements` is the shortest-lived class because it is
the most directly identifying data in the system, and `unsettled_receipt` is
separated from `settlement_receipt` because no financial obligation attaches to
work that was never paid for — so the Art. 17(3) exemption does not apply.

## Controller or processor

An operator routing for **their own** users is a controller. An operator routing
for **another organisation's** users is a **processor**, and that organisation is
the controller — a processor agreement is required before federating. This is the
first question an adopter's legal team will ask.

## Limits worth stating

- **Shredding does not reach copies held by peers.** A federation that gossiped a
  payload cannot un-gossip it. This is why the codebase keeps personal data out
  of anything it publishes: transport commitments carry totals and never
  counterparties, and catalogs carry none at all. Erasure is scoped to what this
  node holds; a processor agreement has to cover the rest.
- **Key destruction must reach backups.** `KeyRing.destroy` removes the key from
  the process. Removing it from snapshots and replicas is an operational
  obligation this code cannot discharge.
- **Federation is an international transfer** by design. Peering across a border
  needs its own basis under Art. 44+. Peers are explicit, so it is a decision
  rather than a default.
- **Retention periods are defaults, not advice.** Confirm them against your own
  jurisdiction and sector.

This is a design. It is not legal advice, and it has not been reviewed by a
privacy lawyer.
