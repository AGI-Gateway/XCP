# Compliance

## Three kinds of control, and why the distinction matters

| | used when | strength |
|---|---|---|
| **Software control** | the obligation is technical | strongest — it either works or a test fails |
| **Measurement** | the residual is computable | strong — a number, not a promise |
| **Covenant** | it is neither | weakest — a commitment someone must keep |

Three residuals originally recorded as "organisational" moved to measurement on
review, because a gap you can measure should not be left to a promise:

- **DORA Art. 29 concentration risk** → `concentration()` computes an HHI over
  your peers and names capabilities only one peer supplies, which is the sharper
  risk than the headline share.
- **SOC 2 A1 availability** → a state inventory with RPO/RTO per item, naming
  the one item whose loss is unrecoverable (the node identity key).
- **DORA Art. 24-27 resilience** → seven named degradation scenarios with
  expected behaviour, each drawn from a defect this build actually had.

```bash
xcp compliance coverage     # the honest summary
xcp compliance gaps         # what is still open, and who carries it
xcp compliance covenants --annex --owner operator
xcp compliance recovery
```

## Covenants

Sixteen commitments the software cannot make for you. Each names **who owes it**,
**what discharges it**, **which clauses it answers**, and **why it cannot be
automated** — a commitment missing any of those is not enforceable.

`--annex` prints them as numbered contract clauses, ready for a DPA, a
procurement schedule or a DORA Art. 30 contract.

| | owes | carries |
|---|---|---|
| `COV-01/02` | deployer | Annex III classification; provider status under Art. 25 |
| `COV-03` | **application** | AI Act Art. 50 disclosure — XCP has no interface to a human |
| `COV-04/05/06` | deployer | DPIA, FRIA, discrimination testing |
| `COV-07` | deployer | a named, trained human actually watching |
| `COV-08` | operator | which retention floor applies, and the reconciliation |
| `COV-09/10/11` | operator | DORA Art. 30 terms, processor agreements, transfer bases |
| `COV-12/13` | operator | rehearsed recovery; incident classification and reporting |
| `COV-14` | operator | the SOC 2 control environment — people and process |
| `COV-15` | operator | erasure reaching backups, where it most often fails |
| `COV-16` | operator | independent pen testing and a contract audit |

A test fails if any control marked `gap` or `operator` does not name the covenant
carrying it, so nothing is left dangling.

!!! warning "What none of this is"
    Not compliance, not certification, not legal advice, and not reviewed by
    counsel. Compliance is determined by lawyers and, for SOC 2, by a licensed
    CPA firm attesting to your organisation's controls over a period of
    observation. This is a mapping with an explicit gap register.
