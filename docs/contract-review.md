# Contract review

**This is not an independent audit.** It is a record of compiling and executing
the contracts for the first time, and what that surfaced. An external audit is
still required before these hold anything of value — see
[Status](#status-and-what-is-still-missing).

## Findings

| id | severity | finding | status |
|---|---|---|---|
| NR-1 | low | The hand-maintained `SessionRegistry.abi.json` was incomplete: four public-variable getters (`MAX_TTL`, `agentController`, `controllerOf`, `isGuardian`) were absent, so a client could not read state the contract exposes. | fixed — ABIs are generated, never hand-edited |
| NR-2 | **high** | `challengeDoubleClaim` recorded a route id on a bare call. A stranger could poison an arbitrary id, then slash the honest node that later billed it legitimately. | fixed — Merkle membership is verified *before* the id is recorded |
| NR-3 | medium | 80% of every slashed bond was permanently unreachable and undocumented — it looked like stuck funds rather than a decision. | fixed — tracked in `totalForfeited`, and burning it is now the stated design |
| NR-4 | **high** | No unbond path. Stake was unrecoverable even for an honest operator, so nobody rational would bond, which removes the Sybil resistance the bond exists to provide. | fixed — `requestUnbond` / `withdrawBond` with a cooldown longer than the challenge window |

NR-2 and NR-4 were found by *executing* the contract, not by reading it. That is
the argument for the test suite existing at all.

### A correction

A first pass reported that the ABI declared a function the contract did not
have. That was wrong: the diff had compared against `ISessionRegistry`, the
interface, rather than the contract. The real problem was the opposite — missing
entries, not phantom ones. Recorded because a security note that overstates a
finding is its own kind of defect.

## Design decisions a reviewer should challenge

**Forfeited stake is burned.** A slash must be a deterrent, not a revenue
stream; making the remainder withdrawable would create a party that profits from
slashing others. The cost is that value leaves the system permanently.

**Challenger reward is 20%.** High enough that someone has a reason to watch,
low enough that frivolous challenges are unattractive. The number is a guess and
has not been modelled.

**Claims are optimistic.** A node posts a commitment and withdraws after a
window. This is only as strong as the assumption that somebody checks — weak in
a sparse federation. Consider a longer window or a paid watcher early on.

**`UNBOND_DELAY` (14d) exceeds `CHALLENGE_WINDOW` (7d)** so an operator cannot
post a fraudulent claim and exit before anyone can contest it. Tested.

## What was checked

- Compiles clean under solc 0.8.24 with the optimiser, no warnings.
- Deployed to an in-process EVM and exercised: registration, bonds, revocation,
  cluster membership proofs, claim lifecycle, challenge, slash, unbond.
- Access control: under-bonded registration, stranger revoke, stranger unbond,
  duplicate registration, early settle, early withdraw — all revert.
- Effects precede interactions in `_slash` and `withdrawBond` (CEI).
- CI recompiles and fails if the committed ABIs drift from the sources.

## Status and what is still missing

- **No independent audit.** No formal verification, no fuzzing, no economic
  modelling of the bond and reward parameters.
- **Never deployed to a public network.** `scripts/deploy-contracts.py` runs
  against an in-process EVM by default; point it at a testnet RPC to deploy.
- **No reentrancy guard.** The two external calls follow checks-effects-
  interactions, which is sufficient for the current shape, but a reviewer should
  confirm that holds as the contract grows.
- **Gas is unmeasured** beyond deployment cost.
- Staking real value is a regulated activity in most jurisdictions. Get legal
  advice before this holds anything.
