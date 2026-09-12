# Conformance — prove an implementation speaks XCP

A federation is a protocol, not a program. If the only way to know whether your
gateway is correct is to read the Python reference and hope, the protocol
fragments — every implementation ends up subtly different and "federation"
degrades into "everyone talks to the reference implementation."

```bash
xcp conform https://gateway.example
xcp conform https://gateway.example --profile core,security --out report.json
```

## Black box, on purpose

The suite talks HTTP and **imports nothing** from the implementation under test.
A Go, Rust or TypeScript gateway gets the same verdict as this one. There is a
test asserting the suite never reaches into `core/`, `trustfirewall/` or `vault/`.

## The negative checks are the point

Most of what the suite does is confirm an implementation **refuses** things: an
unverified call, an out-of-scope mandate, an expired mandate, an unbound
footprint, an oversized body, an unmetered flood.

A suite that only exercised happy paths would certify nothing about a trust
layer — a gateway that accepts everything passes every happy-path test and is
worse than useless. That is tested too: the meta-tests run the suite against a
deliberately permissive gateway and assert it fails.

## MUST vs SHOULD

Failing a **MUST** means non-conformant. Failing a **SHOULD** is a warning and
does not disqualify. That distinction is load-bearing: a suite where everything
is mandatory gets ignored the first time a reasonable deployment fails it.

A refusal is a refusal — a check expecting `401` accepts `429`, because an
implementation that rate-limits the conformance run has not become
non-conformant. What must never happen is a `2xx`.

## Profiles

| profile | covers |
|---|---|
| `core` | session verification and the mandate gate |
| `stateless` | MCP 2026-07-28: no session header, header-derived scope |
| `security` | abuse controls |
| `federation` | node records and certificate bindings |

## Clauses

| clause | level | check |
|---|---|---|
| `XCP-CORE-001` | SHOULD | exposes a health endpoint |
| `XCP-CORE-002` | MUST | opens a session and returns a binding |
| `XCP-CORE-003` | MUST | refuses a call with no identity header |
| `XCP-CORE-004` | MUST | refuses a malformed identity header |
| `XCP-CORE-005` | MUST | refuses an unbound certificate footprint |
| `XCP-CORE-006` | MUST | refuses a call with no mandate |
| `XCP-CORE-007` | MUST | refuses a scope the mandate does not cover |
| `XCP-CORE-008` | MUST | refuses an expired mandate |
| `XCP-CORE-009` | MUST | accepts a valid session and mandate |
| `XCP-CORE-010` | SHOULD | error responses carry a reason |
| `XCP-STATELESS-001` | MUST | does not require a session id header |
| `XCP-STATELESS-002` | SHOULD | tolerates a legacy session id |
| `XCP-SEC-001` | MUST | rate limits an anonymous caller |
| `XCP-SEC-002` | SHOULD | a 429 carries `Retry-After` |
| `XCP-SEC-003` | MUST | rejects an oversized body |
| `XCP-FED-001` | MUST | publishes a node record |
| `XCP-FED-002` | MUST | the node record is well formed |
| `XCP-FED-003` | SHOULD | identity is not the certificate footprint |

## Conformance is evidence, not a badge

A passing `core` + `security` report is what a catalog needs to promote a server
from `unknown` to `probed` in the [Trust Firewall](trust-firewall.md).
The report serialises to JSON for exactly that: it is an input to somebody else's
trust decision, not a certificate to display.

## It has already found bugs

Running it against this repository's own gateway immediately surfaced that
unauthenticated calls were rejected **before** the rate limiter ran — so an
attacker could flood the `401` path indefinitely, and every rejection still cost
a registry lookup. That is fixed; the clause that caught it is `XCP-SEC-001`.

## Status

Draft, and clause numbering will change. Adding a check is a pull request against
`conformance/suite.py`; adding one that the reference implementation fails is
welcome and more useful than one it passes.
