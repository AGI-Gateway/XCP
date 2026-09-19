# Security audit — September 2026

Self-audit of the published tree at `99f54e3`. **Not an independent review.**
Every finding below has a test in `tests/test_security_audit.py` that reproduces
the attack and asserts it now fails.

| id | severity | finding | status |
|---|---|---|---|
| XCP-A-01 | **critical** | `/admin/revoke` had no authentication. One unauthenticated request revoked any session by footprint — a denial of service against every agent on the node. | fixed |
| XCP-A-02 | **critical** | `/v1/federation/revoke` took the originating peer's domain from the request body. With the peer list also public, anyone could name a real peer and revoke any node. | fixed |
| XCP-A-03 | high | `/v1/federation/peer` fetched a caller-supplied URL with no egress control — server-side request forgery reaching cloud metadata and internal services. The fetch error was returned verbatim, making it an oracle. | fixed |
| XCP-A-04 | high | The same fetch ran with `verify=False`, and then reported `tlsVerified: true` for any `https` URL. Worse than not checking: it told the operator a check had happened. | fixed |
| XCP-A-05 | medium | `/v1/federation/peers` published the full topology unauthenticated. This was the reconnaissance that made XCP-A-02 practical. | fixed |
| XCP-A-06 | medium | Five endpoints, including the kill switch, were exempt from rate limiting. | fixed |

## Fixes

**Admin authentication.** `XCP_ADMIN_TOKEN`, compared with `hmac.compare_digest`.
When unset the administrative endpoints are **disabled**, not open — an admin
surface that defaults to open is worse than one that does not exist.

**Signed revocation.** `federation.sign_revocation` / `verify_revocation`. A
revocation must carry an EIP-712 signature from the issuing node's key, is
checked against that peer's known `node_id`, and expires after an hour so an old
revocation cannot be replayed to take a live node down.

**Egress control.** `security/xcpsec/egress.py` validates the **resolved
address**, not the URL string — a hostname an attacker controls can resolve
wherever they like. Private, loopback, link-local, CGNAT and IPv4-mapped ranges
are refused; redirects are not followed, since an open redirector on a benign
host would otherwise defeat the check; responses are size-capped; errors are
generic. `XCP_ALLOW_INSECURE_PEERS=1` opts out for local development only.

**Topology redacted** behind the admin token, consistent with the rest of the
privacy design, which already keeps counterparties out of what it publishes.

## A design issue the fix surfaced

Metering the federation endpoints put them in the anonymous bucket, which is
sized for hostile traffic — about four calls a minute. Peering is unauthenticated
*by necessity*, since a peer must introduce itself before any relationship
exists, so a real federation would have throttled itself. Federation now has its
own budget at a lower per-call cost.

## What was checked and found clean

Dependency CVEs (`pip-audit`: none), secrets in the tree, `eval`/`exec`/`pickle`
/`yaml.load`/`shell=True`, path traversal, and timing-unsafe secret comparison.
`security/xcpsec/mtls.py` sets `check_hostname = False` on the **server** context,
which is correct — a server does not check the hostname of a connecting client.

## Independent review (GPT-5.6)

A source-level review by a party outside the design found two HIGH issues the
self-audit above missed, plus six scope and clarification items. Both HIGH
findings were verified against the source and fixed.

| id | severity | finding |
|---|---|---|
| **XCP-B-01** | **high** | `/v1/federation/peer` never called `verify_node_record()`. The function existed, was tested, and no running code reached it — so enrolment accepted a record's *self-declared* domain, and a caller controlling both `domain` and `gatewayUrl` could have any record promoted to VERIFIED. Now bound to the certificate the peer actually presents; plain HTTP cannot reach VERIFIED at all. |
| **XCP-B-02** | **high** | `mutual` was read from the request body into `PeerTrust.PEERED` — the strongest level. The initiating caller could award itself mutual trust with a boolean. This path now grants at most VERIFIED. |

Six further items — standalone self-registration, two coexisting authorization
generations, A2A/T2T scope, credential pass-through bounds, optional hardening,
and eventual-consistency semantics — are recorded in the draft's Appendix B and
addressed as specification work rather than code fixes.

**XCP-B-01 is the fourth instance of the same defect class in this project:** a
correct, tested library that no running code reached. It survived my own audit.
That is the clearest available evidence that self-assessment has a ceiling.

## Still open

- No independent security audit. This is a self-review, and the same person
  wrote the code and the tests.
- `NodeRegistry.sol` remains unaudited and undeployed.
- Federation is demonstrated between two nodes, not at scale.
