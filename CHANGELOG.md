# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/). This project uses
semantic versioning once it reaches 1.0. Until then, minor versions may break.

> **Note on history.** The git log was squashed to a single commit for a clean
> public record. This file is the record of what that history contained; the
> commit log no longer is.

## [Unreleased]

First public release. Everything below is new.

### Private federation — reachability and trust anchoring

Two controls made a private federation — several datacentres inside one
organisation — impossible to run under the production profile. Neither was a
missing feature; both were defences tuned for the public federation, where peers
are mutually suspicious strangers on routable addresses.

- **`XCP_PRIVATE_PEER_CIDRS`** declares the internal ranges that may hold peers.
  Reaching a peer on a private address previously required
  `XCP_ALLOW_INSECURE_PEERS=1`, which also accepted plain-HTTP peering and which
  the production profile refuses to start with — so the only setting a private
  federation could use was the one the profile rejected. The flag is now two
  decisions, and the scoped one is safe in production.

  Declaring a range is narrower than disabling the guard in ways that are
  tested, not asserted: a host resolving outside every declared range is still
  refused, so an attacker-controlled hostname cannot reach anywhere new; and
  loopback, link-local, cloud-metadata and CGNAT addresses stay refused **even
  when a declaration contains them**, so a range cannot be used to aim the
  gateway at its own admin surface. Declarations broader than /8 (IPv4) or /7
  (IPv6) are refused as a disguised bypass, and a malformed entry stops the node
  rather than silently narrowing what the operator declared. TLS is unaffected.

- **`XCP_PEER_CA_BUNDLE`** declares who signs this federation's peers. The
  footprint binding in `verify_node_record()` is a pinning construction and is
  indifferent to the signer, but chain validation ran first and ran against the
  ambient system store — so an internal CA failed *before* pinning was reached
  and a private federation could not peer at all.

  The bundle **replaces** rather than augments the public roots. Augmenting was
  the softer default and the wrong one: setting the variable is a statement
  about who signs your peers, and leaving the public roots trusted would accept
  a mis-issuance for an internal name on a first peering — the one moment
  pinning cannot help. An unreadable or empty bundle stops the node, because
  falling back would leave the operator believing peers are verified against
  their own CA.

- **`federation/peerfetch.py`** is now the only path to a peer. Both halves of
  peering built their own client with the ambient trust store; the handler's
  client is also where TLS verification was once disabled outright. The module
  owns the trust anchor, the redirect refusal and the size cap, and the
  certificate handshake moved off the event loop — inline, a peer that accepted
  a connection and stalled held the whole gateway for the timeout, which
  matters more on a private federation where peering traffic is ordinary rather
  than rare. Scoped deliberately: upstream tool calls keep the public trust
  store, so declaring an internal CA does not break external APIs.

- `/health` reports the posture (`privateFederation`: counts only) and
  `/v1/federation/trust` reports the detail behind the admin token — the
  declared ranges are a map of where an organisation keeps its gateways, which
  is the reconnaissance step. `xcp triage` honours the bundle, so diagnostics
  no longer report every check unreachable against an internal node.

### Private federation — cluster membership without a chain

`NodeRecord.cluster_id` carried a comment that was also an admission —
*"membership root is on-chain, roster is not"*. Clusters existed only in
`NodeRegistry.sol`, so an organisation federating three of its own datacentres
could not use them without deploying and paying for a contract.

- **`federation/cluster.py`** is the off-chain equivalent: a `ClusterCharter`
  signed by the organisation's own authority key, committing to the member set
  with a Merkle root and carrying no roster. The same file goes to every node
  without publishing who is in the cluster, and `to_dict()` is asserted to
  contain no member id rather than left to review.

- **Whose charter decides.** A peering node verifies an incoming member's proof
  against the root in the charter *it* holds, never against one the claimant
  supplies. That removes charter substitution as an attack: there is no "which
  charter do we believe" question, because only one of them is ours.

- **Removal needs no revocation.** To remove a node the authority re-issues at
  a higher epoch with a root that excludes it. The departed node still holds a
  proof the authority genuinely issued, and it stops verifying against the root
  its former peers hold — no revocation list, no gossip, nothing to wait out.
  Tested end to end, and tested with the epoch forged, so the defence is shown
  to rest on the proof rather than on the epoch check being a diagnostic.

- **The root is the on-chain root.** Byte-compatible with
  `NodeRegistry.verifyMembership` — sorted-pair keccak over raw node_id leaves
  — so a deployment can federate privately now and anchor the identical charter
  with `upsertCluster` later, or run both off one root. Asserted against an
  independent transcription of the Solidity loop, not assumed.

- **A one-member cluster would have published its only member.** A Merkle root
  over a single leaf *is* that leaf, so the root field would have held the
  roster it exists to avoid holding. Trees are padded with random leaves, which
  is transparent to both verifiers and keeps the tree's shape from leaking the
  real member count.

- **`scripts/cluster-charter.py`** is the authority's side: `init` creates the
  key, `issue` signs a charter and writes each member its own proof, `verify`
  checks either. Carrying `members.json` forward keeps the root stable when the
  member set has not changed, so re-issuing to bump a policy hash does not
  invalidate every proof for no reason anyone asked for.

- Enforced in the gateway rather than available as a library: a closed cluster
  refuses a peer with no claim, a stale proof, or another node's claim, and the
  check runs before the peer is recorded. A charter that does not verify stops
  the node — starting without it would leave a closed cluster accepting any
  peer, which is the one outcome it exists to prevent. A claim for a different
  node also stops the node, which catches a membership file copied between
  datacentres.

### Private federation — gated discovery

`/.well-known/xcp-node.json` is unauthenticated by RFC 8615. That is right for
a public node, where it is the entire bootstrap, and it publishes the inside of
a private one: node ids, gateway URLs, operator, certificate bindings, seed
peers — everything an attacker would use to map the estate.

- A node in a **closed cluster** now serves a **reduced record** to callers
  that have not proved membership: domain, protocol versions, and the cluster
  id so the caller knows what to prove. An authorization split on the one
  resource rather than a second, non-standard path — RFC 8615 reserves the
  path, not the response. `NodeRecord.PUBLIC_FIELDS` is an allowlist, because
  a denylist would leak every field added later.

- **The full record needs proof of possession, not a bearer token.** A
  membership claim is a static document, so gating on the claim alone would
  make possession access. `XCP-Cluster-Access` carries the claim plus an
  EIP-712 signature from the key the claim names, over a payload bound to the
  audience and expiring in 60 seconds. Replaying it at another node fails on
  the audience; replaying it later fails on the expiry; a member cannot mint
  itself a longer-lived one, because the verifier refuses a TTL above the
  ceiling — the expiry is the only thing bounding replay. The signature commits
  to a digest of the proof, so a member cannot sign once and then substitute a
  stale proof.

- **Removal now costs discovery as well as peering**, out of the same epoch
  bump. A removed node's proof stops verifying here too, so it can no longer
  read the record it would need in order to attempt peering.

- Every refusal returns the identical reduced record. A precise complaint would
  tell an unauthenticated caller which part of their credential was wrong,
  which is a probing oracle; the reason goes to the audit log, where the
  operator can see it. Tested by comparing the responses to four different
  failures byte for byte.

- Gating would have broken federation in both directions — each node fetching
  a reduced record with no certificate binding, and refusing the other for a
  reason that has nothing to do with the peer. The peer fetcher now presents
  this node's own membership, minted per fetch and bound to the domain being
  asked. When a peer does refuse, the diagnostic says membership rather than
  surfacing as "could not retrieve a valid peer record", which would send an
  operator looking at the network.

- `XCP_NODE_RECORD_PUBLIC=1` keeps a node discoverable despite a closed
  cluster — a public-facing gateway inside a private organisation, or one under
  external monitoring. Marked as weakening a control, because it does.

### Test infrastructure

- Contract tests signalled "skip" by raising `RuntimeError("SKIP: …")`, which
  the file's standalone runner understands and pytest counts as a **failure**.
  On any machine without `solc` or `web3` that left eleven permanently red
  tests, which is worse than noise: it hides whether a change broke something.
  They now skip under both runners.
- Two security-audit tests asserted on source text — one greping a fixed
  2600-character window of a handler — and broke when peer fetching moved into
  its own module. The redirect test is now behavioural (a real redirecting
  server), and the certificate-retrieval invariant is asserted across the call
  chain. A companion test refuses a second HTTP client in the handler, which is
  how the first one came to have verification disabled.
- `_gateway` in the private-federation tests applied its own defaults *after*
  the caller's overrides, so a test that set `XCP_NODE_KEY` silently got the
  default instead. It surfaced as the gateway refusing to start — correctly,
  because the membership claim then named a different node than the one
  running. The fixture had been masking what a caller asked for.
- The configuration-drift scan only saw environment variables passed to
  `getenv` as string literals, so a module tidy enough to name its variables
  was invisible to it — `XCP_PEER_CA_BUNDLE` was caught only because an
  unrelated literal happened to exist elsewhere. It now resolves module-level
  constants too, which is the difference between the registry being enforced
  and appearing to be.

### Second implementation

- **Node gateway** (`core/gateway-ts/`) written against the specification rather
  than ported from Python. **Passes the conformance suite 15/15**, which is the
  first evidence that the spec is implementable from the document and that the
  suite is a specification instrument rather than a regression test. CI runs it
  on every push.

### Delegation chains

- Sealed credentials can now be passed onward up to a budget the **originator**
  sets and no hop can raise. The chain is bound into the AAD, so a hop cannot
  rewrite the recorded path; loops are refused; and a recipient applies its own
  policy to which hops it accepts.
- Stated rather than overclaimed: re-sealing requires the intermediate hop to
  hold plaintext momentarily. The chain adds **accountability**, not secrecy
  from intermediaries. For secrecy from a hop, seal directly to the recipient.

### Security audit

Self-audit of the published tree before release: six findings, two critical, all
fixed with attack-reproducing tests. See [SECURITY-AUDIT.md](SECURITY-AUDIT.md).

- **Administrative authentication.** `/admin/revoke` previously had none — one
  unauthenticated request revoked any session. Now requires `XCP_ADMIN_TOKEN`,
  compared in constant time, and is **disabled** when unset rather than open.
- **Signed revocation.** The gossip endpoint took the originating peer's domain
  from the request body. With the peer list also public, anyone could name a real
  peer and revoke any node. Revocations now carry an EIP-712 signature from the
  issuing node's key and expire after an hour so one cannot be replayed.
- **Egress control** (`security/xcpsec/egress.py`). The peer-record fetch
  accepted a caller-supplied URL with TLS verification disabled — server-side
  request forgery reaching internal services, with the error echoed back as an
  oracle. Validation now happens on the **resolved address**, redirects are
  refused, responses are capped, and errors are generic.
- **Topology redacted** behind the admin token, consistent with a privacy design
  that already keeps counterparties out of what it publishes.
- **Federation gets its own rate budget.** Metering it under the anonymous
  bucket — sized for hostile traffic at roughly four calls a minute — would have
  made a real federation throttle itself, since peering is unauthenticated by
  necessity.

### Core protocol

- **Clients** in Python, Go, Java and the browser, sharing one interface, so any
  client works against any gateway.
- **Gateway** — the trust boundary. Verifies the caller, gates every action
  against a signed mandate, and routes to upstream MCP servers. Holds no keys and
  no funds: a verifier and router, never a custodian.
- **MCP server** — an XCP-aware reference server that trusts only
  gateway-verified identity.
- **Verifier** — real Merkle inclusion, EIP-712 recovery and scope coverage,
  running either in memory or against an on-chain registry.
- **ERC-8004x Session Registry** — Solidity contract plus an in-process EVM test
  for the read path.
- **A2T / A2A / T2T** gRPC contract for agent→tool, agent↔agent and tool↔tool
  streams.

### Stateless identity (MCP 2026-07-28)

- Targets the MCP revision that removed protocol sessions. Identity is a
  **per-request credential** bound to one method, one tool, one argument digest,
  one certificate footprint and a seconds-long expiry — replacing a session id
  with something worth far less to steal.
- Authorization is decided from the mandatory `Mcp-Method` and `Mcp-Name`
  headers **without parsing the body**, so it runs at edge speed.
- MRTR flows link multi-round-trip calls into one logical call. Stale headers and
  deprecated methods surface as warnings, not failures.

### Trust Firewall

- **Graded corpus reachability**: caller tier × server trust class
  (`unknown` → `probed` → `attested` → `contracted`) yields an effect, a
  settlement mode, and inherited obligations (sandbox, quarantine, receipt).
- Unvetted servers stay **reachable in observe mode** rather than blocked;
  nothing binding happens against them, and money never moves toward an
  unattested counterparty.

### Trust lattice

- Agent tier × human tier resolves to one **mandate template**: scopes, payment
  rails, session TTL and spend cap.
- Entitlements from an enterprise IdP **narrow and never widen**. The ceiling is
  the weaker leg, with one deliberate exception where a company-backed autonomous
  agent has the company as its principal.

### Receipts and settlement

- **Proof-of-delivery**: a task commitment, a tamper-evident call chain, and an
  EIP-712 signed receipt.
- An escrow state machine that releases only on verified evidence or an arbiter
  ruling. Auto-accept is off by default.
- `xcp receipt <bundle>` verifies an evidence bundle offline.

### Federation

- A web of independently-operated nodes with **no central authority**. A node
  proves itself with a domain and a TLS certificate published at
  `/.well-known/xcp-node.json`; peers verify it locally, consulting no third
  party.
- Transitive trust **decays per hop and is capped**, so a compromised node cannot
  launder full trust.
- Revocation spreads by gossip from trusted peers only, backstopped by
  seconds-long credential TTLs. Chain anchoring is optional and off by default.
  Nodes may disagree; no consensus is required.

### Open extension points

- Two ungated registries: any **MCP connection** and any **foundational
  inference model**. No allowlist, no vendor keys, no approval step — validation
  is the only gate, and provider additions are explicitly exempt from maintainer
  review.
- Six tool-call styles normalise to one `(tool, arguments)` shape, so adding a
  model requires no core change.

### Discovery

- Generates an ARD `ai-catalog.json` and an MCP Registry manifest from one
  config, with representative queries derived from the live tool surface.

### Security

- Optional `xcpsec` library: hardened mTLS with certificate pinning, an argument
  firewall, an execution sandbox with resource limits and network isolation,
  supply-chain manifest pinning, and prompt-injection content boundaries.

### Self-serve

- `xcp` CLI: `init`, `doctor`, `tier`, `certs`, `up`, `publish`, `verify`,
  `receipt`.
- Docker Compose and a Helm chart with safe defaults; docs site published to
  GitHub Pages.

### Notes

- XCP and the ERC-8004x Session Registry are **draft proposals originated in this
  project**. MCP, A2A, ERC-8004, ARD and the OWASP taxonomies are independent
  work by others.
- ARD support targets a draft specification and will change when it stabilises.
- This code has **not** had an independent security audit.
