# Roadmap

Dated loosely, ordered firmly. Anything below "next" is a direction, not a promise.

## Now — make self-serve real
- [x] Trust lattice (agent × human tiers → mandate template)
- [x] `xcp` CLI: init / doctor / tier / certs / up / publish / verify
- [x] ARD catalog + MCP Registry manifest generation with derived queries
- [x] Optional security library (`xcpsec`): mTLS, argument firewall, sandbox,
      supply chain, content firewall
- [ ] Helm chart hardening + published container images
- [ ] Hosted quickstart that needs no local Python

## Now — make self-serve real (continued)
- [x] **Stateless core** — MCP 2026-07-28 support: per-request call-bound
      credentials replacing `Mcp-Session-Id`, header-speed decisions
- [x] **Trust Firewall** — graded reachability across the corpus by caller tier
      × server trust class
- [x] **Receipts**: proof-of-delivery bound to settlement (task commitment,
      tamper-evident call chain, signed receipt, evidence-conditioned escrow)
- [x] Docs site published to GitHub Pages
- [x] **Open provider registries** — add an MCP connection or an inference
      model with no approval step (`providers/`)

## Now — private federation
Several datacentres inside one organisation, with independent agents talking
A2A across boundaries and reaching common external tools. The first two are
done; the rest is what a private federation still needs.

- [x] **Reachability** — `XCP_PRIVATE_PEER_CIDRS` declares the internal ranges
      that may hold peers, so a production node can peer across datacentres
      without the blanket flag the production profile refuses
- [x] **Trust anchoring** — `XCP_PEER_CA_BUNDLE` declares who signs this
      federation's peers, so an internal CA verifies. Scoped to federation;
      upstream tool calls keep public trust
- [x] **Off-chain cluster membership** — a signed `ClusterCharter` commits to
      the member set with a Merkle root and carries no roster, so the same file
      goes to every node without publishing who is in the cluster. Removal is
      a re-issue at a higher epoch: the departed node's genuine proof stops
      verifying against the root its peers hold, with no revocation list and
      nothing to expire. The root stays byte-compatible with
      `NodeRegistry.upsertCluster`, so a deployment can anchor the identical
      charter on-chain later or run both off one root
- [x] **Membership-gated node record** — a closed cluster serves a reduced
      record to strangers (domain, protocol versions, cluster id) and the full
      one to a caller presenting a signed, audience-bound, 60-second membership
      proof. An authorization split on the one RFC 8615 resource rather than a
      second path. A removed member therefore loses discovery as well as
      peering, from the same epoch bump
- [ ] **Cross-boundary A2A** — `/v1/a2a/delegate` authorises a delegation and
      reports `delivered: false`; it does not open a channel. Needs a signed
      delegation ticket the destination redeems, re-deriving the tier under its
      own entitlements so authority narrows and never widens at the boundary
- [ ] **Datacentre locality in routing** — `PeerMetrics` has `hops` and no
      region or site, so multi-datacentre latency optimisation has nothing to
      optimise against. Carries the data-residency constraint for tools too
- [ ] **Federated tool catalogue** — `XCP_UPSTREAMS` is a static per-gateway
      map, so every datacentre needs its own egress path and its own copy of
      each vendor credential. Needs nodes to advertise reachable servers and
      `_route_mcp` to fall back to a peer that can

## Next — close the trust loop
- [ ] Enterprise SSO connector: map IdP entitlement attributes → mandate narrowing
- [ ] Reputation write-back to the ERC-8004 reputation registry
- [ ] ARD registry endpoint (`POST /search`) + federated catalog ingestion

## Later — needs external validation first
- [ ] Standards-track progression for XCP (currently a draft we originated)
- [ ] Tokenomics: slashable bonds, fee routing, reputation as collateral
- [ ] Independent security audit

## Explicitly not planned
- Becoming another agent marketplace. We index and verify; we don't intermediate.
- Custody of user keys or funds. The gateway is a verifier and router, not a
  custodian, and we intend to keep that property.

## How to influence this
Open an issue. Roadmap items that no adopter asks for get dropped; items two or
more organisations need get pulled forward.
