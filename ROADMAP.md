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
- [ ] **Off-chain cluster membership** — `cluster_id` currently anchors to a
      Merkle root in `NodeRegistry.sol`, so a private federation has to use a
      chain to use clusters. Needs a signed `ClusterCharter` carrying the same
      root-not-roster property with no chain dependency
- [ ] **Membership-gated node record** — `/.well-known/xcp-node.json` is
      unauthenticated by RFC 8615, which is right for the public federation and
      publishes internal topology in a private one. Needs an authorization
      split on the one resource: a reduced record for negotiation, the full one
      to a caller proving cluster membership
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
