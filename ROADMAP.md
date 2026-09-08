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
