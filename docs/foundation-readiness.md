# Foundation readiness

An honest assessment of what XCP would need before a proposal to the
[Agentic AI Foundation](https://aaif.io) is worth the Technical Committee's
time, written against AAIF's own stated criteria.

This document exists because a self-assessment that only lists strengths is a
marketing page, and a foundation's technical committee reads a great many of
those. The blockers below are stated first.

## The three blockers

### 1. The copyright holder is anonymous

`LICENSE` reads `Copyright (c) 2026 Anonymous Contributors`, and the README
states the project is "maintained anonymously so no single vendor controls it."

That reasoning is sound as a defence against vendor capture, and it is close to
disqualifying for foundation contribution. A foundation needs identifiable
parties to assign trademark, accept a project contribution agreement, seat a
technical steering committee, and — if the project is ever relicensed —
consent on behalf of the copyright holders. None of that can be done by
"Anonymous Contributors".

It is also a one-way door that gets harder to walk back. Relicensing or
assigning copyright requires the agreement of everyone who holds it. Today that
is effectively one person. After twenty external contributors it is twenty
people, some of whom will be unreachable.

**What would resolve it:** at least one identifiable maintainer or entity of
record. Anonymity for other contributors is fine and common; anonymity for the
*copyright holder* is the problem. Note that a foundation is itself the strongest
available answer to vendor capture — stronger than anonymity, because it is
enforceable.

### 2. Adoption is one person

At the time of writing: 1 star, 0 forks, 0 external contributors, 0 issues
filed by anyone else. AAIF asks for projects "healthy enough to grow beyond one
company or maintainer group" with "good adoption" and demonstrated "contributor
community strength."

The honest reading is that XCP is a well-built artefact without a community
yet. The test suite, the conformance checks, the SDK vector contract and the
second implementation are real evidence of engineering care, and none of them
is evidence of adoption. A proposal that conflates the two will be read as
either naive or overstated, and both are expensive first impressions.

**What would resolve it:** external users. Realistically, a handful of
organisations running a node and at least one contributor who is not the
author. This is the slowest item on the list and the one least amenable to
engineering effort.

### 3. MIT, where the Linux Foundation expects Apache-2.0

XCP is MIT. agentgateway — the closest AAIF project — is Apache-2.0, as are most
Linux Foundation projects, for a specific reason: Apache-2.0 carries an express
patent grant and MIT does not. For a *protocol* project that gap matters more
than usual, because implementers are being asked to adopt a wire format and
would prefer a licence that says what happens to patents reading on it.

**What would resolve it:** relicensing to Apache-2.0. This is blocked on
item 1 — you cannot get consent from an anonymous copyright holder — which is
the clearest illustration of why anonymity is the load-bearing problem rather
than a stylistic choice.

## What is genuinely strong

Stated plainly, because the blockers above are not the whole picture.

- **It fills a gap AAIF has named.** The foundation runs an *Identity & Trust*
  working group and a *Security & Privacy* working group. AAIF hosts MCP and
  A2A — the protocols — and agentgateway — a data plane. It does not host a
  trust and delegated-authority model for the traffic those protocols carry.
  XCP is aimed precisely there.
- **It is complementary rather than competitive.** agentgateway's authorization
  stops at the name level; its own documentation notes that name-based CEL
  cannot tell whether `deploy` targets staging or production, and that
  argument-level decisions need an external ExtMCP processor. XCP's mandate and
  lattice semantics are a natural fit for exactly that hook. A proposal that
  positions XCP as a layer *for* an existing AAIF project is far stronger than
  one that positions it against.
- **Engineering practice is foundation-grade.** 847 tests, a conformance suite
  with levelled MUST/SHOULD checks, an independent second implementation that
  must pass it, differential testing between the two, a generated protocol
  contract with 139 cross-language vectors, signed and attested releases,
  generated configuration and deployment profiles, and a compliance map that
  records its own gaps rather than claiming coverage it lacks.
- **The chain is no longer a precondition.** `XCP_REGISTRAR` lets a production
  node run on an ordinary CA or identity provider. This mattered for
  foundation suitability specifically: a project whose lowest useful tier
  required a blockchain would read as a crypto project with a trust layer
  attached, which is not what the technical committee is looking for.

## What is in progress

- **DCO sign-off** is now required for new commits (see
  [`CONTRIBUTING.md`](../CONTRIBUTING.md) and [`DCO`](../DCO)). Historical
  commits are unsigned and cannot be retroactively signed by anyone but their
  author. Enforcing it in CI is deliberately not yet enabled, because it would
  block the current maintainer's workflow before the history question is
  settled.
- **Java and .NET SDK ports** do not exist. Three ports (Python, TypeScript, Go)
  reproduce the vector contract.
- **The Kubernetes operator** does not exist. The Terraform module does, but its
  HCL has never been checked by a Terraform binary.
- **GitHub Pages** is not enabled, so the documentation site builds on every
  push and is never served.

## A realistic sequence

Ordered by what unblocks what, not by effort.

1. Name an identifiable maintainer or entity of record. Everything else in the
   governance column depends on this.
2. Relicense to Apache-2.0 while the consent set is small.
3. Enable GitHub Pages so the documentation is reachable without a clone.
4. Enforce DCO in CI, from a stated commit forward.
5. Get the project in front of AAIF's Identity & Trust working group. A working
   group is the right first contact for a project at this stage — it is where
   the technical argument gets tested, and participation is itself the evidence
   of community the proposal will later need.
6. Build the ExtMCP integration with agentgateway. This is the highest-leverage
   engineering work available: it demonstrates interoperability with an
   existing foundation project and puts XCP in front of that project's users.
7. Propose only once there are external users. A proposal is not an application
   for attention; it is a claim that a community already exists and would be
   better served under neutral governance.

## The uncomfortable summary

XCP is technically ready and socially unready. The engineering would survive
technical committee review; the governance and adoption would not, and no
amount of further engineering changes that. The two items that matter most —
an identifiable maintainer and users who are not the author — are the two that
cannot be solved by writing more code.
