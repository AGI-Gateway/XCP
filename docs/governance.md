# Governance

XCP is open source under the MIT licence. This document says who decides
what, so contributors and adopting organisations know what they are relying on.

## Anonymous by design

This project is maintained **anonymously**. Copyright is held by "Anonymous
Contributors"; there is no sponsoring company named in the licence, the code, or
these documents. Contributions default to anonymous attribution and you are
welcome to leave them that way.

Be aware of what that trades away, because it is a real trade:

- An unidentifiable copyright holder makes the licence **harder to enforce**.
  MIT is permissive enough that this rarely matters in practice, but it is true.
- Some enterprise legal teams want a **named upstream** before approving a
  dependency. Anonymity may slow adoption in those organisations.
- There is **no warranty and no support commitment**, which the licence already
  says, but anonymity makes it concrete.

We think those costs are worth paying for infrastructure that no single vendor
controls. You should decide for yourself.

## Decision making

| Change | How it's decided |
|---|---|
| Bug fixes, docs, tests | One maintainer approval |
| New features, APIs | Two maintainer approvals; issue first |
| **Protocol/wire changes** | RFC-style issue, 7-day comment period, maintainer consensus |
| **Provider additions** | Validation only — no approval needed (see below) |
| Governance, licensing | Announced in advance, consensus among maintainers |

Protocol changes are held to a higher bar deliberately: anything altering
headers, scopes, the session/mandate flow, or the trust lattice affects every
deployed implementation.

### Providers are deliberately ungated

Adding an [MCP connection or an inference model](https://github.com/AGI-Gateway/XCP/blob/main/providers/README.md)
does **not** require approval. It is validated, not reviewed for merit. There is
no allowlist of blessed vendors and no gatekeeper deciding whose model or server
is worthy. If a registry entry validates, it belongs.

This is the single most important governance property of the project. A trust
layer that decides who is allowed to connect would be the thing it was built to
replace.

## Proposing a protocol change

1. Open an issue using the **Protocol change** template.
2. State the problem, the proposed wire change, and the migration path for
   existing deployments.
3. Seven days minimum for comment. Silence is not consent — we look for explicit
   agreement.
4. If accepted, it lands in `docs/protocol.md` and the reference implementation
   together, with a version bump.

## Becoming a maintainer

Sustained, high-quality contribution over time — code, review, docs, or triage.
Nominated by an existing maintainer, agreed by the rest. Maintainers may remain
anonymous.

## Specification status

XCP and the ERC-8004x Session Registry are **draft proposals originated in this
project**. MCP, A2A, ERC-8004 and the OWASP taxonomies are independent, real work
by others. We do not claim standardisation we have not earned.
