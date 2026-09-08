# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use **GitHub's private vulnerability reporting** on this repository
(Security → Report a vulnerability). It works without email and without either
side deanonymising themselves, which is why we use it.

Include:
- what the issue is and which component is affected
- steps to reproduce, ideally a minimal case
- your assessment of impact

We'll acknowledge within 3 business days and aim to give an initial assessment
within 10. We'll agree a disclosure timeline with you; the default is 90 days or
until a fix ships, whichever is sooner. We're happy to credit you.

## Scope

In scope: the gateway, verifier, server, clients, `xcpsec`, the Session Registry
contract, the trust lattice, and the CLI.

Out of scope: issues in third-party MCP servers you point the wrapper at (report
those to their owners); missing hardening in the example/dev configuration that
is documented as dev-only (e.g. the local dev PKI, the well-known Anvil test key
used in examples).

## What this software is and isn't

This is **reference code for a draft protocol**. It has not had an independent
security audit. It passes its own test suite and the enforcement path has no
stubs, but you should review it yourself before production use, and pin to a
released spec version.

Known limitations are documented honestly in [docs/security.md](docs/security.md),
including the threat classes XCP does *not* address and where the optional
`xcpsec` library reduces rather than eliminates risk.

## Hardening checklist for operators

- Run the gateway in `enforce` posture; `observe` is for onboarding only.
- Use real certificates from your own CA — never the dev PKI from `xcp certs`.
- Set `XCP_SECURITY=1` to enable the argument firewall.
- Keep session TTLs short; the protocol caps bindings at 7 days.
- Serve `/.well-known/*` unauthenticated (RFC 8615) but everything else gated.
- Monitor `mandate_denials_total` and `session_verifications_total{result}`.
