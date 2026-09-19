# `xcp` CLI

Standard library only — no dependencies, runs anywhere Python 3.10+ does.

| Command | What it does |
|---|---|
| `xcp init` | scaffold `xcp.toml` |
| `xcp doctor` | check environment, config and your resolved tier |
| `xcp tier` | show the lattice, or resolve your envelope (`--table`, `--json`, `--limit`) |
| `xcp certs` | generate a local mTLS dev PKI (never for production) |
| `xcp up` | run the stack (`--docker` for compose) |
| `xcp publish` | generate ARD catalog + MCP manifest (`--introspect` to enrich) |
| `xcp verify <url>` | probe an endpoint's XCP posture before trusting it |

See [docs/self-serve.md](../docs/self-serve.md) for the full walkthrough.
