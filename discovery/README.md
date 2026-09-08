# Discovery — ARD + MCP Registry publishing

Turn a running MCP/XCP surface into something agents can find.

```bash
./xcp publish --introspect
# dist/.well-known/ai-catalog.json   → ARD crawl path
# dist/server-<name>.json            → MCP Registry install path
```

```python
from discovery.ard import Publisher, Resource, build_catalog, validate_catalog

cat = build_catalog(
    Publisher(domain="acme.example", name="Acme Corp"),
    [Resource(name="research", description="Research tools",
              endpoint="https://acme.example/mcp", tools=tools_list,
              trust_tier="A2xH2", xcp_gateway="https://gw.acme.example")])
validate_catalog(cat)   # [] when clean
```

## Why `--introspect`

It reads your real tool surface and derives **representative queries** — the
signal registries rank on. Thin hand-written descriptions rank badly.

```
tools: echo, sum, now
→ "echo the provided text back", "sum by numbers", "return the current server time"
```

## Trust metadata

Entries advertise the tier and the gateway fronting them:

```json
"trust": {"auth": "xcp-mtls", "xcpTrustTier": "A2xH2",
          "xcpGateway": "https://gw.acme.example", "verifiedAtConnect": true}
```

ARD anchors identity to domain ownership **at publish time**. `xcpGateway` says
the endpoint is additionally verifiable **at connect time**.

## Status

Targets the **ARD v0.9 draft**. The emitted shape is centralised in
`CATALOG_SPEC_VERSION` / `build_catalog` so it's cheap to re-target at v1.0.
`validate_catalog()` is a local sanity check, not a schema validator — validate
against the published schema before relying on it. Serve `/.well-known/*`
unauthenticated per RFC 8615.
