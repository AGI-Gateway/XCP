# Connectors — the global MCP catalog

Two halves, because a global catalog cannot be a folder of hand-written YAML:

| | what it is | size |
|---|---|---|
| `catalog/*.yaml` | curated, verified, promotable | dozens |
| `sources.py` | crawled from upstream registries and peer nodes | thousands |

Ingested entries arrive `unconfirmed` / `unknown`, which the
[Trust Firewall](../docs/trust-firewall.md) treats as observe-only, read-only,
sandboxed, output quarantined, nothing binding. **That is what makes it safe to
index a corpus nobody has vetted — discovery is not endorsement.**

## Verification status caps trust

In a catalog agents route traffic from, an unverified URL is worse than a missing
one. So status caps how far an entry can be promoted:

| status | meaning | max trust |
|---|---|---|
| `confirmed` | vendor-documented, source cited | `contracted` |
| `community` | third-party, not vendor-official | `probed` |
| `unconfirmed` | vendor hosts one; this URL unverified | `unknown` |
| `self_hosted` | no official remote; you supply the host | `unknown` |

**The shipped catalog never claims `attested` or `contracted`.** Those describe an
operator's relationship with a vendor — a signed manifest they pinned, a contract
they hold — not a property of the vendor. Promotion is always local.

## Ingestion at scale

```python
from connectors import GlobalCatalog, Source, SourceKind

cat = GlobalCatalog()
cat.load_curated()                                    # verified core
cat.ingest_url(Source(id="mcp-registry", kind=SourceKind.OFFICIAL,
                      url="https://registry.modelcontextprotocol.io/v0/servers"))
cat.apply_to_firewall(fw)                             # graded, no per-server code
cat.route("mcp:tools/search")                         # verified endpoints first
peer_doc = cat.export()                               # publish for peers
```

Sources: the official MCP Registry, any domain's `/.well-known/ai-catalog.json`,
community aggregators, other XCP nodes via [federation](../docs/agentic-internet.md),
and imported scan output. **None is required and none is operated by this
project** — a node that crawls nothing still works with what it curated.

Safety: every fetch passes `xcpsec.argfirewall.ssrf_guard`, documents are
size-capped at 5 MB, curated entries always win over crawled ones, and **nothing
ingested can set its own trust class** — a remote document asserting it is
trusted is ignored.

# Per-service entries

Each external service gets a declarative file in [`catalog/`](catalog/). The file
says where the MCP endpoint is, how to authenticate, which trust class it sits
in, and which scopes it exposes.

**No file here contains a credential.** Every secret is a `vault://` reference
resolved at runtime — enforced at load time and by a build-breaking test.

## Layout

```
connectors/
├── README.md
├── loader.py              parse · validate · register
└── catalog/
    ├── _template.yaml     copy this to add a SaaS
    ├── github.yaml
    ├── google-workspace.yaml
    ├── slack.yaml
    ├── salesforce.yaml
    └── stripe.yaml
```

## Anatomy of an entry

```yaml
id: github
name: GitHub
endpoint:
  url: https://api.githubcopilot.com/mcp/
  transport: streamable_http        # streamable_http | stdio | websocket
  mcp_spec: "2026-07-28"
auth:
  method: oauth2_auth_code          # see the method table below
  scopes: [repo, read:org]
  secrets:                          # REFERENCES ONLY
    client_id:     vault://env/connectors/github#client_id
    client_secret: vault://env/connectors/github#client_secret
  resource_indicator: https://api.githubcopilot.com/mcp/   # RFC 8707
trust:
  class: attested                   # unknown | probed | attested | contracted
  min_tier: A0xH0                   # who may reach it at all
  min_write_tier: A1xH1             # who may mutate through it
scopes_exposed:
  - mcp:tools/github.search
tags: [devtools, scm]
```

`trust.class` feeds the [Trust Firewall](../docs/trust-firewall.md), which grades
reachability by caller tier × server class. `min_write_tier` is the connector's
own floor on top of that.

## Authentication methods

| `auth.method` | Use for | Secrets typically referenced |
|---|---|---|
| `oauth2_auth_code` | User-present delegated access (**PKCE required**) | `client_id`, `client_secret` |
| `oauth2_client_creds` | Service-to-service, no user | `client_id`, `client_secret` |
| `oauth2_device` | CLIs and input-constrained devices | `client_id` |
| `oidc` | Sign-in with an identity claim | `client_id`, `client_secret` |
| `jwt_bearer` | RFC 7523 assertion, no user interaction | `consumer_key`, `private_key` |
| `mtls` | XCP-native channel binding | client cert + key refs |
| `api_key` | Legacy services. **Discouraged** | `api_key` |
| `hmac` | Webhook / request verification | `signing_secret` |
| `none` | Genuinely public endpoints | — |

Full reference, including what to watch for with each: [`vault/README.md`](../vault/README.md#authentication-methods).

## Using the catalog

```python
from connectors import load_catalog, register_all, required_secrets
from trustfirewall import TrustFirewall

load_catalog()                    # validates every file; raises on a bad entry
register_all(firewall=fw)         # into providers/ and the trust firewall
required_secrets()                # what an operator must provision
```

## Adding a SaaS

1. Copy `catalog/_template.yaml`.
2. Fill in the endpoint, auth method and exposed scopes.
3. Put secrets in **your** backend and reference them with `vault://`.
4. Start at `trust.class: unknown` — reachable in observe mode, sandboxed, output
   quarantined, nothing binding. Climb by probing, pinning a signed manifest, or
   contracting.

No approval step. Validation is the only gate.

## Rules the loader enforces

- Endpoint must be `https://` (or `stdio://` for local).
- Every secret must be a parseable `vault://` reference — a literal credential
  fails to load.
- `http_sse` transport is flagged as deprecated in MCP 2026-07-28.
- Duplicate connector ids are rejected.
- **A connector tagged `payments` or `financial` must require `A2` for writes.**
