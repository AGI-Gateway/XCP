# Connectors — the global MCP catalog

Two halves, because a global catalog cannot be a folder of hand-written YAML:

| | what it is | size |
|---|---|---|
| `catalog/*.yaml` | curated, verified, promotable | dozens |
| `snapshot/servers.json` | long tail: awesome-lists, npm **and public API specs** | **7,027** |
| `sources.py` | live crawl of upstreams and peer nodes | unbounded |

## Promotion is always local

**The shipped catalog never claims `attested` or `contracted`.** Those describe an
operator's relationship with a vendor — a signed manifest they pinned, a contract
they hold — not a property of the vendor that a public catalog can assert on
their behalf.

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

## Navigating 7,568 entries

```bash
xcp catalog                     # headline counts
xcp catalog --categories        # every category, with counts
xcp catalog --category dev-tools --kind routable
xcp catalog --search stripe
```

### Two axes, and you need both

**Axis 1 — can I reach it today?**

| kind | meaning | count |
|---|---|---:|
| `routable` | an **MCP** endpoint. An agent connects now. | **158** |
| `wrappable` | a public API with a spec. Reachable over the internet, but it speaks **REST, not MCP** — one `xcp wrap` from routable. | **520** |
| `installable` | a package. Nothing to connect to until an operator runs it. | **6,869** |

!!! warning "Why `wrappable` is not counted as routable"
    A public REST API is demonstrably online, so it is tempting to call it
    routable. It is not: an MCP agent cannot connect to `https://api.stripe.com/v1`.
    Marking it routable would make the Trust Firewall send agent traffic to an
    endpoint where every call fails.

    Both `wrappable` and `installable` become routable the same way — **an
    operator deploys something, and it is routable at their URL, not the
    vendor's.** That is the federation property again: XCP does not host the long
    tail.

```bash
xcp catalog --kind wrappable            # browse public APIs
xcp wrap stripe                         # generate a deployable MCP server
uvicorn mcp_stripe:app --port 9100       # now it is routable, at your host
```

The generator reads an OpenAPI 3.x document and emits **one MCP tool per API
operation**, with input schemas derived from the spec's parameters and request
bodies. Credentials resolve through `vault://` references — a generated wrapper
contains no secret, and there is a test asserting it. `DELETE` operations are
excluded unless you pass `--include-destructive`.

It emits a readable file rather than proxying, deliberately: a generated wrapper
you cannot inspect is a supply-chain problem wearing a convenience costume.

**Axis 2 — should I believe it?**

| verification | meaning | max trust class |
|---|---|---|
| `confirmed` | vendor-documented, source cited | `contracted` |
| `community` | third-party, not vendor-official | `probed` |
| `unconfirmed` | vendor hosts one; this URL unverified | `unknown` |
| `self_hosted` | no official remote; you supply the host | `unknown` |

Everything harvested lands at `unconfirmed` / `unknown`, which the Trust Firewall
treats as observe-only, sandboxed, nothing binding. **Category tells you what a
server claims to do. Only verification tells you whether to believe it.**

### By category

| category | total | routable | installable | covers |
|---|---:|---:|---:|---|
| `dev-tools` | 1,025 | 35 | 990 | Coding, version control, CI and IDE integration |
| `other` | 590 | 12 | 578 | Everything not yet classified |
| `finance-payments` | 560 | 33 | 527 | Payments, trading, accounting and crypto |
| `security` | 364 | 11 | 353 | Security, compliance, secrets and vulnerability work |
| `ai-agents` | 339 | 10 | 329 | Agent frameworks, orchestration, LLM and prompt tooling |
| `data-stores` | 289 | 11 | 278 | Databases, warehouses and vector stores |
| `cloud-infra` | 249 | 9 | 240 | Cloud platforms, containers, IaC and deployment |
| `observability` | 179 | 7 | 172 | Monitoring, logging, tracing and incident response |
| `browsing-scraping` | 166 | 7 | 159 | Browsers, crawlers, scrapers and web fetch |
| `knowledge-memory` | 148 | 6 | 142 | RAG, embeddings, knowledge graphs and agent memory |
| `media-design` | 128 | 5 | 123 | Images, audio, video, 3D and design tools |
| `search-web` | 120 | 8 | 112 | Search engines, news and general web lookup |
| `communication` | 109 | 5 | 104 | Chat, email, calendar and meetings |
| `location-weather` | 105 | 6 | 99 | Maps, geospatial, weather and travel |
| `productivity` | 102 | 4 | 98 | Docs, tasks, projects and knowledge workspaces |
| `crm-sales` | 59 | 6 | 53 | CRM, marketing and customer support |
| `science-research` | 42 | 2 | 40 | Papers, bio, chem, maths and scientific computing |
| `gaming` | 33 | 1 | 32 | Games, engines and virtual worlds |
| `iot-hardware` | 28 | 1 | 27 | Devices, sensors, robotics and embedded systems |
| `ecommerce` | 13 | 0 | 13 | Storefronts, orders, inventory and marketplaces |

Categories were derived from the corpus vocabulary rather than invented and
forced onto it. Each entry gets exactly one primary category, first-match-wins,
so a "Postgres vector search" server lands in one place rather than three. About
12% fall to `other` — that is honest residue, not a gap being papered over.

### Where the routable ones actually are

Only **179 of 4,648** entries are reachable endpoints, and they cluster in
`dev-tools`, `finance-payments` and `data-stores`. That is the real shape of the
ecosystem today: a handful of hosted services and a very long tail of packages.
`ecommerce` has none at all.

## The curated core — 21 verified services

Every row links to the vendor's own MCP or API documentation. Tools listed are
the scopes each connector declares; a live probe fills in the full list.

| service | category | verification | endpoint | auth | tools |
|---|---|---|---|---|---|
| [Amazon Web Services](https://awslabs.github.io/mcp/) | `cloud-infra` | unconfirmed | `https://mcp.aws.amazon.com/mcp` | oauth2_client_creds | `aws.describe_resources`, `aws.invoke_operation` |
| [Cloudflare](https://developers.cloudflare.com/agents/model-context-protocol/) | `cloud-infra` | unconfirmed | `https://mcp.cloudflare.com/mcp` | oauth2_auth_code | `cloudflare.list_zones`, `cloudflare.purge_cache` |
| [Slack](https://api.slack.com/) | `communication` | unconfirmed | `https://mcp.slack.com/mcp` | oauth2_auth_code | `slack.search`, `slack.post_message` |
| [HubSpot](https://developers.hubspot.com/mcp) | `crm-sales` | **confirmed** | `https://mcp.hubspot.com` | oauth2_auth_code | `hubspot.search_crm`, `hubspot.get_contact`, `hubspot.update_deal` |
| [Salesforce](https://developer.salesforce.com/docs) | `crm-sales` | unconfirmed | `https://mcp.salesforce.com/mcp` | oauth2_auth_code | `salesforce.soql`, `salesforce.update_record` |
| [Zendesk](https://developer.zendesk.com/api-reference/) | `crm-sales` | self-hosted | _you host it_ | oauth2_auth_code | `zendesk.search_tickets`, `zendesk.update_ticket` |
| [Airtable](https://airtable.com/developers/web/api/introduction) | `data-stores` | unconfirmed | `https://mcp.airtable.com/mcp` | oauth2_auth_code | `airtable.list_records`, `airtable.create_record` |
| [Databricks](https://docs.databricks.com/aws/en/generative-ai/mcp/) | `data-stores` | self-hosted | _you host it_ | oauth2_client_creds | `databricks.run_query`, `databricks.list_catalogs` |
| [Snowflake](https://docs.snowflake.com/en/user-guide/snowflake-cortex/mcp-server) | `data-stores` | unconfirmed | `https://mcp.snowflake.com/mcp` | oauth2_auth_code | `snowflake.query`, `snowflake.list_tables` |
| [Atlassian (Jira, Confluence, JSM, Bitbucket)](https://support.atlassian.com/rovo/docs/getting-started-with-the-atlassian-remote-mcp-server/) | `dev-tools` | **confirmed** | `https://mcp.atlassian.com/v2/mcp` | oauth2_auth_code | `jira.search_issues`, `jira.create_issue`, `confluence.search`, `confluence.create_page` |
| [GitHub](https://docs.github.com/en/copilot/customizing-copilot/extending-copilot-chat-with-mcp) | `dev-tools` | **confirmed** | `https://api.githubcopilot.com/mcp/` | oauth2_auth_code | `github.search`, `github.read_file`, `github.create_issue`, `github.create_pull_request` |
| [Linear](https://linear.app/docs/mcp) | `dev-tools` | unconfirmed | `https://mcp.linear.app/mcp` | oauth2_auth_code | `linear.search_issues`, `linear.create_issue` |
| [Shopify](https://shopify.dev/docs/apps/build/storefront-mcp) | `finance-payments` | unconfirmed | `https://mcp.shopify.com/mcp` | oauth2_auth_code | `shopify.search_products`, `shopify.create_order` |
| [Square](https://developer.squareup.com/docs) | `finance-payments` | unconfirmed | `https://mcp.squareup.com/mcp` | oauth2_auth_code | `square.list_payments`, `square.create_refund` |
| [Stripe](https://docs.stripe.com/mcp) | `finance-payments` | **confirmed** | `https://mcp.stripe.com` | api_key | `stripe.list_customers`, `stripe.create_refund` |
| [Dropbox](https://www.dropbox.com/developers/documentation) | `knowledge-memory` | unconfirmed | `https://mcp.dropbox.com/mcp` | oauth2_auth_code | `dropbox.search`, `dropbox.get_file` |
| [Google Workspace](https://developers.google.com/workspace) | `knowledge-memory` | self-hosted | _you host it_ | oauth2_auth_code | `gworkspace.drive_search`, `gworkspace.calendar_create` |
| [Figma](https://help.figma.com/hc/en-us/articles/32132100833559) | `media-design` | unconfirmed | `https://mcp.figma.com/mcp` | oauth2_auth_code | `figma.get_file`, `figma.list_components` |
| [Sentry](https://docs.sentry.io/product/sentry-mcp/) | `observability` | unconfirmed | `https://mcp.sentry.dev/mcp` | oauth2_auth_code | `sentry.search_issues`, `sentry.get_event` |
| [Asana](https://developers.asana.com/docs/using-asanas-mcp-server) | `productivity` | unconfirmed | `https://mcp.asana.com/mcp` | oauth2_auth_code | `asana.search_tasks`, `asana.create_task` |
| [Notion](https://developers.notion.com/docs/mcp) | `productivity` | **confirmed** | `https://mcp.notion.com/mcp` | oauth2_auth_code | `notion.search`, `notion.fetch`, `notion.create_pages`, `notion.update_page` |

## Reachability — what has actually been checked

| state | count | meaning |
|---|---:|---|
| `alive` | 1,051 | repository resolves, not archived |
| `archived` | 23 | still there, no longer maintained |
| `gone` | 26 | 404 — the artifact was removed |
| `unchecked` | 5,927 | not yet validated |
| `curated` | 21 | hand-verified core |

```bash
python scripts/validate-catalog.py --installable    # resolve packages and repos
python scripts/validate-catalog.py --routable       # probe live MCP endpoints
```

!!! warning "Routable probing needs open egress"
    `--routable` performs a real MCP `tools/list` call against each endpoint.
    Run it from a machine with unrestricted network access. Behind a filtering
    proxy every endpoint returns a transport error and the run records **false
    negatives**, which is worse for the catalog than having no data. The script
    checks a control host first and **refuses to write** if egress is blocked.

    The reachability figures above therefore cover *artifacts*, not live
    endpoints — the 158 routable endpoints have not been probed here.

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
