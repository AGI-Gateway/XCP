#!/usr/bin/env python3
"""
seed-catalog.py — regenerate the curated connector catalog.

Every entry carries a `verification` block stating how well the endpoint is
known. That is not bookkeeping: in a catalog agents route traffic from, an
unverified URL is worse than a missing one. Verification status therefore CAPS
the trust class (see connectors/loader.py), so an endpoint nobody has confirmed
can only ever be reached in observe mode.

    confirmed   vendor-documented endpoint, with a source
    community   third-party or community-run, not vendor-official
    unconfirmed vendor is known to host one; this exact URL is not verified
    self_hosted no official remote exists — you run it and supply the URL
"""
import pathlib, textwrap

OUT = pathlib.Path(__file__).resolve().parent.parent / "connectors" / "catalog"
CHECKED = "2026-09-08"

# id, name, vendor, url, auth, scopes, trust, min_tier, min_write, tags,
# status, source, tools, notes
E = [
 ("notion","Notion","Notion Labs","https://mcp.notion.com/mcp","oauth2_auth_code",
  [],"probed","A0xH1","A1xH1",["productivity","knowledge"],"confirmed",
  "https://docs.stacklok.com/toolhive/guides-mcp/notion-remote",
  ["notion.search","notion.fetch","notion.create_pages","notion.update_page"],
  "Official remote server. OAuth 2.1. Point at mcp.notion.com rather than a "
  "third-party wrapper of the Notion API."),

 ("atlassian","Atlassian (Jira, Confluence, JSM, Bitbucket)","Atlassian",
  "https://mcp.atlassian.com/v2/mcp","oauth2_auth_code",[],"probed","A0xH1","A1xH2",
  ["devtools","itsm","knowledge"],"confirmed",
  "https://github.com/atlassian/atlassian-mcp-server",
  ["jira.search_issues","jira.create_issue","confluence.search","confluence.create_page"],
  "OAuth 2.1 or API token. The legacy SSE endpoint (/v1/sse) stopped working on "
  "30 June 2026 — Streamable HTTP only. API-token auth needs an org admin to "
  "enable it, and is required for Jira Service Management tools. Access is "
  "limited to what the user can already see."),

 ("hubspot","HubSpot","HubSpot, Inc.","https://mcp.hubspot.com","oauth2_auth_code",
  [],"probed","A0xH1","A1xH2",["crm","sales"],"confirmed",
  "https://www.servicenow.com/docs/r/t2jQMKLZFp9AGt3V12O7mQ/HGYvUIRpTf9W5Ir9DiYpfg",
  ["hubspot.search_crm","hubspot.get_contact","hubspot.update_deal"],
  "Public beta at the time of writing. OAuth 2.0. A read-only mode is available "
  "— prefer it unless the task genuinely needs writes."),

 ("github","GitHub","GitHub, Inc.","https://api.githubcopilot.com/mcp/",
  "oauth2_auth_code",["repo","read:org","workflow"],"probed","A0xH0","A1xH1",
  ["devtools","scm"],"confirmed","https://openhelm.ai/blog/best-remote-mcp-servers-2026",
  ["github.search","github.read_file","github.create_issue","github.create_pull_request"],
  "Prefer a GitHub App with short-lived installation tokens over a classic PAT "
  "with broad scopes. OAuth tokens do not expire by default."),

 ("stripe","Stripe","Stripe, Inc.","https://mcp.stripe.com","api_key",[],
  "probed","A2xH2","A2xH2",["payments","financial"],"confirmed",
  "https://openhelm.ai/blog/best-remote-mcp-servers-2026",
  ["stripe.list_customers","stripe.create_refund"],
  "Money-moving. Use a restricted key scoped to the minimum resources, require "
  "A2xH2 for every call, and pair with a receipt obligation."),

 # vendor-hosted per public surveys; exact URL not verified here
 ("slack","Slack","Slack Technologies","https://mcp.slack.com/mcp","oauth2_auth_code",
  ["channels:read","chat:write","search:read"],"unknown","A0xH1","A1xH1",
  ["communication"],"unconfirmed","https://www.usecarly.com/blog/chatgpt-mcp-servers/",
  ["slack.search","slack.post_message"],
  "Verify inbound webhooks with the signing secret (HMAC over timestamp + body) "
  "and reject anything older than five minutes."),

 ("salesforce","Salesforce","Salesforce, Inc.","https://mcp.salesforce.com/mcp",
  "oauth2_auth_code",["api","refresh_token"],"unknown","A1xH2","A2xH2",
  ["crm","enterprise"],"unconfirmed","https://www.usecarly.com/blog/chatgpt-mcp-servers/",
  ["salesforce.soql","salesforce.update_record"],
  "If you use the JWT bearer flow instead, the signing key is high-value — "
  "managed secret backend only, never the env backend."),

 ("shopify","Shopify","Shopify Inc.","https://mcp.shopify.com/mcp","oauth2_auth_code",
  [],"unknown","A1xH1","A2xH2",["ecommerce","financial"],"unconfirmed",
  "https://www.usecarly.com/blog/chatgpt-mcp-servers/",
  ["shopify.search_products","shopify.create_order"],
  "Order and refund tools move money — treat writes as financial."),

 ("linear","Linear","Linear Orbit, Inc.","https://mcp.linear.app/mcp","oauth2_auth_code",
  [],"unknown","A0xH1","A1xH1",["devtools","project"],"unconfirmed",
  "https://openhelm.ai/blog/best-remote-mcp-servers-2026",
  ["linear.search_issues","linear.create_issue"],""),

 ("sentry","Sentry","Functional Software, Inc.","https://mcp.sentry.dev/mcp",
  "oauth2_auth_code",[],"unknown","A0xH1","A1xH1",["monitoring","devtools"],
  "unconfirmed","https://openhelm.ai/blog/best-remote-mcp-servers-2026",
  ["sentry.search_issues","sentry.get_event"],""),

 ("asana","Asana","Asana, Inc.","https://mcp.asana.com/mcp","oauth2_auth_code",[],
  "unknown","A0xH1","A1xH1",["project","productivity"],"unconfirmed",
  "https://www.usecarly.com/blog/chatgpt-mcp-servers/",
  ["asana.search_tasks","asana.create_task"],""),

 ("cloudflare","Cloudflare","Cloudflare, Inc.","https://mcp.cloudflare.com/mcp",
  "oauth2_auth_code",[],"unknown","A1xH2","A2xH2",["cloud","infrastructure"],
  "unconfirmed","https://openhelm.ai/blog/best-remote-mcp-servers-2026",
  ["cloudflare.list_zones","cloudflare.purge_cache"],
  "Infrastructure control plane — a mutating call can take a site offline."),

 ("aws","Amazon Web Services","Amazon.com, Inc.","https://mcp.aws.amazon.com/mcp",
  "oauth2_client_creds",[],"unknown","A1xH2","A2xH2",["cloud","infrastructure"],
  "unconfirmed","https://mcpplaygroundonline.com/blog/awesome-mcp-servers",
  ["aws.describe_resources","aws.invoke_operation"],
  "The managed server went GA on 6 May 2026 fronting 15,000+ AWS API operations. "
  "That is an enormous blast radius: scope the IAM role hard and require A2xH2 "
  "for anything mutating."),

 ("snowflake","Snowflake","Snowflake Inc.","https://mcp.snowflake.com/mcp",
  "oauth2_auth_code",[],"unknown","A1xH2","A2xH2",["data","warehouse"],
  "unconfirmed","https://mcpplaygroundonline.com/blog/awesome-mcp-servers",
  ["snowflake.query","snowflake.list_tables"],
  "Endpoint is per-account and warehouse-managed; substitute your account URL."),

 ("figma","Figma","Figma, Inc.","https://mcp.figma.com/mcp","oauth2_auth_code",[],
  "unknown","A0xH1","A1xH1",["design"],"unconfirmed",
  "https://mcpplaygroundonline.com/blog/awesome-mcp-servers",
  ["figma.get_file","figma.list_components"],""),

 ("airtable","Airtable","Formagrid, Inc.","https://mcp.airtable.com/mcp",
  "oauth2_auth_code",[],"unknown","A0xH1","A1xH1",["database","productivity"],
  "unconfirmed","https://www.usecarly.com/blog/chatgpt-mcp-servers/",
  ["airtable.list_records","airtable.create_record"],""),

 ("square","Square","Block, Inc.","https://mcp.squareup.com/mcp","oauth2_auth_code",
  [],"unknown","A2xH2","A2xH2",["payments","financial"],"unconfirmed",
  "https://www.usecarly.com/blog/chatgpt-mcp-servers/",
  ["square.list_payments","square.create_refund"],
  "Money-moving: A2xH2 for every call."),

 ("dropbox","Dropbox","Dropbox, Inc.","https://mcp.dropbox.com/mcp","oauth2_auth_code",
  [],"unknown","A0xH1","A1xH1",["storage"],"unconfirmed",
  "https://www.usecarly.com/blog/chatgpt-mcp-servers/",
  ["dropbox.search","dropbox.get_file"],""),

 # no confirmed official remote — you host it
 ("databricks","Databricks","Databricks, Inc.","https://<your-workspace>.cloud.databricks.com/mcp",
  "oauth2_client_creds",[],"unknown","A1xH2","A2xH2",["data","analytics"],
  "self_hosted","", ["databricks.run_query","databricks.list_catalogs"],
  "No vendor-hosted public endpoint confirmed. Run it against your own "
  "workspace and replace the placeholder host."),

 ("zendesk","Zendesk","Zendesk, Inc.","https://<your-subdomain>.zendesk.com/mcp",
  "oauth2_auth_code",[],"unknown","A0xH1","A1xH2",["support","itsm"],
  "self_hosted","", ["zendesk.search_tickets","zendesk.update_ticket"],
  "No vendor-hosted public endpoint confirmed. Substitute your subdomain."),

 ("google-workspace","Google Workspace","Google LLC",
  "https://<your-operator-host>/google-workspace/mcp","oauth2_auth_code",
  ["https://www.googleapis.com/auth/drive.readonly"],"unknown","A0xH1","A1xH2",
  ["productivity","storage","email"],"self_hosted","",
  ["gworkspace.drive_search","gworkspace.calendar_create"],
  "No single vendor-hosted MCP endpoint for Workspace as a whole. Domain-wide "
  "delegation grants access to every user in the tenant — prefer per-user "
  "consent and readonly scopes."),
]

TPL = """# Generated by scripts/seed-catalog.py — edit there, or add your own file.
# Nothing here is secret. Credentials are vault:// REFERENCES resolved at runtime.
id: {id}
name: {name}
vendor: {vendor}
description: {desc}

endpoint:
  url: {url}
  transport: streamable_http
  mcp_spec: "2026-07-28"

verification:
  status: {status}
  source: {source}
  checked: "{checked}"

auth:
  method: {auth}
  scopes: [{scopes}]
  secrets:
{secrets}
trust:
  class: {trust}
  min_tier: {min_tier}
  min_write_tier: {min_write}

scopes_exposed:
{scopes_exposed}
tags: [{tags}]
maintainer: anonymous
{notes}"""

def secret_lines(cid, auth):
    keys = {"oauth2_auth_code": ["client_id", "client_secret"],
            "oauth2_client_creds": ["client_id", "client_secret"],
            "oauth2_device": ["client_id"],
            "oidc": ["client_id", "client_secret"],
            "jwt_bearer": ["consumer_key", "private_key"],
            "api_key": ["api_key"], "hmac": ["signing_secret"], "none": []}
    ks = keys.get(auth, ["api_key"])
    backend = "hashicorp" if auth in ("api_key", "jwt_bearer") else "env"
    return "".join(f"    {k}: vault://{backend}/connectors/{cid}#{k}\n" for k in ks)

written = 0
for (cid, name, vendor, url, auth, scopes, trust, mn, mw, tags,
     status, source, tools, notes) in E:
    body = TPL.format(
        id=cid, name=name, vendor=vendor,
        desc=f"{name} via its Model Context Protocol endpoint.",
        url=url, status=status, source=source or '""', checked=CHECKED,
        auth=auth, scopes=", ".join(scopes),
        secrets=secret_lines(cid, auth),
        trust=trust, min_tier=mn, min_write=mw,
        scopes_exposed="".join(f"  - mcp:tools/{t}\n" for t in tools),
        tags=", ".join(tags),
        notes=("notes: >\n" + textwrap.indent(textwrap.fill(notes, 74), "  ") + "\n")
              if notes else "")
    (OUT / f"{cid}.yaml").write_text(body)
    written += 1
print(f"wrote {written} catalog entries")
