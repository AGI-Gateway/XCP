"""
connectors.taxonomy — a navigable classification for the catalog.

Nearly five thousand servers is an inventory, not something a person or an agent
can navigate. This assigns every entry exactly one primary category so the
catalog can be browsed, filtered and routed by domain.

The categories were derived from the corpus itself — the dominant vocabulary
across ~4,600 real server names and descriptions — rather than invented and then
forced onto the data. Rules are ordered and first-match-wins, because a
"Postgres vector search" server should land in one place, not three.

Classification is a *navigation aid*, never a trust signal. A server's category
says what it claims to do; only its verification status and trust class say
whether you should believe it.
"""

from __future__ import annotations

import re
from typing import Iterable

# Ordered: the first rule that matches wins. More specific domains come first,
# because broad terms like "search" or "agent" appear almost everywhere.
CATEGORY_RULES: list[tuple[str, str, list[str]]] = [
    ("finance-payments", "Payments, trading, accounting and crypto",
     ["payment", "stripe", "invoice", "billing", "paypal", "crypto", "blockchain",
      "trading", "trade", "wallet", "bank", "finance", "financial", "accounting",
      "ledger", "tax", "solana", "ethereum", "defi", "coinbase", "quickbooks"]),
    ("security", "Security, compliance, secrets and vulnerability work",
     ["security", "vulnerab", "pentest", "exploit", "cve", "compliance", "audit",
      "threat", "malware", "forensic", "secret", "credential", "encryption",
      "firewall", "siem", "soc2", "owasp"]),
    ("cloud-infra", "Cloud platforms, containers, IaC and deployment",
     ["kubernetes", "k8s", "docker", "terraform", "ansible", "aws", "azure", "gcp",
      "cloudflare", "serverless", "lambda", "infrastructure", "devops", "deploy",
      "provision", "helm", "nginx", "vercel", "heroku", "vps", "cluster"]),
    ("observability", "Monitoring, logging, tracing and incident response",
     ["monitor", "observab", "logging", "telemetry", "metric", "tracing", "grafana",
      "prometheus", "sentry", "datadog", "alert", "incident", "pagerduty", "uptime"]),
    ("data-stores", "Databases, warehouses and vector stores",
     ["postgres", "mysql", "sqlite", "mongodb", "redis", "clickhouse", "snowflake",
      "bigquery", "databricks", "duckdb", "database", "sql ", "warehouse", "vector",
      "elasticsearch", "opensearch", "neo4j", "supabase", "firebase", "dynamodb",
      "cassandra", "pinecone", "qdrant", "weaviate", "chroma", "milvus"]),
    ("dev-tools", "Coding, version control, CI and IDE integration",
     ["git", "repo", "pull request", "code", "coding", "ide", "cursor", "vscode",
      "jetbrains", "compil", "lint", "debug", "refactor", "unit test", "ci/cd",
      "jenkins", "gitlab", "bitbucket", "npm", "package manager", "jira", "linear",
      "issue track", "sonar", "codebase"]),
    ("browsing-scraping", "Browsers, crawlers, scrapers and web fetch",
     ["browser", "scrape", "scraping", "crawl", "playwright", "puppeteer",
      "selenium", "web page", "webpage", "fetch url", "html", "screenshot",
      "firecrawl", "web content"]),
    ("knowledge-memory", "RAG, embeddings, knowledge graphs and agent memory",
     ["memory", "knowledge graph", "knowledge base", "embedding", "semantic search",
      "rag", "retrieval", "vector search", "recall", "long-term", "ontology",
      "obsidian", "zettel", "note-taking", "second brain"]),
    ("crm-sales", "CRM, marketing and customer support",
     ["crm", "salesforce", "hubspot", "zendesk", "intercom", "freshdesk", "lead",
      "pipeline", "marketing", "campaign", "customer support", "helpdesk",
      "ticketing", "mailchimp"]),
    ("ecommerce", "Storefronts, orders, inventory and marketplaces",
     ["shopify", "ecommerce", "e-commerce", "storefront", "woocommerce", "magento",
      "product catalog", "inventory", "order manage", "amazon seller", "etsy"]),
    ("communication", "Chat, email, calendar and meetings",
     ["slack", "discord", "telegram", "whatsapp", "teams", "email", "gmail",
      "imap", "smtp", "calendar", "meeting", "zoom", "sms", "twilio", "matrix",
      "messaging", "inbox"]),
    ("productivity", "Docs, tasks, projects and knowledge workspaces",
     ["notion", "confluence", "asana", "trello", "monday", "clickup", "todoist",
      "airtable", "spreadsheet", "google docs", "google drive", "onedrive",
      "dropbox", "task manage", "project manage", "wiki", "document"]),
    ("media-design", "Images, audio, video, 3D and design tools",
     ["image", "video", "audio", "speech", "text-to-speech", "tts", "whisper",
      "figma", "canva", "design", "render", "blender", "3d", "photo", "music",
      "podcast", "diagram", "screenshot gen", "pdf"]),
    ("science-research", "Papers, bio, chem, maths and scientific computing",
     ["arxiv", "pubmed", "research paper", "scientific", "bioinformatic", "genom",
      "chemistr", "molecul", "physics", "mathemat", "wolfram", "simulation",
      "academic", "citation", "dataset"]),
    ("location-weather", "Maps, geospatial, weather and travel",
     ["weather", "map", "geospatial", "geocod", "location", "gis", "travel",
      "flight", "hotel", "transit", "openstreetmap", "timezone"]),
    ("iot-hardware", "Devices, sensors, robotics and embedded systems",
     ["iot", "sensor", "arduino", "raspberry", "robot", "hardware", "embedded",
      "home assistant", "smart home", "mqtt", "serial port", "drone"]),
    ("gaming", "Games, engines and virtual worlds",
     ["minecraft", "unity", "unreal", "steam", "game ", "gaming", "roblox",
      "godot", "chess", "pokemon"]),
    ("ai-agents", "Agent frameworks, orchestration, LLM and prompt tooling",
     ["agent", "llm", "openai", "anthropic", "claude", "gemini", "ollama",
      "prompt", "fine-tun", "inference", "multi-agent", "orchestrat", "workflow",
      "reasoning", "chain-of-thought", "model context"]),
    ("search-web", "Search engines, news and general web lookup",
     ["search engine", "web search", "google search", "brave search", "duckduckgo",
      "perplexity", "news", "rss", "wikipedia", "youtube", "reddit", "twitter",
      "social media", " search"]),
]

FALLBACK = ("other", "Everything not yet classified")

CATEGORIES: dict[str, str] = {cid: desc for cid, desc, _ in CATEGORY_RULES}
CATEGORIES[FALLBACK[0]] = FALLBACK[1]

_COMPILED = [(cid, re.compile("|".join(re.escape(k) for k in kws)))
             for cid, _desc, kws in CATEGORY_RULES]


def classify(name: str, description: str = "", tags: Iterable[str] = ()) -> str:
    """
    Assign one primary category. First match wins, so put the specific rules
    first — a "Postgres vector search" server belongs in one place, not three.
    """
    hay = f"{name} {description} {' '.join(tags)}".lower()
    for cid, rx in _COMPILED:
        if rx.search(hay):
            return cid
    return FALLBACK[0]


def describe(category: str) -> str:
    return CATEGORIES.get(category, FALLBACK[1])


__all__ = ["classify", "describe", "CATEGORIES", "CATEGORY_RULES", "FALLBACK"]
