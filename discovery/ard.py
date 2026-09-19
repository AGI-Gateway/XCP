"""
discovery.ard — publish an XCP/MCP surface to the agentic discovery layer.

Self-serve on-ramp: point this at a running MCP or XCP server and it produces a
spec-shaped `ai-catalog.json` you host at `/.well-known/ai-catalog.json`, plus a
manifest for the MCP Registry. Two pipes, one command:

    ARD crawl path      →  /.well-known/ai-catalog.json   (registries crawl it)
    MCP install path    →  server.json                    (registry indexes it)

What ARD is (as of the v0.9/v1.0 draft): publishers host a machine-readable
catalog on their own domain — so domain ownership is the identity anchor —
listing MCP servers, A2A agents, OpenAPI tools or nested catalogs. Registries
crawl and index those catalogs and answer natural-language capability queries.
Discovery is deliberately separate from invocation: once an agent picks a
resource it connects over that resource's native protocol.

Because the spec is a moving draft, this module keeps the emitted shape in one
place (`CATALOG_SPEC_VERSION`, `build_catalog`) so it is cheap to re-target when
the spec lands at v1.0. Validate against the published schema before you rely on
it in production.

XCP-specific value-add: entries can advertise the *trust tier* the endpoint is
served at and the XCP gateway that fronts it, so a discovering agent learns not
just "this capability exists" but "it is verifiable live, at this tier".

Status: XCP and ERC-8004x are draft proposals; ARD is a third-party draft spec.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

CATALOG_SPEC_VERSION = "0.9"
WELL_KNOWN_PATH = "/.well-known/ai-catalog.json"


class CatalogError(Exception):
    pass


# ── URN minting ────────────────────────────────────────────────────────────

_URN_SAFE = re.compile(r"[^a-z0-9._-]+")


def domain_of(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        raise CatalogError(f"cannot derive a domain from {url!r}")
    return host


def mint_urn(domain: str, kind: str, name: str) -> str:
    """
    Domain-anchored, transport-independent identifier. ARD requires a stable
    logical name decoupled from the current URL, so an endpoint can move without
    breaking references.
        urn:ard:example.com:mcp-server:research
    """
    slug = _URN_SAFE.sub("-", name.strip().lower()).strip("-")
    return f"urn:ard:{domain}:{kind}:{slug}"


# ── representative queries ─────────────────────────────────────────────────

_STOP = {"the", "a", "an", "of", "and", "or", "to", "for", "with", "from",
         "this", "that", "it", "its", "returns", "return", "given", "using"}


def representative_queries(tools: list[dict], limit: int = 6) -> list[str]:
    """
    Derive natural-language queries a registry can match against. Most publishers
    write thin descriptions and rank poorly; deriving queries from the actual tool
    surface is a real quality edge, and it is what makes an entry findable.
    """
    qs: list[str] = []
    for t in tools:
        name = str(t.get("name", "")).strip()
        desc = str(t.get("description", "")).strip().rstrip(".")
        if not name:
            continue
        pretty = name.replace("_", " ").replace(".", " ").replace("-", " ")
        if desc:
            first = desc.split(".")[0].strip()
            if first and len(first) < 110:
                qs.append(first[0].lower() + first[1:])
        params = list((t.get("inputSchema") or {}).get("properties", {}).keys())
        if params:
            qs.append(f"{pretty} by {params[0].replace('_',' ')}")
        else:
            qs.append(pretty)
    # dedupe, keep order, drop near-empty
    seen, out = set(), []
    for q in qs:
        k = _URN_SAFE.sub(" ", q.lower()).strip()
        toks = [w for w in k.split() if w not in _STOP]
        if len(" ".join(toks)) < 4 or k in seen:
            continue
        seen.add(k)
        out.append(q)
        if len(out) >= limit:
            break
    return out


# ── catalog model ──────────────────────────────────────────────────────────

@dataclass
class Resource:
    """One advertised capability."""
    name: str
    description: str
    endpoint: str
    kind: str = "mcp-server"            # mcp-server | a2a-agent | openapi | catalog
    tools: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    # XCP trust metadata — tells a discovering agent this is verifiable live
    trust_tier: str = ""                # e.g. "A2xH2"
    xcp_gateway: str = ""               # gateway that fronts + verifies this
    auth: str = "xcp-mtls"              # xcp-mtls | oauth2 | none

    def media_type(self) -> str:
        return {
            "mcp-server": "application/vnd.mcp.server+json",
            "a2a-agent": "application/vnd.a2a.agent-card+json",
            "openapi": "application/vnd.oai.openapi+json",
            "catalog": "application/vnd.ard.catalog+json",
        }.get(self.kind, "application/json")


@dataclass
class Publisher:
    domain: str
    name: str
    contact: str = ""
    verification: str = "domain"        # domain | dns-txt | signed


def build_catalog(publisher: Publisher, resources: Iterable[Resource],
                  spec_version: str = CATALOG_SPEC_VERSION) -> dict[str, Any]:
    """
    Assemble the catalog document. ARD requires each entry to carry exactly one
    of `url` or `data` (a value-or-reference rule that keeps parsing
    unambiguous) — we always emit `url` and keep descriptive metadata alongside.
    """
    entries = []
    for r in resources:
        if not r.endpoint:
            raise CatalogError(f"resource {r.name!r} has no endpoint")
        entry: dict[str, Any] = {
            "id": mint_urn(publisher.domain, r.kind, r.name),
            "name": r.name,
            "description": r.description,
            "mediaType": r.media_type(),
            "url": r.endpoint,                     # value-or-reference: url only
            "tags": sorted(set(r.tags)) or [r.kind],
            "representativeQueries": representative_queries(r.tools),
        }
        trust: dict[str, Any] = {"auth": r.auth}
        if r.trust_tier:
            trust["xcpTrustTier"] = r.trust_tier
        if r.xcp_gateway:
            trust["xcpGateway"] = r.xcp_gateway
            trust["verifiedAtConnect"] = True
        entry["trust"] = trust
        if r.tools:
            entry["toolCount"] = len(r.tools)
        entries.append(entry)

    return {
        "specVersion": spec_version,
        "publisher": {
            "domain": publisher.domain,
            "name": publisher.name,
            **({"contact": publisher.contact} if publisher.contact else {}),
            "verification": publisher.verification,
        },
        "entries": entries,
    }


def validate_catalog(cat: dict[str, Any]) -> list[str]:
    """
    Local sanity checks. NOT a substitute for validating against the published
    ARD JSON Schema — the spec is a draft and this only catches obvious breaks.
    """
    problems: list[str] = []
    if not cat.get("specVersion"):
        problems.append("missing specVersion")
    pub = cat.get("publisher") or {}
    if not pub.get("domain"):
        problems.append("publisher.domain is required (it is the identity anchor)")
    entries = cat.get("entries")
    if not isinstance(entries, list) or not entries:
        problems.append("entries must be a non-empty list")
        return problems
    seen_ids = set()
    for i, e in enumerate(entries):
        where = f"entries[{i}]"
        for req in ("id", "name", "mediaType"):
            if not e.get(req):
                problems.append(f"{where}.{req} is required")
        if ("url" in e) == ("data" in e):
            problems.append(f"{where} must have exactly one of url or data")
        if e.get("id") in seen_ids:
            problems.append(f"{where}.id is duplicated: {e.get('id')}")
        seen_ids.add(e.get("id"))
        if e.get("url", "").startswith("http://"):
            problems.append(f"{where}.url should be https")
        if not e.get("representativeQueries"):
            problems.append(f"{where} has no representativeQueries — it will rank poorly")
    return problems


# ── MCP Registry manifest (the second pipe) ────────────────────────────────

def build_mcp_manifest(publisher: Publisher, r: Resource,
                       version: str = "1.0.0") -> dict[str, Any]:
    """
    A `server.json`-style manifest for the MCP Registry install path. Publishing
    to both keeps you discoverable whichever pipe an agent client uses.
    """
    ns = publisher.domain.replace(".", "-")
    return {
        "name": f"{ns}/{_URN_SAFE.sub('-', r.name.lower())}",
        "description": r.description,
        "version": version,
        "packages": [],
        "remotes": [{"type": "streamable-http", "url": r.endpoint}],
        "repository": {"url": f"https://{publisher.domain}", "source": "website"},
        "_xcp": {"trustTier": r.trust_tier, "xcpGateway": r.xcp_gateway} if r.trust_tier else {},
    }


# ── introspection: build resources from a live server ──────────────────────

def resource_from_tools_list(name: str, description: str, endpoint: str,
                             tools_list_result: dict, **kw: Any) -> Resource:
    """
    Build a Resource from an MCP `tools/list` response, so a publisher never has
    to hand-write their capability descriptions.
    """
    tools = (tools_list_result or {}).get("tools", [])
    if not isinstance(tools, list):
        raise CatalogError("tools/list result did not contain a tools array")
    return Resource(name=name, description=description, endpoint=endpoint,
                    tools=tools, **kw)


def write_catalog(cat: dict[str, Any], path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cat, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return path


__all__ = [
    "Publisher", "Resource", "build_catalog", "validate_catalog",
    "build_mcp_manifest", "representative_queries", "mint_urn", "domain_of",
    "resource_from_tools_list", "write_catalog", "CatalogError",
    "CATALOG_SPEC_VERSION", "WELL_KNOWN_PATH",
]
