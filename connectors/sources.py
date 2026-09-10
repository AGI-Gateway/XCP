"""
connectors.sources — how the catalog reaches internet scale.

The curated files in `catalog/` are the verified core: a few dozen endpoints
somebody checked by hand. They will never be the whole catalog, because there are
tens of thousands of MCP servers reachable on the internet and the number moves
weekly. A global catalog cannot be a folder of YAML written by people.

So the catalog has two halves:

    catalog/*.yaml   curated, verified, promotable      — dozens
    ingested         crawled from upstream + peers      — thousands

Ingested entries arrive at `verification: unconfirmed` and `trust: unknown`,
which the Trust Firewall already treats correctly: reachable in observe mode,
read-only, sandboxed, output quarantined, nothing binding, no settlement. That is
what makes it safe to index a corpus nobody has vetted — discovery is not
endorsement, and the grading is enforced rather than advisory.

WHERE ENTRIES COME FROM
-----------------------
  official     the MCP Registry — structured, vendor-published
  ard          any domain's /.well-known/ai-catalog.json (RFC 8615)
  aggregator   community indexes of public servers
  peer         another XCP node's catalog, via federation
  scan         internet-wide scan output, imported from a file

FEDERATION IS THE POINT
-----------------------
Every node running this codebase publishes what it knows and ingests what its
peers know. No node has to crawl the whole internet, and no node depends on a
central index — including ours. Two nodes with different peer sets converge on
overlapping views without any coordination, and a node that never talks to
anyone still works with whatever it curated itself.

SAFETY
------
Ingestion pulls untrusted documents from arbitrary hosts, so it is an SSRF sink
and a poisoning target. Every fetch goes through `xcpsec.argfirewall.ssrf_guard`,
responses are size-capped, and nothing ingested can raise its own trust class —
promotion is a local decision, never something a remote document can assert.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import json
import pathlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlparse

MAX_DOCUMENT_BYTES = 5 * 1024 * 1024      # cap on any fetched document
MAX_ENTRIES_PER_SOURCE = 50_000


class EndpointKind(str, Enum):
    """
    The distinction that matters for a routing catalog.

    Most MCP servers in the wild are NOT network endpoints. They are packages you
    install and run locally over stdio. You cannot route agent traffic to one:
    there is nothing to connect to until somebody runs it.

        ROUTABLE     a remote HTTPS endpoint — an agent can connect today
        WRAPPABLE    a public API with a machine-readable spec. Reachable over
                     the internet, but it speaks REST, not MCP: an agent cannot
                     connect to it until XCP generates and deploys a wrapper.
        INSTALLABLE  a package (npm/pip/repo) — becomes routable only once a
                     node installs it and exposes it through its own gateway

    That second case is the whole federation story. XCP does not host the
    long tail; thousands of independent nodes each wrap the servers they run and
    publish them to peers. An installable entry is a lead, not a destination.
    """
    ROUTABLE = "routable"
    WRAPPABLE = "wrappable"
    INSTALLABLE = "installable"

    @property
    def reachable_today(self) -> bool:
        """Only ROUTABLE means an agent can connect right now."""
        return self is EndpointKind.ROUTABLE


class SourceKind(str, Enum):
    OFFICIAL = "official"        # the MCP Registry
    ARD = "ard"                  # a domain's /.well-known/ai-catalog.json
    AGGREGATOR = "aggregator"    # community index
    PEER = "peer"                # another XCP node
    SCAN = "scan"                # imported scan output
    REPO_INDEX = "repo_index"    # a curated list of source repositories
    MANUAL = "manual"            # the curated catalog/ files


class IngestError(Exception):
    pass


@dataclass
class Source:
    """An upstream the catalog can be populated from."""
    id: str
    kind: SourceKind
    url: str = ""
    description: str = ""
    enabled: bool = True
    # a source can never grant more than this, whatever its documents claim
    max_trust: str = "unknown"

    def validate(self) -> list[str]:
        p = []
        if not self.id:
            p.append("source needs an id")
        if self.kind != SourceKind.SCAN and not self.url.startswith("https://"):
            p.append(f"{self.id}: source url must be https")
        if self.max_trust != "unknown" and self.kind != SourceKind.MANUAL:
            p.append(f"{self.id}: only the curated catalog may exceed 'unknown'")
        return p


# Well-known upstreams. None is required, and none is operated by this project.
DEFAULT_SOURCES: list[Source] = [
    Source(id="mcp-registry", kind=SourceKind.OFFICIAL,
           url="https://registry.modelcontextprotocol.io/v0/servers",
           description="The official MCP Registry — structured, vendor-published."),
    Source(id="ard-crawl", kind=SourceKind.ARD, url="https://example.invalid",
           description="Any domain's /.well-known/ai-catalog.json. Seed with the "
                       "domains you care about; peers contribute the rest.",
           enabled=False),
]


@dataclass
class IngestedEntry:
    """
    A discovered server, normalised. Deliberately thinner than a curated
    `ConnectorEntry`: we know where it is and who said so, and little else.
    """
    id: str
    name: str
    endpoint_url: str
    source_id: str
    source_kind: SourceKind
    description: str = ""
    vendor: str = ""
    transport: str = "streamable_http"
    auth_hint: str = "unknown"
    tags: list[str] = field(default_factory=list)
    discovered_at: int = 0
    kind: EndpointKind = EndpointKind.ROUTABLE
    install_ref: str = ""            # repo or package for INSTALLABLE entries
    category: str = "other"          # navigation aid, never a trust signal
    docs: str = ""                   # the server's own documentation
    api_base: str = ""               # upstream REST base, for WRAPPABLE
    spec_url: str = ""               # the OpenAPI document
    operations: int = 0              # how many API operations the spec exposes
    validated: str = "unchecked"     # alive | archived | gone | reachable | unreachable
    tools: list[str] = field(default_factory=list)   # only from a live probe
    # never negotiable from the wire
    verification_status: str = "unconfirmed"
    trust_class: str = "unknown"

    @property
    def host(self) -> str:
        return (urlparse(self.endpoint_url).hostname or "").lower()

    @property
    def routable(self) -> bool:
        return self.kind == EndpointKind.ROUTABLE and self.host != ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "endpoint": self.endpoint_url,
                "host": self.host, "source": self.source_id,
                "sourceKind": self.source_kind.value, "vendor": self.vendor,
                "transport": self.transport, "authHint": self.auth_hint,
                "tags": list(self.tags), "discoveredAt": self.discovered_at,
                "verification": self.verification_status,
                "trustClass": self.trust_class, "kind": self.kind.value,
                "category": self.category, "docs": self.docs,
                "validated": self.validated, "tools": list(self.tools),
                "apiBase": self.api_base, "specUrl": self.spec_url,
                "operations": self.operations,
                "installRef": self.install_ref}


def _safe_fetch(url: str, fetcher: Optional[Callable[[str], str]] = None) -> str:
    """Fetch a document with an SSRF guard and a size cap."""
    try:
        from security.xcpsec.argfirewall import ssrf_guard
        ssrf_guard(url)
    except ImportError:
        if not url.startswith("https://"):
            raise IngestError("refusing a non-https source without xcpsec")
    except PermissionError as e:
        raise IngestError(f"SSRF guard refused {url}: {e}")
    if fetcher is not None:
        body = fetcher(url)
    else:
        import urllib.request
        with urllib.request.urlopen(url, timeout=20) as r:
            body = r.read(MAX_DOCUMENT_BYTES + 1).decode("utf-8", "replace")
    if len(body.encode("utf-8", "ignore")) > MAX_DOCUMENT_BYTES:
        raise IngestError(f"{url}: document exceeds {MAX_DOCUMENT_BYTES} bytes")
    return body


# ── normalisers, one per upstream shape ────────────────────────────────────

def _slug(text: str) -> str:
    import re
    return re.sub(r"[^a-z0-9._-]+", "-", (text or "").strip().lower()).strip("-")


def normalise_mcp_registry(doc: Any, source: Source) -> list[IngestedEntry]:
    """The official MCP Registry `servers` shape."""
    now = int(time.time())
    items = doc.get("servers", doc) if isinstance(doc, dict) else doc
    out = []
    for s in (items or [])[:MAX_ENTRIES_PER_SOURCE]:
        if not isinstance(s, dict):
            continue
        remotes = s.get("remotes") or []
        url = ""
        for r in remotes:
            if isinstance(r, dict) and str(r.get("url", "")).startswith("https://"):
                url = r["url"]
                break
        if not url:
            continue                      # local/stdio-only servers are not routable
        name = str(s.get("name", "")) or url
        out.append(IngestedEntry(
            id=_slug(name), name=name, endpoint_url=url,
            description=str(s.get("description", ""))[:400],
            vendor=str((s.get("repository") or {}).get("url", ""))[:200],
            source_id=source.id, source_kind=source.kind, discovered_at=now))
    return out


def normalise_ard_catalog(doc: Any, source: Source) -> list[IngestedEntry]:
    """A domain's /.well-known/ai-catalog.json."""
    now = int(time.time())
    out = []
    entries = (doc or {}).get("entries", []) if isinstance(doc, dict) else []
    publisher = ((doc or {}).get("publisher") or {}).get("domain", "")
    for e in entries[:MAX_ENTRIES_PER_SOURCE]:
        url = str(e.get("url", ""))
        if not url.startswith("https://"):
            continue
        trust = e.get("trust") or {}
        out.append(IngestedEntry(
            id=_slug(str(e.get("id") or e.get("name") or url)),
            name=str(e.get("name", "")) or url, endpoint_url=url,
            description=str(e.get("description", ""))[:400], vendor=publisher,
            auth_hint=str(trust.get("auth", "unknown")),
            tags=[str(t) for t in (e.get("tags") or [])][:10],
            source_id=source.id, source_kind=source.kind, discovered_at=now))
    return out


def normalise_peer_catalog(doc: Any, source: Source) -> list[IngestedEntry]:
    """Another XCP node's exported catalog."""
    now = int(time.time())
    out = []
    for e in ((doc or {}).get("connectors", []))[:MAX_ENTRIES_PER_SOURCE]:
        url = str(e.get("endpoint", ""))
        if not url.startswith("https://"):
            continue
        out.append(IngestedEntry(
            id=_slug(str(e.get("id") or url)), name=str(e.get("name", "")) or url,
            endpoint_url=url, description=str(e.get("description", ""))[:400],
            vendor=str(e.get("vendor", "")), auth_hint=str(e.get("auth", "unknown")),
            tags=[str(t) for t in (e.get("tags") or [])][:10],
            source_id=source.id, source_kind=source.kind, discovered_at=now))
    return out


_BULLET = re.compile(r"^\s*[-*]\s+(.*)$")
_REPO = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
_IMG = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_EMOJI = re.compile(r"[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]")
_REMOTE = re.compile(
    r"https://(?!github\.com|glama\.ai|raw\.)"
    r"([a-z0-9-]+(?:\.[a-z0-9-]+)+)(/[A-Za-z0-9._~/-]*(?:mcp|sse)\b[A-Za-z0-9._~/-]*)")
_INSTALL = re.compile(r"`((?:npx|uvx|pipx|pip install|docker run)[^`]{2,80})`")


def normalise_repo_index(doc: Any, source: Source) -> list[IngestedEntry]:
    """
    A curated markdown index of MCP servers — the long tail.

    Most entries are INSTALLABLE: a repository you install and run over stdio.
    There is no endpoint to route to until an operator runs one. A minority
    advertise a remote endpoint in their description; those are extracted as
    ROUTABLE, and still arrive unverified and untrusted like anything crawled.
    """
    now = int(time.time())
    out: list[IngestedEntry] = []
    seen: set[str] = set()

    if isinstance(doc, str):
        lines = doc.splitlines()
    else:
        items = doc if isinstance(doc, list) else (doc or {}).get("servers", [])
        lines = []
        for s in items:
            repo = str(s.get("repo") or s.get("repository") or "")
            lines.append(f"- [{s.get('name','')}]({repo}) - {s.get('description','')}")

    for line in lines[: MAX_ENTRIES_PER_SOURCE * 4]:
        m = _BULLET.match(line)
        if not m:
            continue
        body = m.group(1)
        r = _REPO.search(body)
        if not r:
            continue
        slug = f"{r.group(1)}/{r.group(2)}"
        if slug.lower() in seen:
            continue
        seen.add(slug.lower())

        desc = _IMG.sub("", body)
        desc = _LINK.sub(r"\1", desc)
        desc = _EMOJI.sub(" ", desc)
        desc = re.sub(r"^\s*[\w./-]+\s*[-\u2013\u2014]\s*", "", desc.strip())
        desc = re.sub(r"\s+", " ", desc).strip(" -\u2013\u2014")[:280]

        rem = _REMOTE.search(body)
        ins = _INSTALL.search(body)
        endpoint = f"https://{rem.group(1)}{rem.group(2)}" if rem else ""
        out.append(IngestedEntry(
            id=_slug(slug), name=slug, endpoint_url=endpoint,
            install_ref=(ins.group(1) if ins else f"https://github.com/{slug}"),
            kind=EndpointKind.ROUTABLE if endpoint else EndpointKind.INSTALLABLE,
            description=desc, vendor=r.group(1),
            source_id=source.id, source_kind=source.kind, discovered_at=now))
        if len(out) >= MAX_ENTRIES_PER_SOURCE:
            break
    return out


NORMALISERS: dict[SourceKind, Callable[[Any, Source], list[IngestedEntry]]] = {
    SourceKind.OFFICIAL: normalise_mcp_registry,
    SourceKind.AGGREGATOR: normalise_mcp_registry,
    SourceKind.ARD: normalise_ard_catalog,
    SourceKind.PEER: normalise_peer_catalog,
    SourceKind.SCAN: normalise_mcp_registry,
    SourceKind.REPO_INDEX: normalise_repo_index,
}


# ── the index ──────────────────────────────────────────────────────────────

class GlobalCatalog:
    """
    The union of what this node curated and what it has discovered.

        cat = GlobalCatalog()
        cat.load_curated()                       # verified core
        cat.ingest(Source(...), document)        # thousands more
        cat.apply_to_firewall(fw)                # graded reachability, no per-server code
        cat.route("mcp:tools/search")            # find candidates for a scope
    """

    def __init__(self) -> None:
        self.curated: list[Any] = []
        self.ingested: dict[str, IngestedEntry] = {}     # keyed by host+id

    # ---- population ----
    SNAPSHOT = pathlib.Path(__file__).resolve().parent / "snapshot" / "servers.json"

    def load_snapshot(self, path: Optional[Any] = None) -> int:
        """
        Load the bundled discovery snapshot: thousands of real MCP servers
        harvested from public indexes, so a fresh node is useful before it has
        crawled anything or met a peer.

        Everything here is unverified and untrusted, exactly like a live crawl.
        Refresh it with `python scripts/build-snapshot.py --fetch`.
        """
        f = pathlib.Path(path) if path else self.SNAPSHOT
        if not f.is_file():
            return 0
        doc = json.loads(f.read_text())
        now = int(time.time())
        curated_hosts = {_host(c.endpoint_url) for c in self.curated}
        added = 0
        for s in doc.get("servers", []):
            try:
                kind = EndpointKind(str(s.get("kind", "installable")))
            except ValueError:
                kind = EndpointKind.INSTALLABLE
            url = str(s.get("endpoint", "") or "")
            if kind == EndpointKind.ROUTABLE and _host(url) in curated_hosts:
                continue
            e = IngestedEntry(
                id=str(s.get("id", "")), name=str(s.get("name", "")),
                endpoint_url=url, install_ref=str(s.get("install", "")),
                kind=kind, description=str(s.get("description", ""))[:300],
                vendor=str(s.get("vendor", "")), source_id="snapshot",
                category=str(s.get("category", "other")),
                docs=str(s.get("docs", "")),
                validated=str(s.get("validated", "unchecked")),
                tools=list(s.get("tools") or []),
                api_base=str(s.get("apiBase", "")),
                spec_url=str(s.get("specUrl", "")),
                operations=int(s.get("operations", 0) or 0),
                source_kind=SourceKind.REPO_INDEX, discovered_at=now)
            key = f"{e.host or e.install_ref or e.spec_url}|{e.id}"
            if key not in self.ingested:
                self.ingested[key] = e
                added += 1
        return added

    def load_curated(self) -> int:
        from .loader import load_catalog
        self.curated = load_catalog()
        return len(self.curated)

    def ingest(self, source: Source, document: Any) -> int:
        problems = source.validate()
        if problems:
            raise IngestError("; ".join(problems))
        if not source.enabled:
            return 0
        doc = json.loads(document) if isinstance(document, str) else document
        norm = NORMALISERS.get(source.kind)
        if norm is None:
            raise IngestError(f"no normaliser for source kind {source.kind}")
        added = 0
        curated_hosts = {_host(c.endpoint_url) for c in self.curated}
        from .taxonomy import classify
        for e in norm(doc, source):
            if e.category == "other":
                e.category = classify(e.id, e.description, e.tags)
            if e.kind == EndpointKind.ROUTABLE:
                if not e.endpoint_url.startswith("https://") or not e.host:
                    continue
                if e.host in curated_hosts:
                    continue              # curated always wins over crawled
            elif e.kind == EndpointKind.WRAPPABLE:
                if not e.spec_url or not e.api_base:
                    continue              # a wrappable lead needs a spec to generate from
            elif not e.install_ref:
                continue                  # an installable lead needs a package ref
            # trust and verification are set locally, never by the document
            e.trust_class = "unknown"
            e.verification_status = "unconfirmed"
            key = f"{e.host or e.install_ref}|{e.id}"
            if key not in self.ingested:
                self.ingested[key] = e
                added += 1
        return added

    def ingest_url(self, source: Source,
                   fetcher: Optional[Callable[[str], str]] = None) -> int:
        return self.ingest(source, _safe_fetch(source.url, fetcher))

    # ---- use ----
    def apply_to_firewall(self, firewall: Any) -> int:
        from trustfirewall import ServerClass
        mapping = {"unknown": ServerClass.UNKNOWN, "probed": ServerClass.PROBED,
                   "attested": ServerClass.ATTESTED,
                   "contracted": ServerClass.CONTRACTED}
        n = 0
        for c in self.curated:
            h = _host(c.endpoint_url)
            if h:
                firewall.classify(h, mapping[c.trust_class])
                n += 1
        for e in self.ingested.values():
            if e.routable:                # nothing to classify for a package
                firewall.classify(e.host, ServerClass.UNKNOWN)
                n += 1
        return n

    def route(self, scope: str) -> list[dict[str, Any]]:
        """
        Candidate endpoints for a scope, best-verified first. Routing prefers
        what somebody actually checked; crawled entries are the long tail.
        """
        rank = {"confirmed": 0, "community": 1, "unconfirmed": 2, "self_hosted": 3}
        out = []
        for c in self.curated:
            if scope in c.scopes_exposed or any(
                    s.endswith("*") and scope.startswith(s[:-1])
                    for s in c.scopes_exposed):
                out.append({"id": c.id, "endpoint": c.endpoint_url,
                            "verification": c.verification_status,
                            "trust": c.trust_class, "curated": True})
        out.sort(key=lambda r: rank.get(r["verification"], 9))
        return out

    def search(self, text: str, limit: int = 25) -> list[dict[str, Any]]:
        q = (text or "").lower()
        hits = []
        for c in self.curated:
            if q in c.id.lower() or q in c.name.lower() or q in " ".join(c.tags):
                hits.append({"id": c.id, "endpoint": c.endpoint_url,
                             "curated": True,
                             "verification": c.verification_status})
        for e in self.ingested.values():
            if q in e.id or q in e.name.lower() or q in " ".join(e.tags).lower():
                hits.append({**e.to_dict(), "curated": False})
        return hits[:limit]

    def by_category(self, category: str, kind: Optional[str] = None,
                    limit: int = 100) -> list[dict[str, Any]]:
        """Browse one slice of the catalog."""
        out = []
        for c in self.curated:
            if getattr(c, "category", "") == category:
                out.append({"id": c.id, "endpoint": c.endpoint_url,
                            "curated": True, "kind": "routable",
                            "docs": c.homepage or c.verification_source,
                            "tools": list(c.scopes_exposed),
                            "validated": "curated",
                            "verification": c.verification_status})
        for e in self.ingested.values():
            if e.category != category:
                continue
            if kind and e.kind.value != kind:
                continue
            out.append({**e.to_dict(), "curated": False})
        return out[:limit]

    def validation_summary(self) -> dict[str, int]:
        """
        How much of the catalog has actually been checked, and what came back.
        `unchecked` is reported honestly rather than folded into a pass rate.
        """
        from collections import Counter
        c = Counter(e.validated for e in self.ingested.values())
        c.update({"curated": len(self.curated)})
        return dict(c)

    def categories(self) -> dict[str, dict[str, int]]:
        """Counts per category, split by what is actually reachable today."""
        from collections import defaultdict
        agg: dict[str, dict[str, int]] = defaultdict(
            lambda: {"total": 0, "routable": 0, "installable": 0, "curated": 0})
        for c in self.curated:
            cat = getattr(c, "category", "other")
            agg[cat]["total"] += 1; agg[cat]["routable"] += 1; agg[cat]["curated"] += 1
        for e in self.ingested.values():
            agg[e.category]["total"] += 1
            agg[e.category]["routable" if e.routable else "installable"] += 1
        return dict(sorted(agg.items(), key=lambda kv: -kv[1]["total"]))

    def export(self) -> dict[str, Any]:
        """Publish this node's view so peers can ingest it."""
        return {
            "specVersion": "0.1-draft",
            "generatedAt": int(time.time()),
            "connectors": [c.to_dict() for c in self.curated],
            "ingested": [e.to_dict() for e in self.ingested.values()],
        }

    def stats(self) -> dict[str, Any]:
        from collections import Counter
        by_source = Counter(e.source_kind.value for e in self.ingested.values())
        by_status = Counter(c.verification_status for c in self.curated)
        by_kind = Counter(e.kind.value for e in self.ingested.values())
        return {"curated": len(self.curated), "ingested": len(self.ingested),
                "ingestedByKind": dict(by_kind),
                "routable": sum(1 for e in self.ingested.values() if e.routable),
                "total": len(self.curated) + len(self.ingested),
                "curatedByStatus": dict(by_status),
                "ingestedBySource": dict(by_source),
                "distinctHosts": len({e.host for e in self.ingested.values()} |
                                     {_host(c.endpoint_url) for c in self.curated})}


def _host(url: str) -> str:
    return (urlparse(url or "").hostname or "").lower()


__all__ = ["GlobalCatalog", "Source", "SourceKind", "EndpointKind", "IngestedEntry",
           "IngestError", "DEFAULT_SOURCES", "NORMALISERS",
           "normalise_mcp_registry", "normalise_ard_catalog",
           "normalise_peer_catalog", "normalise_repo_index", "MAX_DOCUMENT_BYTES"]
