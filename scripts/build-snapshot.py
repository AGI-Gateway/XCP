#!/usr/bin/env python3
"""
build-snapshot.py — refresh the bundled discovery snapshot.

The curated catalog is a few dozen verified endpoints. The snapshot is the long
tail: thousands of real MCP servers harvested from public indexes, so a fresh
node has a useful catalog before it has crawled anything or met a peer.

Everything here arrives unverified and untrusted. Installable entries are leads,
not destinations — see connectors/README.md.

    python scripts/build-snapshot.py            # from bundled/ cached sources
    python scripts/build-snapshot.py --fetch    # re-fetch upstream first
"""
import json, pathlib, sys, time, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "connectors" / "snapshot" / "servers.json"

SOURCES = {
    "punkpeye":  "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md",
    "abordage":  "https://raw.githubusercontent.com/abordage/awesome-mcp/main/README.md",
    "wong2":     "https://raw.githubusercontent.com/wong2/awesome-mcp-servers/main/README.md",
    "appcypher": "https://raw.githubusercontent.com/appcypher/awesome-mcp-servers/main/README.md",
    "official":  "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md",
}


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=45) as r:
        return r.read(8 * 1024 * 1024).decode("utf-8", "replace")


def main() -> int:
    from connectors.sources import normalise_repo_index, Source, SourceKind
    from connectors.taxonomy import classify, CATEGORIES
    cache = pathlib.Path("/tmp")
    merged: dict[str, dict] = {}
    for name, url in SOURCES.items():
        try:
            if "--fetch" in sys.argv:
                md = fetch(url)
                (cache / f"idx-{name}.md").write_text(md, encoding="utf-8")
            else:
                md = (cache / f"idx-{name}.md").read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  skip {name}: {e}")
            continue
        entries = normalise_repo_index(
            md, Source(id=name, kind=SourceKind.REPO_INDEX, url=url))
        for e in entries:
            merged.setdefault(e.id, {
                "id": e.id, "name": e.name, "endpoint": e.endpoint_url,
                "install": e.install_ref, "kind": e.kind.value,
                "description": e.description, "vendor": e.vendor, "source": name,
                "category": classify(e.id, e.description),
            })
        print(f"  {name:<10} {len(entries):>5} entries")

    routable = sum(1 for v in merged.values() if v["kind"] == "routable")
    doc = {
        "specVersion": "0.1-draft",
        "generatedAt": int(time.time()),
        "sources": SOURCES,
        "counts": {"total": len(merged), "routable": routable,
                   "installable": len(merged) - routable},
        "categories": {c: sum(1 for v in merged.values() if v["category"] == c)
                       for c in CATEGORIES},
        "note": ("Harvested from public indexes. Every entry is UNVERIFIED and "
                 "UNTRUSTED: routable ones reach the Trust Firewall as 'unknown' "
                 "(observe-only, sandboxed, nothing binding); installable ones are "
                 "leads, not destinations, until an operator runs and wraps them."),
        "servers": sorted(merged.values(), key=lambda v: v["id"]),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True) + "\n")
    print(f"\nwrote {OUT.relative_to(ROOT)}  "
          f"{len(merged)} servers ({routable} routable, "
          f"{len(merged)-routable} installable)  "
          f"{OUT.stat().st_size//1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
