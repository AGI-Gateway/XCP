#!/usr/bin/env python3
"""
harvest-registries.py — find published MCP servers in package registries.

The awesome-list indexes are curated and therefore incomplete. npm and PyPI are
where servers are actually *published*, so this harvests them directly and keeps
the `homepage` field, which is where a server's own documentation lives.

    python scripts/harvest-registries.py            # npm
    python scripts/harvest-registries.py --pypi     # + PyPI (slower)

Output merges into connectors/snapshot/servers.json via build-snapshot.py.
Everything harvested is INSTALLABLE and UNVERIFIED — a package on a registry is
not a running endpoint.
"""
import json, pathlib, re, sys, time, urllib.parse, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "connectors" / "snapshot" / "registries.json"

QUERIES = ["mcp-server", "mcp server", "modelcontextprotocol",
           "model context protocol", "keywords:mcp", "keywords:mcp-server"]
PAGE = 250
MAX_PAGES = 12

# A package is an MCP server if it says so, not if it fuzzy-matches "mcp".
NAME_RX = re.compile(r"(^|[-_@/])mcp([-_/]|$)|mcp[-_]?server|server[-_]?mcp", re.I)
KW_RX = re.compile(r"^(mcp|mcp-server|modelcontextprotocol|model-context-protocol)$", re.I)


def get(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"User-Agent": "xcp-catalog/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(12 * 1024 * 1024).decode("utf-8", "replace"))


def is_mcp(pkg: dict) -> bool:
    name = pkg.get("name", "")
    kws = [str(k) for k in (pkg.get("keywords") or [])]
    if any(KW_RX.match(k) for k in kws):
        return True
    if NAME_RX.search(name):
        return True
    desc = (pkg.get("description") or "").lower()
    return "model context protocol" in desc or "mcp server" in desc


def harvest_npm() -> dict[str, dict]:
    found: dict[str, dict] = {}
    for q in QUERIES:
        for page in range(MAX_PAGES):
            url = ("https://registry.npmjs.org/-/v1/search?text="
                   f"{urllib.parse.quote(q)}&size={PAGE}&from={page*PAGE}")
            try:
                doc = get(url)
            except Exception as e:
                print(f"    {q} p{page}: {e}")
                break
            objs = doc.get("objects", [])
            if not objs:
                break
            for o in objs:
                p = o.get("package", {})
                if not is_mcp(p):
                    continue
                name = p.get("name", "")
                if not name or name in found:
                    continue
                links = p.get("links", {})
                found[name] = {
                    "id": re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-"),
                    "name": name,
                    "endpoint": "",
                    "install": f"npx -y {name}",
                    "kind": "installable",
                    "description": (p.get("description") or "")[:280],
                    "vendor": (p.get("publisher") or {}).get("username", ""),
                    "source": "npm",
                    "docs": links.get("homepage") or links.get("repository")
                            or links.get("npm") or f"https://www.npmjs.com/package/{name}",
                    "repo": links.get("repository", ""),
                    "registry": f"https://www.npmjs.com/package/{name}",
                    "version": p.get("version", ""),
                }
            time.sleep(0.2)
        print(f"  npm '{q}': running total {len(found)}")
    return found


def harvest_pypi(names: list[str]) -> dict[str, dict]:
    """PyPI has no search API; resolve a candidate list against the JSON API."""
    found: dict[str, dict] = {}
    for n in names:
        try:
            d = get(f"https://pypi.org/pypi/{urllib.parse.quote(n)}/json", timeout=15)
        except Exception:
            continue
        info = d.get("info", {})
        found[n] = {
            "id": re.sub(r"[^a-z0-9._-]+", "-", n.lower()).strip("-"),
            "name": n, "endpoint": "", "install": f"uvx {n}",
            "kind": "installable",
            "description": (info.get("summary") or "")[:280],
            "vendor": info.get("author") or "", "source": "pypi",
            "docs": info.get("home_page") or info.get("project_url")
                    or f"https://pypi.org/project/{n}/",
            "repo": ((info.get("project_urls") or {}).get("Source")
                     or (info.get("project_urls") or {}).get("Homepage") or ""),
            "registry": f"https://pypi.org/project/{n}/",
            "version": info.get("version", ""),
        }
        time.sleep(0.1)
    return found


def main() -> int:
    print("harvesting npm…")
    merged = harvest_npm()
    if "--pypi" in sys.argv:
        print("harvesting pypi…")
        cands = ["mcp", "mcp-server", "fastmcp", "mcp-server-fetch", "mcp-server-git",
                 "mcp-server-time", "mcp-server-sqlite", "mcp-proxy", "mcp-agent"]
        merged.update(harvest_pypi(cands))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "generatedAt": int(time.time()),
        "note": ("Harvested from public package registries. Every entry is "
                 "INSTALLABLE and UNVERIFIED: a published package is not a "
                 "running endpoint."),
        "counts": {"total": len(merged)},
        "servers": sorted(merged.values(), key=lambda v: v["id"]),
    }, separators=(",", ":"), sort_keys=True) + "\n")
    withdocs = sum(1 for v in merged.values() if v["docs"])
    print(f"\nwrote {OUT.relative_to(ROOT)}  {len(merged)} packages "
          f"({withdocs} with a docs link)  {OUT.stat().st_size//1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
