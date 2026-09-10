#!/usr/bin/env python3
"""
harvest-apis.py — index public APIs that XCP can wrap into MCP servers.

Sources the APIs.guru OpenAPI directory: several thousand publicly reachable
APIs with machine-readable specs. Each becomes a WRAPPABLE catalog entry — not
routable, because it speaks REST, but one `xcp wrap` away from being routable at
your own node's URL.

    GH_TOKEN=... python scripts/harvest-apis.py --limit 400
"""
import json, os, pathlib, re, sys, time, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "connectors" / "snapshot" / "apis.json"
API = "https://api.github.com/repos/APIs-guru/openapi-directory/contents/APIs"
RAW = "https://raw.githubusercontent.com/APIs-guru/openapi-directory/main/APIs/"
TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""


def gh(url: str):
    h = {"Accept": "application/vnd.github+json", "User-Agent": "xcp/0.1"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read(8 * 1024 * 1024).decode("utf-8", "replace"))


def main() -> int:
    limit = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else 400
    providers = [x["name"] for x in gh(API) if x["type"] == "dir"]
    print(f"{len(providers)} API providers in the directory")
    out: dict[str, dict] = {}
    resume = json.loads(OUT.read_text())["apis"] if OUT.is_file() else []
    for a in resume:
        out[a["id"]] = a
    todo = [p for p in providers if re.sub(r"[^a-z0-9.-]+", "-", p.lower()) not in out]
    print(f"  {len(out)} already indexed, {len(todo)} to go")

    for i, prov in enumerate(todo[:limit], 1):
        try:
            versions = gh(f"{API}/{prov}")
        except Exception as e:
            print(f"  {prov}: {e}")
            continue
        # newest version directory, or a spec directly under the provider
        vers = [v["name"] for v in versions if v["type"] == "dir"]
        if vers:
            ver = sorted(vers)[-1]
            spec = f"{RAW}{prov}/{ver}/openapi.yaml"
        else:
            ver = ""
            spec = f"{RAW}{prov}/openapi.yaml"
        pid = re.sub(r"[^a-z0-9.-]+", "-", prov.lower())
        out[pid] = {
            "id": pid, "name": prov, "kind": "wrappable",
            "apiBase": "", "specUrl": spec, "version": ver,
            "docs": f"https://{prov}" if "." in prov else "",
            "source": "apis.guru", "operations": 0,
            "description": f"Public API for {prov}, wrappable into an MCP server.",
        }
        if i % 50 == 0:
            print(f"  {i}/{min(len(todo), limit)}")
            _save(out)
    _save(out)
    print(f"\nwrote {OUT.relative_to(ROOT)}  {len(out)} public APIs")
    return 0


def _save(out: dict) -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "generatedAt": int(time.time()),
        "note": ("Public APIs with OpenAPI specs. WRAPPABLE, not routable: each "
                 "speaks REST, and becomes an MCP endpoint only once XCP "
                 "generates a wrapper and an operator deploys it."),
        "counts": {"total": len(out)},
        "apis": sorted(out.values(), key=lambda v: v["id"]),
    }, separators=(",", ":"), sort_keys=True) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
