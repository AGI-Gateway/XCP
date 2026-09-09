#!/usr/bin/env python3
"""
validate-catalog.py — check that catalog entries actually exist.

Two different jobs, because routable and installable entries fail differently:

  ROUTABLE     probe the endpoint with a real MCP `tools/list` call. A 200 with a
               tools array means it is live and speaks the protocol. Anything
               else is recorded with the reason.

  INSTALLABLE  the package is the artifact, so validate that: does the repo or
               package still exist, is it archived, and where are its docs?

    python scripts/validate-catalog.py --routable        # needs open egress
    python scripts/validate-catalog.py --installable --limit 2000
    python scripts/validate-catalog.py --both

IMPORTANT: run `--routable` from a machine with open network egress. Behind a
restrictive proxy every endpoint returns a transport error and the run records
false negatives, which is worse for the catalog than having no data at all. The
script refuses to write routable results if it cannot reach a known-good control
host first.
"""
import json, os, pathlib, re, sys, time, urllib.error, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SNAP = ROOT / "connectors" / "snapshot" / "servers.json"
OUT = ROOT / "connectors" / "snapshot" / "validation.json"
GH = "https://api.github.com/repos/"
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
CONTROL = "https://example.com"


def _req(url: str, data=None, headers=None, timeout=12):
    h = {"User-Agent": "xcp-catalog-validator/0.1", **(headers or {})}
    body = json.dumps(data).encode() if data is not None else None
    if body:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h,
                                 method="POST" if body else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(2 * 1024 * 1024).decode("utf-8", "replace")


def egress_ok() -> bool:
    try:
        _req(CONTROL, timeout=8)
        return True
    except Exception:
        return False


# ── routable: does it speak MCP? ───────────────────────────────────────────

def probe_endpoint(url: str) -> dict:
    """MCP 2026-07-28: tools/list with the mandatory routing headers."""
    try:
        status, body = _req(url, data={"jsonrpc": "2.0", "id": 1,
                                       "method": "tools/list"},
                            headers={"Mcp-Method": "tools/list",
                                     "Accept": "application/json, text/event-stream"})
    except urllib.error.HTTPError as e:
        code = e.code
        return {"reachable": code in (401, 403),   # auth-gated still means alive
                "status": code,
                "reason": "auth required" if code in (401, 403) else f"http {code}",
                "tools": []}
    except Exception as e:
        return {"reachable": False, "status": 0,
                "reason": type(e).__name__, "tools": []}
    tools = []
    try:
        doc = json.loads(re.sub(r"^data:\s*", "", body.strip().splitlines()[-1])
                         if body.lstrip().startswith("data:") else body)
        tools = [t.get("name", "") for t in
                 ((doc.get("result") or {}).get("tools") or [])]
    except Exception:
        pass
    return {"reachable": True, "status": status,
            "reason": "ok" if tools else "responded, no tool list",
            "tools": tools[:60]}


# ── installable: does the artifact still exist? ────────────────────────────

def check_repo(slug: str) -> dict:
    hdr = {"Accept": "application/vnd.github+json"}
    if TOKEN:
        hdr["Authorization"] = f"Bearer {TOKEN}"
    try:
        status, body = _req(GH + slug, headers=hdr, timeout=15)
        d = json.loads(body)
        return {"exists": True, "archived": bool(d.get("archived")),
                "stars": d.get("stargazers_count", 0),
                "docs": d.get("homepage") or d.get("html_url", ""),
                "description": (d.get("description") or "")[:200],
                "pushed": (d.get("pushed_at") or "")[:10],
                "license": ((d.get("license") or {}) or {}).get("spdx_id") or ""}
    except urllib.error.HTTPError as e:
        return {"exists": False, "reason": f"http {e.code}"}
    except Exception as e:
        return {"exists": False, "reason": type(e).__name__}


def _save(results: dict) -> None:
    OUT.write_text(json.dumps({"generatedAt": int(time.time()),
                               "results": results}, separators=(",", ":"),
                              sort_keys=True) + "\n")


REPO_RX = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")


def main() -> int:
    doc = json.loads(SNAP.read_text())
    servers = doc["servers"]
    limit = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else 10**9
    do_r = "--routable" in sys.argv or "--both" in sys.argv
    do_i = "--installable" in sys.argv or "--both" in sys.argv
    results = json.loads(OUT.read_text())["results"] if OUT.is_file() else {}

    if do_r:
        if not egress_ok():
            print("REFUSING routable probes: no open egress (control host "
                  f"{CONTROL} unreachable). Every result would be a false "
                  "negative caused by this machine, not the endpoints.")
        else:
            targets = [s for s in servers if s.get("kind") == "routable"][:limit]
            print(f"probing {len(targets)} routable endpoints…")
            for i, s in enumerate(targets, 1):
                results[s["id"]] = {"kind": "routable", **probe_endpoint(s["endpoint"])}
                if i % 25 == 0:
                    print(f"  {i}/{len(targets)}")

    if do_i:
        targets = [s for s in servers
                   if s.get("kind") == "installable" and REPO_RX.search(
                       s.get("install", "") + " " + s.get("id", ""))][:limit]
        print(f"validating {len(targets)} installable artifacts…")
        targets = [s for s in targets if s["id"] not in results]
        print(f"  ({len(targets)} not yet checked)")
        for i, s in enumerate(targets, 1):
            m = REPO_RX.search(s.get("install", ""))
            if not m:
                continue
            results[s["id"]] = {"kind": "installable", **check_repo(m.group(1))}
            if i % 50 == 0:
                alive = sum(1 for v in results.values() if v.get("exists"))
                print(f"  {i}/{len(targets)}  ({alive} confirmed)", flush=True)
                _save(results)          # checkpoint: a long run must be resumable

    _save(results)
    ok_r = sum(1 for v in results.values() if v.get("reachable"))
    ok_i = sum(1 for v in results.values() if v.get("exists"))
    print(f"\nwrote {OUT.relative_to(ROOT)}  {len(results)} checked  "
          f"({ok_r} endpoints reachable, {ok_i} artifacts confirmed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
