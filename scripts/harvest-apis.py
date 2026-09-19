#!/usr/bin/env python3
"""
harvest-apis.py — index public APIs that XCP can wrap into MCP servers.

Uses the APIs.guru bulk index: ~2,500 publicly reachable APIs with
machine-readable OpenAPI specs, in a single document. Each becomes a WRAPPABLE
catalog entry — not routable, because it speaks REST, but one `xcp wrap` from
being routable at your own node's URL.

    python scripts/harvest-apis.py

Spec URLs are rewritten to raw.githubusercontent.com where possible so a wrap
does not depend on a third-party API host being up.
"""
import json, pathlib, re, sys, time, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "connectors" / "snapshot" / "apis.json"
BULK = ("https://raw.githubusercontent.com/APIs-guru/openapi-directory/"
        "gh-pages/v2/list.json")
MIRROR = ("https://raw.githubusercontent.com/APIs-guru/openapi-directory/"
          "main/APIs/")

# APIs.guru categories -> XCP catalog categories
CATMAP = {
    "financial": "finance-payments", "payment": "finance-payments",
    "ecommerce": "ecommerce", "cloud": "cloud-infra",
    "developer_tools": "dev-tools", "open_data": "science-research",
    "security": "security", "monitoring": "observability",
    "analytics": "data-stores", "storage": "data-stores",
    "media": "media-design", "photo": "media-design",
    "email": "communication", "messaging": "communication",
    "social": "search-web", "search": "search-web",
    "location": "location-weather", "transport": "location-weather",
    "weather": "location-weather", "iot": "iot-hardware",
    "hardware": "iot-hardware", "machine_learning": "ai-agents",
    "text": "ai-agents", "collaboration": "productivity",
    "customer_relation": "crm-sales", "marketing": "crm-sales",
    "enterprise": "productivity", "eventmanagement": "productivity",
    "telecom": "communication", "healthcare": "science-research",
    "sports": "other", "entertainment": "media-design",
}


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", (s or "").lower()).strip("-")


def spec_url(pref: dict, provider: str) -> str:
    """
    Prefer the GitHub mirror: wrapping should not depend on a third-party API
    host being reachable.
    """
    yaml_url = pref.get("swaggerYamlUrl") or ""
    m = re.search(r"/v2/specs/(.+?)/(.+?)/(swagger|openapi)\.yaml$", yaml_url)
    if m:
        return f"{MIRROR}{m.group(1)}/{m.group(2)}/{m.group(3)}.yaml"
    return yaml_url or pref.get("swaggerUrl", "")


def base_url(pref: dict) -> str:
    """Derive the API's own base URL from the spec origin or contact."""
    info = pref.get("info") or {}
    for o in (info.get("x-origin") or []):
        u = str((o or {}).get("url", ""))
        m = re.match(r"(https://[^/]+)", u)
        if m:
            return m.group(1)
    url = ((info.get("contact") or {}).get("url") or "")
    m = re.match(r"(https?://[^/]+)", url)
    return (m.group(1).replace("http://", "https://") if m else "")


def main() -> int:
    print("fetching the bulk index…")
    with urllib.request.urlopen(BULK, timeout=90) as r:
        bulk = json.loads(r.read(32 * 1024 * 1024).decode("utf-8", "replace"))
    print(f"  {len(bulk)} APIs")

    out: dict[str, dict] = {}
    skipped = 0
    for provider, entry in bulk.items():
        versions = entry.get("versions") or {}
        pref = versions.get(entry.get("preferred")) or (
            list(versions.values())[-1] if versions else None)
        if not pref:
            skipped += 1
            continue
        info = pref.get("info") or {}
        su = spec_url(pref, provider)
        if not su.startswith("https://"):
            skipped += 1
            continue
        cats = [CATMAP.get(c, "") for c in (info.get("x-apisguru-categories") or [])]
        category = next((c for c in cats if c), "other")
        pid = slug(provider)
        out[pid] = {
            "id": pid,
            "name": info.get("title") or provider,
            "kind": "wrappable",
            "apiBase": base_url(pref),
            "specUrl": su,
            "version": entry.get("preferred", ""),
            "openapi": pref.get("openapiVer", ""),
            "docs": ((info.get("contact") or {}).get("url")
                     or info.get("termsOfService") or f"https://{provider}"),
            "provider": provider,
            "category": category,
            "source": "apis.guru",
            "operations": 0,
            "description": re.sub(r"\s+", " ", (info.get("description") or ""))[:280]
                            or f"Public API for {provider}.",
            "updated": (pref.get("updated") or "")[:10],
        }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "generatedAt": int(time.time()), "source": BULK,
        "note": ("Public APIs with OpenAPI specs. WRAPPABLE, not routable: each "
                 "speaks REST and becomes an MCP endpoint only once XCP "
                 "generates a wrapper and an operator deploys it."),
        "counts": {"total": len(out)},
        "apis": sorted(out.values(), key=lambda v: v["id"]),
    }, separators=(",", ":"), sort_keys=True) + "\n")

    withbase = sum(1 for v in out.values() if v["apiBase"])
    mirrored = sum(1 for v in out.values() if "raw.githubusercontent" in v["specUrl"])
    print(f"\nwrote {OUT.relative_to(ROOT)}  {len(out)} APIs "
          f"({skipped} skipped)")
    print(f"  with apiBase        {withbase}")
    print(f"  spec on GitHub      {mirrored}")
    from collections import Counter
    print("  categories:", dict(Counter(v["category"] for v in out.values()).most_common(8)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
