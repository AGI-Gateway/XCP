#!/usr/bin/env python3
"""
xcp — the self-serve command line for XCP.

Everything an organisation needs to stand up a verified agent endpoint and get
it discoverable, without talking to anybody:

    xcp init                 scaffold xcp.toml for this project
    xcp doctor               check the local environment and config
    xcp tier                 show the trust lattice / resolve your envelope
    xcp certs                generate a local mTLS dev PKI
    xcp up                   run the stack (verifier + gateway + server)
    xcp publish              generate ai-catalog.json + MCP registry manifest
    xcp verify <url>         probe an endpoint's XCP posture before trusting it
    xcp receipt <bundle>     verify a proof-of-delivery evidence bundle
    xcp catalog              inspect and search the discovery catalog

Zero third-party dependencies — standard library only, so `xcp` runs anywhere
Python 3.10+ does.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

CONFIG_NAME = "xcp.toml"

# ── tiny TOML reader (stdlib tomllib on 3.11+, minimal fallback otherwise) ──
try:
    import tomllib  # py3.11+

    def _load_toml(p: Path) -> dict:
        with open(p, "rb") as fh:
            return tomllib.load(fh)
except ImportError:                                   # pragma: no cover
    def _load_toml(p: Path) -> dict:
        cfg: dict[str, Any] = {}
        section = cfg
        for raw in p.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                section = cfg.setdefault(line[1:-1], {})
            elif "=" in line:
                k, v = (x.strip() for x in line.split("=", 1))
                if v.startswith(("'", '"')) and v.endswith(("'", '"')):
                    v = v[1:-1]
                elif v in ("true", "false"):
                    v = v == "true"
                elif v.lstrip("-").isdigit():
                    v = int(v)
                section[k] = v
        return cfg


# ── output helpers ─────────────────────────────────────────────────────────

def _c(code: str, s: str) -> str:
    return s if os.getenv("NO_COLOR") else f"\033[{code}m{s}\033[0m"


def ok(s: str) -> None:    print(f"  {_c('32', 'ok')}    {s}")
def warn(s: str) -> None:  print(f"  {_c('33', 'warn')}  {s}")
def bad(s: str) -> None:   print(f"  {_c('31', 'fail')}  {s}")
def info(s: str) -> None:  print(f"  {_c('36', '·')}     {s}")
def head(s: str) -> None:  print(f"\n{_c('1', s)}\n{'─' * len(s)}")


def find_config(start: Optional[Path] = None) -> Optional[Path]:
    d = (start or Path.cwd()).resolve()
    for cand in [d, *d.parents]:
        p = cand / CONFIG_NAME
        if p.exists():
            return p
    return None


def load_config() -> dict:
    p = find_config()
    if not p:
        bad(f"no {CONFIG_NAME} found — run `xcp init` first")
        sys.exit(1)
    return _load_toml(p)


# ── commands ───────────────────────────────────────────────────────────────

TEMPLATE = """# xcp.toml — XCP project configuration
# docs: https://github.com/AGI-Gateway/XCP/blob/main/docs/self-serve.md

[project]
name        = "{name}"
description = "{desc}"

[publisher]
# Your domain is the identity anchor for discovery — catalogs are trusted
# because they are served from a domain you demonstrably control.
domain  = "{domain}"
name    = "{org}"
contact = ""

[trust]
# Trust lattice position. Start where you are; `xcp tier --upgrade` shows the
# next step.  agent: free | registry | company     human: public | general_sso | enterprise
agent = "free"
human = "public"

[gateway]
url       = "http://localhost:8080"
posture   = "enforce"          # enforce | observe
upstreams = {{ }}                # name -> MCP url, e.g. {{ research = "http://localhost:9001/mcp" }}

[[resource]]
name        = "{name}"
description = "{desc}"
kind        = "mcp-server"     # mcp-server | a2a-agent | openapi
endpoint    = "https://{domain}/mcp"
tags        = []
"""


def cmd_init(args: argparse.Namespace) -> int:
    target = Path.cwd() / CONFIG_NAME
    if target.exists() and not args.force:
        bad(f"{CONFIG_NAME} already exists (use --force to overwrite)")
        return 1
    name = args.name or Path.cwd().name
    domain = args.domain or "example.com"
    target.write_text(TEMPLATE.format(
        name=name, desc=args.description or f"{name} capabilities",
        domain=domain, org=args.org or domain))
    head("Project initialised")
    ok(f"wrote {CONFIG_NAME}")
    info("next:  xcp doctor     — check your environment")
    info("       xcp tier       — see what authority your tier grants")
    info("       xcp up         — run the stack locally")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    head("Environment")
    py = sys.version_info
    (ok if py >= (3, 10) else bad)(f"python {py.major}.{py.minor}.{py.micro}")
    for mod, why in [("fastapi", "gateway + server"), ("httpx", "client"),
                     ("eth_account", "mandate signing"), ("cryptography", "certificates")]:
        try:
            __import__(mod)
            ok(f"{mod} available ({why})")
        except ImportError:
            warn(f"{mod} missing — needed for {why}:  pip install -r requirements.txt")
    if _which("openssl"):
        ok("openssl available (cert generation)")
    else:
        warn("openssl missing — `xcp certs` will not work")
    if _which("docker"):
        ok("docker available (xcp up --docker)")
    else:
        info("docker not found — `xcp up` will run processes directly")

    head("Configuration")
    p = find_config()
    if not p:
        warn(f"no {CONFIG_NAME} — run `xcp init`")
        return 0
    ok(f"config at {p}")
    cfg = _load_toml(p)
    dom = (cfg.get("publisher") or {}).get("domain", "")
    if not dom or dom == "example.com":
        warn("publisher.domain is unset/placeholder — discovery needs a real domain")
    else:
        ok(f"publisher domain: {dom}")
    res = cfg.get("resource") or []
    if isinstance(res, dict):
        res = [res]
    (ok if res else warn)(f"{len(res)} resource(s) declared")

    head("Trust")
    try:
        from trust.tiers import AgentTier, HumanTier, resolve, next_upgrade
        t = cfg.get("trust") or {}
        a = AgentTier[str(t.get("agent", "free")).upper()]
        h = HumanTier[str(t.get("human", "public")).upper()]
        tpl = resolve(a, h)
        ok(f"tier {tpl.cell} ({tpl.name}) — settlement: {tpl.settlement}, ttl {tpl.ttl_seconds//3600}h")
        up = next_upgrade(a, h)
        if up:
            info(f"upgrade: {up}")
    except Exception as e:
        warn(f"could not resolve tier: {e}")
    return 0


def cmd_tier(args: argparse.Namespace) -> int:
    from trust.tiers import (AgentTier, HumanTier, Entitlements, resolve,
                             next_upgrade, lattice_table)
    if args.table:
        head("The XCP trust lattice")
        print(f"  {'cell':<7} {'name':<21} {'ttl':>5}  {'settle':<8} {'cap':>9}  scopes")
        for row in lattice_table():
            cap = row["spend_cap_minor"]
            print(f"  {row['cell']:<7} {row['name']:<21} "
                  f"{row['ttl_seconds']//3600:>4}h  {row['settlement']:<8} "
                  f"{('none' if cap == 0 else str(cap)):>9}  {len(row['scopes'])} scope patterns")
        print("\n  ceiling = the weaker leg, except A2xH0 (the company is the principal).")
        return 0

    cfg = load_config() if not (args.agent and args.human) else {}
    t = cfg.get("trust") or {}
    a = AgentTier[(args.agent or t.get("agent", "free")).upper()]
    h = HumanTier[(args.human or t.get("human", "public")).upper()]
    ent = Entitlements(approval_limit_minor=args.limit) if args.limit is not None else None
    tpl = resolve(a, h, ent)

    head(f"Trust envelope — {tpl.cell} · {tpl.name}")
    info(f"agent      {a.label}")
    info(f"human      {h.label}")
    print()
    ok(f"session ttl      {tpl.ttl_seconds // 3600}h")
    ok(f"posture          {tpl.posture}")
    ok(f"settlement       {tpl.settlement}"
       + (f" (receipt required)" if tpl.requires_receipt else ""))
    ok(f"rails            {', '.join(tpl.rails_list()) or 'none'}")
    ok(f"spend cap        {'no protocol cap' if tpl.spend_cap_minor == 0 else tpl.spend_cap_minor}")
    ok(f"scopes           {', '.join(tpl.scopes)}")
    if tpl.notes:
        print()
        info(tpl.notes)
    up = next_upgrade(a, h)
    if up:
        print()
        print(f"  {_c('1', 'upgrade')} {up}")
    if args.json:
        print()
        print(tpl.to_json())
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    from discovery.ard import (Publisher, Resource, build_catalog, validate_catalog,
                               build_mcp_manifest, write_catalog, WELL_KNOWN_PATH)
    cfg = load_config()
    pub_cfg = cfg.get("publisher") or {}
    if not pub_cfg.get("domain"):
        bad("publisher.domain is required to publish (it is your identity anchor)")
        return 1
    publisher = Publisher(domain=pub_cfg["domain"], name=pub_cfg.get("name", pub_cfg["domain"]),
                          contact=pub_cfg.get("contact", ""))
    res_cfg = cfg.get("resource") or []
    if isinstance(res_cfg, dict):
        res_cfg = [res_cfg]
    if not res_cfg:
        bad("no [[resource]] entries in xcp.toml — nothing to publish")
        return 1

    tier = ""
    try:
        from trust.tiers import AgentTier, HumanTier, resolve
        t = cfg.get("trust") or {}
        tier = resolve(AgentTier[str(t.get("agent", "free")).upper()],
                       HumanTier[str(t.get("human", "public")).upper()]).cell
    except Exception:
        pass

    gw = (cfg.get("gateway") or {}).get("url", "")
    resources = []
    for rc in res_cfg:
        tools: list[dict] = []
        if args.introspect:
            tools = _introspect_tools(rc.get("endpoint", ""))
            info(f"introspected {len(tools)} tool(s) from {rc.get('name')}")
        resources.append(Resource(
            name=rc.get("name", "unnamed"), description=rc.get("description", ""),
            endpoint=rc.get("endpoint", ""), kind=rc.get("kind", "mcp-server"),
            tags=list(rc.get("tags") or []), tools=tools,
            trust_tier=tier, xcp_gateway=gw))

    cat = build_catalog(publisher, resources)
    problems = validate_catalog(cat)

    head("Catalog")
    outdir = Path(args.out)
    (outdir / ".well-known").mkdir(parents=True, exist_ok=True)
    cat_path = outdir / ".well-known" / "ai-catalog.json"
    write_catalog(cat, str(cat_path))
    ok(f"wrote {cat_path}")
    info(f"host it at  https://{publisher.domain}{WELL_KNOWN_PATH}")
    for r, res in zip(res_cfg, resources):
        man = build_mcp_manifest(publisher, res)
        mp = outdir / f"server-{res.name}.json"
        mp.write_text(json.dumps(man, indent=2) + "\n")
        ok(f"wrote {mp}  (MCP Registry manifest)")

    if problems:
        print()
        for p in problems:
            warn(p)
    else:
        ok("catalog passes local validation")
    print()
    info("ARD is a draft spec — validate against the published schema before you rely on it.")
    info("`/.well-known/*` must be served unauthenticated (RFC 8615).")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Probe an endpoint's XCP posture before trusting it."""
    url = args.url.rstrip("/")
    head(f"Probing {url}")
    health = _get_json(f"{url}/health")
    if health:
        ok(f"reachable — {json.dumps(health)[:120]}")
        if health.get("posture"):
            ok(f"posture: {health['posture']}")
        if health.get("requiresVerified"):
            ok("server requires gateway-verified identity")
    else:
        warn("no /health endpoint")
    anon = _post_json(f"{url}/v1/a2t/call", {"server": "x", "tool": "y", "arguments": {}})
    if anon is None:
        ok("anonymous call refused (or endpoint absent) — good")
    elif isinstance(anon, dict) and anon.get("error"):
        ok(f"anonymous call rejected: {str(anon['error'])[:70]}")
    else:
        bad("anonymous call was ACCEPTED — this endpoint is unauthenticated")
    cat = _get_json(f"{url}/.well-known/ai-catalog.json")
    if cat:
        ok(f"publishes an ARD catalog ({len(cat.get('entries', []))} entries)")
    else:
        info("no ARD catalog at /.well-known/ai-catalog.json")
    return 0


def cmd_certs(args: argparse.Namespace) -> int:
    script = REPO / "deploy" / "gen-certs.sh"
    if not script.exists():
        bad(f"missing {script}")
        return 1
    env = {**os.environ, "AGENT_ID": str(args.agent_id)}
    head("Generating local mTLS PKI")
    r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip())
    return r.returncode


def cmd_up(args: argparse.Namespace) -> int:
    cfg = load_config()
    gw = cfg.get("gateway") or {}
    ups = gw.get("upstreams") or {}
    if args.docker:
        head("Starting the stack with docker compose")
        return subprocess.run(["docker", "compose", "-f",
                               str(REPO / "deploy" / "docker-compose.yml"), "up", "--build"]).returncode
    head("Starting the stack")
    info("verifier :8500   gateway :8080   server :9001")
    info("stop with Ctrl-C")
    env = {**os.environ,
           "XCP_POSTURE": gw.get("posture", "enforce"),
           "XCP_UPSTREAMS": json.dumps(ups or {"research": "http://127.0.0.1:9001/mcp"}),
           "REQUIRE_VERIFIED": "1"}
    return subprocess.run([sys.executable, str(REPO / "examples" / "end_to_end.py")],
                          env=env).returncode



def cmd_receipt(args: argparse.Namespace) -> int:
    """Verify an evidence bundle — the third-party check anyone can run."""
    from receipts import verify_bundle
    path = Path(args.bundle)
    if not path.exists():
        bad(f"no such file: {path}")
        return 1
    try:
        bundle = json.loads(path.read_text())
    except Exception as e:
        bad(f"not valid JSON: {e}")
        return 1
    head(f"Verifying {path.name}")
    task = bundle.get("task", {})
    rec = bundle.get("receipt", {})
    chain = bundle.get("callChain", {})
    info(f"task        {task.get('task_id','?')} — {str(task.get('description',''))[:52]}")
    info(f"parties     payer {task.get('payer_agent')} → payee {task.get('payee_agent')}")
    info(f"amount      {task.get('amount_minor')} {task.get('currency','')} via {task.get('rail','')}")
    info(f"evidence    {chain.get('count', 0)} recorded call(s)")
    if bundle.get("outputRef"):
        info(f"output      {bundle['outputRef']}")
    print()
    problems = verify_bundle(bundle)
    if problems:
        for p in problems:
            bad(p)
        print()
        warn("this bundle does NOT verify — do not settle against it")
        return 2
    ok("task digest matches the receipt")
    ok("call chain is intact (no edits, reorders or deletions)")
    ok("payee signature recovers")
    if rec.get("acceptance_sig"):
        ok("payer acceptance signature recovers")
    else:
        info("not yet accepted by the payer")
    print()
    ok("bundle verifies")
    info("this proves the work was performed and the artifact is exactly this one.")
    info("it does NOT prove the output is good — that is still your call.")
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    """Inspect, search and refresh the discovery catalog."""
    from connectors import GlobalCatalog
    cat = GlobalCatalog()
    cat.load_curated()
    if not args.no_snapshot:
        cat.load_snapshot()
    if args.search:
        head(f"Search: {args.search}")
        rows = cat.search(args.search, limit=args.limit)
        if not rows:
            info("no matches")
        for r in rows:
            kind = "curated" if r.get("curated") else r.get("kind", "?")
            target = r.get("endpoint") or r.get("installRef") or ""
            print(f"  {r.get('id','')[:38]:<40} {kind:<12} {target[:52]}")
        return 0
    s = cat.stats()
    head("Catalog")
    ok(f"curated      {s['curated']:>6}   verified core, promotable")
    ok(f"discovered   {s['ingested']:>6}   harvested, unverified")
    print()
    info(f"routable     {s['routable']:>6}   remote endpoints an agent can reach now")
    info(f"installable  {s['ingestedByKind'].get('installable', 0):>6}   packages — routable once a node runs them")
    info(f"total        {s['total']:>6}")
    print()
    for k, v in s["curatedByStatus"].items():
        info(f"curated/{k:<12} {v}")
    print()
    info("refresh with: python scripts/build-snapshot.py --fetch")
    return 0


# ── small helpers ──────────────────────────────────────────────────────────

def _which(binary: str) -> bool:
    from shutil import which
    return which(binary) is not None


def _get_json(url: str, timeout: float = 5) -> Optional[dict]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _post_json(url: str, body: dict, timeout: float = 5) -> Optional[dict]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return {"error": f"HTTP {e.code}"}
    except Exception:
        return None


def _introspect_tools(endpoint: str) -> list[dict]:
    if not endpoint:
        return []
    res = _post_json(endpoint, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    if not res:
        return []
    return ((res.get("result") or {}).get("tools")) or []


# ── entry point ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xcp", description="Self-serve command line for XCP.")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="scaffold xcp.toml")
    i.add_argument("--name"); i.add_argument("--domain"); i.add_argument("--org")
    i.add_argument("--description"); i.add_argument("--force", action="store_true")
    i.set_defaults(fn=cmd_init)

    d = sub.add_parser("doctor", help="check environment and config")
    d.set_defaults(fn=cmd_doctor)

    t = sub.add_parser("tier", help="show the trust lattice / your envelope")
    t.add_argument("--agent", choices=["free", "registry", "company"])
    t.add_argument("--human", choices=["public", "general_sso", "enterprise"])
    t.add_argument("--limit", type=int, help="entitlement approval limit (minor units)")
    t.add_argument("--table", action="store_true", help="print the whole lattice")
    t.add_argument("--json", action="store_true")
    t.set_defaults(fn=cmd_tier)

    pub = sub.add_parser("publish", help="generate ARD catalog + MCP manifest")
    pub.add_argument("--out", default="dist", help="output directory (default: dist)")
    pub.add_argument("--introspect", action="store_true",
                     help="call tools/list on each endpoint to enrich the catalog")
    pub.set_defaults(fn=cmd_publish)

    v = sub.add_parser("verify", help="probe an endpoint's XCP posture")
    v.add_argument("url")
    v.set_defaults(fn=cmd_verify)

    c = sub.add_parser("certs", help="generate a local mTLS dev PKI")
    c.add_argument("--agent-id", type=int, default=42001)
    c.set_defaults(fn=cmd_certs)

    rc = sub.add_parser("receipt", help="verify a proof-of-delivery evidence bundle")
    rc.add_argument("bundle", help="path to an evidence bundle JSON file")
    rc.set_defaults(fn=cmd_receipt)

    cat = sub.add_parser("catalog", help="inspect and search the discovery catalog")
    cat.add_argument("--search", help="find connectors by name or tag")
    cat.add_argument("--limit", type=int, default=20)
    cat.add_argument("--no-snapshot", action="store_true",
                     help="curated entries only")
    cat.set_defaults(fn=cmd_catalog)

    u = sub.add_parser("up", help="run the stack locally")
    u.add_argument("--docker", action="store_true")
    u.set_defaults(fn=cmd_up)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
