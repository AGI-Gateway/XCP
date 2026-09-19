"""
Differential analysis: two implementations, identical inputs.

WHY THIS IS INDEPENDENT EVIDENCE
--------------------------------
The Python and Node gateways were written separately -- the second against the
draft rather than by porting the first. Where they DISAGREE about the same
bytes, at least one is wrong, and the disagreement is evidence no single
reviewer produced and no model's opinion was involved.

Where they agree, that is weaker: two implementations can share a
misunderstanding of an ambiguous specification. Agreement is consistent with a
spec defect, so it is reported as agreement and not as correctness.
"""
from __future__ import annotations
import json, os, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

PY_PORT, NODE_PORT = 8890, 8891
FP = "0x" + "ab" * 32


def _post(port, path, body, headers=None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


#: Inputs chosen where two independent parsers could plausibly differ.
CASES = [
    ("no identity",              {}),
    ("identity, no mandate",     {"XCP-Agent-Identity": f"42001;8453;{FP}"}),
    ("footprint uppercased",     {"XCP-Agent-Identity": f"42001;8453;{FP.upper()}"}),
    ("footprint 0X prefix",      {"XCP-Agent-Identity": f"42001;8453;0X{FP[2:]}"}),
    ("trailing space in part",   {"XCP-Agent-Identity": f"42001;8453;{FP} "}),
    ("leading space in agent",   {"XCP-Agent-Identity": f" 42001;8453;{FP}"}),
    ("four fields",              {"XCP-Agent-Identity": f"42001;8453;{FP};x"}),
    ("two fields",               {"XCP-Agent-Identity": "42001;8453"}),
    ("empty identity",           {"XCP-Agent-Identity": ""}),
    ("negative agent id",        {"XCP-Agent-Identity": f"-1;8453;{FP}"}),
    ("agent id with plus",       {"XCP-Agent-Identity": f"+42001;8453;{FP}"}),
    ("huge agent id",            {"XCP-Agent-Identity": f"{'9'*40};8453;{FP}"}),
    ("short footprint",          {"XCP-Agent-Identity": "42001;8453;0xab"}),
    ("mandate not json",         {"XCP-Agent-Identity": f"42001;8453;{FP}",
                                  "XCP-Mandate": "not-json"}),
    ("mandate null scope",       {"XCP-Agent-Identity": f"42001;8453;{FP}",
                                  "XCP-Mandate": json.dumps(
                                      {"mandateScope": None,
                                       "notAfter": int(time.time()) + 3600})}),
    ("mandate scope not list",   {"XCP-Agent-Identity": f"42001;8453;{FP}",
                                  "XCP-Mandate": json.dumps(
                                      {"mandateScope": "mcp:tools/echo",
                                       "notAfter": int(time.time()) + 3600})}),
    ("mandate no notAfter",      {"XCP-Agent-Identity": f"42001;8453;{FP}",
                                  "XCP-Mandate": json.dumps(
                                      {"mandateScope": ["mcp:tools/echo"]})}),
    ("bare wildcard scope",      {"XCP-Agent-Identity": f"42001;8453;{FP}",
                                  "XCP-Mandate": json.dumps(
                                      {"mandateScope": ["*"],
                                       "notAfter": int(time.time()) + 3600})}),
    ("prefix wildcard",          {"XCP-Agent-Identity": f"42001;8453;{FP}",
                                  "XCP-Mandate": json.dumps(
                                      {"mandateScope": ["mcp:tools/*"],
                                       "notAfter": int(time.time()) + 3600})}),
    ("notAfter as string",       {"XCP-Agent-Identity": f"42001;8453;{FP}",
                                  "XCP-Mandate": json.dumps(
                                      {"mandateScope": ["mcp:tools/echo"],
                                       "notAfter": str(int(time.time()) + 3600)})}),
    ("no common version",        {"XCP-Agent-Identity": f"42001;8453;{FP}",
                                  "XCP-Accept-Versions": "9.9"}),
]


def main() -> int:
    env_py = {**os.environ, "XCP_POSTURE": "enforce", "XCP_RATE_LIMIT": "0",
              "XCP_UPSTREAMS": '{"research":"http://127.0.0.1:9999/mcp"}'}
    py = subprocess.Popen([sys.executable, "-m", "uvicorn",
                           "core.gateway.xcp_gateway:app", "--port", str(PY_PORT),
                           "--log-level", "error"],
                          env=env_py, cwd=str(ROOT),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env_node = {**os.environ, "XCP_PORT": str(NODE_PORT), "XCP_POSTURE": "enforce",
                "XCP_RATE_LIMIT": "0",
                "XCP_UPSTREAMS": '{"research":"http://127.0.0.1:9999/mcp"}'}
    nd = subprocess.Popen(["node", "core/gateway-ts/gateway.mjs"], env=env_node,
                          cwd=str(ROOT),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for port in (PY_PORT, NODE_PORT):
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
                break
            except Exception:
                time.sleep(0.4)

    for port in (PY_PORT, NODE_PORT):
        _post(port, "/v1/session/open",
              {"agentId": 42001, "chainId": 8453, "footprint": FP, "tier": "A2xH2"})

    body = {"server": "research", "tool": "echo", "arguments": {}}
    divergences = []
    print(f"  {'case':<26}{'python':>8}{'node':>8}")
    for name, hdrs in CASES:
        a = _post(PY_PORT, "/v1/a2t/call", body, hdrs)
        b = _post(NODE_PORT, "/v1/a2t/call", body, hdrs)
        flag = "" if a == b else "   <-- DIVERGENT"
        if a != b:
            divergences.append((name, a, b))
        print(f"  {name:<26}{a:>8}{b:>8}{flag}")

    py.terminate(); nd.terminate()
    print(f"\n  {len(CASES) - len(divergences)}/{len(CASES)} agree, "
          f"{len(divergences)} divergent")
    if divergences:
        print("\n  Divergences are defects in at least one implementation, and")
        print("  possibly in the specification that failed to disambiguate them:")
        for n, a, b in divergences:
            print(f"    {n}: python={a} node={b}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
