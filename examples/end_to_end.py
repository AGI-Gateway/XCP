#!/usr/bin/env python3
"""
end_to_end.py — spin up the XCP server + gateway and drive them with the
Python client, demonstrating the full flow:

    client --mTLS/session--> gateway --verified identity--> MCP server
              |                  |
              |                  +-- verifySession + mandate gate
              +-- A2T / A2A / T2T with per-call mandate proofs

Run from the repo root:
    pip install fastapi "uvicorn[standard]" httpx eth-account eth-utils cryptography prometheus-client
    python examples/end_to_end.py

Expected output: a session opens, a granted tool call succeeds, an
out-of-scope call is denied, and A2A/T2T delegations enforce their scopes.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_server():
    os.environ["REQUIRE_VERIFIED"] = "1"
    os.environ["XCP_SERVER_NAME"] = "research"
    sys.path.insert(0, str(ROOT / "core" / "server"))
    import uvicorn, xcp_server
    uvicorn.run(xcp_server.app, host="127.0.0.1", port=9001, log_level="error")


def run_gateway():
    os.environ["XCP_POSTURE"] = "enforce"
    os.environ["XCP_UPSTREAMS"] = json.dumps({"research": "http://127.0.0.1:9001/mcp"})
    sys.path.insert(0, str(ROOT / "core" / "gateway"))
    import uvicorn, xcp_gateway
    uvicorn.run(xcp_gateway.app, host="127.0.0.1", port=8080, log_level="error")


def wait(url: str, tries: int = 40) -> bool:
    for _ in range(tries):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.5)
    return False


def main() -> int:
    multiprocessing.set_start_method("spawn", force=True)
    for fn in (run_server, run_gateway):
        multiprocessing.Process(target=fn, daemon=True).start()
    if not wait("http://127.0.0.1:8080/health"):
        print("gateway did not start")
        return 1

    sys.path.insert(0, str(ROOT / "core" / "client" / "python"))
    from xcp_client import XCPClient, AgentIdentity, sign_mandate

    # A well-known Anvil/Hardhat test key — do NOT use in production.
    key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    ident = AgentIdentity(agent_id=42001, chain_id=8453, private_key=key)

    print("\nXCP end-to-end demo")
    print("=" * 48)
    client = XCPClient("http://127.0.0.1:8080", ident)
    sess = client.connect()
    print(f"session opened   agent={sess.agent_id} "
          f"footprint={sess.footprint[:16]}… rails={sess.rails}")

    now = int(time.time())
    tool_mandate = sign_mandate(key, "m-tools", ident.address,
                                ["mcp:tools/echo", "mcp:tools/now"], now + 3600)

    r = client.call_tool("research", "echo", {"text": "hello xcp"},
                         mandate=tool_mandate)
    served = r.get("result", {}).get("_xcp", {})
    print(f"A2T echo         OK  served_for={served.get('servedFor')} "
          f"verified_by={served.get('verifiedBy')}")

    try:
        client.call_tool("research", "sum", {"numbers": [1, 2]},
                         mandate=tool_mandate)
        print("A2T sum          UNEXPECTED allow")
    except Exception as e:
        print(f"A2T sum          DENIED (out of scope) ✓")

    peer = "did:8004:8453:0xPEER"
    a2a_mandate = sign_mandate(key, "m-a2a", ident.address,
                               [f"a2a:delegate/{peer}"], now + 3600)
    r = client.delegate(peer, {"job": "summarize"}, mandate=a2a_mandate)
    print(f"A2A delegate     OK  accepted={r.get('accepted')} peer={peer}")

    t2t_mandate = sign_mandate(key, "m-t2t", ident.address,
                               ["t2t:chain/research.fetch->summarize.run"],
                               now + 3600)
    r = client.chain_tools("research.fetch", "summarize.run", {"data": "x"},
                           mandate=t2t_mandate)
    print(f"T2T chain        OK  {r.get('src')} -> {r.get('dst')}")

    client.close()
    print("=" * 48)
    print("done — every governed action was session-verified and scope-gated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
