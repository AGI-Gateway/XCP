"""
test_e2e.py — smoke test for the XCP client/server/gateway.

Spawns the reference server + gateway, drives them with the Python client, and
asserts the enforcement decisions. Runnable locally and in CI.

    pip install fastapi "uvicorn[standard]" httpx eth-account eth-utils cryptography prometheus-client pytest
    pytest tests/test_e2e.py -q      # or: python tests/test_e2e.py
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


def _run_server():
    os.environ["REQUIRE_VERIFIED"] = "1"
    os.environ["XCP_SERVER_NAME"] = "research"
    sys.path.insert(0, str(ROOT / "core" / "server"))
    import uvicorn, xcp_server
    uvicorn.run(xcp_server.app, host="127.0.0.1", port=9091, log_level="error")


def _run_gateway():
    os.environ["XCP_POSTURE"] = "enforce"
    os.environ["XCP_UPSTREAMS"] = json.dumps({"research": "http://127.0.0.1:9091/mcp"})
    sys.path.insert(0, str(ROOT / "core" / "gateway"))
    import uvicorn, xcp_gateway
    uvicorn.run(xcp_gateway.app, host="127.0.0.1", port=8090, log_level="error")


def _wait(url: str, tries: int = 40) -> bool:
    for _ in range(tries):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.5)
    return False


_STARTED = False


def _ensure_up():
    global _STARTED
    if _STARTED:
        return
    try:
        multiprocessing.set_start_method("spawn", force=True)
    except RuntimeError:
        pass
    for fn in (_run_server, _run_gateway):
        multiprocessing.Process(target=fn, daemon=True).start()
    assert _wait("http://127.0.0.1:8090/health"), "gateway did not start"
    _STARTED = True


def _client():
    sys.path.insert(0, str(ROOT / "core" / "client" / "python"))
    from xcp_client import XCPClient, AgentIdentity, sign_mandate
    key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    ident = AgentIdentity(agent_id=42001, chain_id=8453, private_key=key)
    c = XCPClient("http://127.0.0.1:8090", ident)
    c.connect()
    return c, ident, sign_mandate, key


def test_session_opens():
    _ensure_up()
    c, ident, _, _ = _client()
    assert c.session is not None
    assert c.session.agent_id == 42001
    assert c.session.footprint.startswith("0x")
    c.close()


def test_granted_tool_call_succeeds():
    _ensure_up()
    c, ident, sign_mandate, key = _client()
    m = sign_mandate(key, "m", ident.address, ["mcp:tools/echo"],
                     int(time.time()) + 3600)
    r = c.call_tool("research", "echo", {"text": "hi"}, mandate=m)
    assert r["result"]["_xcp"]["servedFor"] == "42001"
    c.close()


def test_out_of_scope_call_denied():
    _ensure_up()
    c, ident, sign_mandate, key = _client()
    m = sign_mandate(key, "m", ident.address, ["mcp:tools/echo"],
                     int(time.time()) + 3600)
    from xcp_client import XCPError
    denied = False
    try:
        c.call_tool("research", "sum", {"numbers": [1, 2]}, mandate=m)
    except XCPError:
        denied = True
    assert denied, "out-of-scope call should be denied"
    c.close()


def test_missing_mandate_denied():
    _ensure_up()
    c, ident, _, _ = _client()
    from xcp_client import XCPError
    denied = False
    try:
        c.call_tool("research", "echo", {"text": "x"})
    except XCPError:
        denied = True
    assert denied, "call without a mandate should be denied"
    c.close()


def test_a2a_and_t2t_scopes():
    _ensure_up()
    c, ident, sign_mandate, key = _client()
    peer = "did:8004:8453:0xPEER"
    a2a = sign_mandate(key, "a", ident.address, [f"a2a:delegate/{peer}"],
                       int(time.time()) + 3600)
    assert c.delegate(peer, {"j": 1}, mandate=a2a)["accepted"] is True
    t2t = sign_mandate(key, "t", ident.address,
                       ["t2t:chain/a.fetch->b.run"], int(time.time()) + 3600)
    assert c.chain_tools("a.fetch", "b.run", {"d": 1}, mandate=t2t)["chained"] is True
    c.close()


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS {name}")
                passed += 1
            except Exception as e:
                print(f"  FAIL {name}: {e}")
                failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
