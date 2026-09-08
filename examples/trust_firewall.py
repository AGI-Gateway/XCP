#!/usr/bin/env python3
"""
trust_firewall.py — consuming the whole MCP corpus, safely, statelessly.

MCP 2026-07-28 removed protocol sessions and made `Mcp-Method` / `Mcp-Name`
mandatory. This demo shows what that changes for XCP:

  1. identity moves from a session to a per-request, call-bound credential
  2. authorization is decided from headers, without parsing the body
  3. the whole corpus stays reachable — the *terms* vary by trust class

    python examples/trust_firewall.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from trustfirewall import (TrustFirewall, ServerClass, Effect, mint, verify,
                           scope_for, corpus_matrix, new_flow,
                           H_MCP_METHOD, H_MCP_NAME, H_XCP_CREDENTIAL,
                           MCP_SPEC_TARGET)

KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
FP = "0x" + "ab" * 32


def rule(t: str) -> None:
    print(f"\n\033[1m{t}\033[0m\n{'─' * max(len(t), 66)}")


def line(a: str, b: str = "") -> None:
    print(f"  {a:<34} {b}")


def headers(cred, method, name=""):
    return {H_MCP_METHOD: method, H_MCP_NAME: name,
            H_XCP_CREDENTIAL: cred.to_header()}


def main() -> int:
    print(f"\nXCP Trust Firewall — targeting MCP {MCP_SPEC_TARGET}")
    print("=" * 66)

    # ── 1. headers → scope, no body parsing ──
    rule("1 · the two mandatory headers decide the scope")
    for m, n in [("tools/call", "search"), ("tools/list", ""),
                 ("resources/read", "file://x"), ("tools/call", "transfer_funds")]:
        line(f"Mcp-Method: {m}" + (f" · Mcp-Name: {n}" if n else ""),
             "→ " + scope_for(m, n))
    line("", "")
    line("body parsed?", "no — this runs at edge/WAF speed")

    # ── 2. the credential replaces the session ──
    rule("2 · a per-request credential replaces Mcp-Session-Id")
    body = b'{"q":"filings"}'
    cred = mint(KEY, agent_id=42001, chain_id=8453, footprint=FP, tier="A2xH2",
                mcp_method="tools/call", mcp_name="search", body=body,
                ttl_seconds=60, spend_cap_minor=25_000)
    line("bound to", f"{cred.scope} · args digest · footprint")
    line("lifetime", f"{cred.exp - int(time.time())}s (seconds, not days)")
    line("verifies statelessly", str(verify(cred, mcp_method="tools/call",
                                            mcp_name="search", body=body) == []))
    line("wire size", f"{len(cred.to_header())} bytes in one header")

    rule("3 · replay is structurally impossible")
    for label, m, n, b in [
        ("same credential, other tool", "tools/call", "transfer_funds", body),
        ("same credential, other args", "tools/call", "search", b'{"q":"x"}'),
        ("after expiry", "tools/call", "search", body),
    ]:
        now = int(time.time()) + 3600 if label == "after expiry" else None
        problems = verify(cred, mcp_method=m, mcp_name=n, body=b, now=now)
        line(label, f"REFUSED — {problems[0][:42]}" if problems else "ALLOWED (!)")

    # ── 4. graded reachability across the corpus ──
    rule("4 · the whole corpus is reachable; the terms vary")
    fw = TrustFirewall(posture="enforce")
    fw.load_lattice()
    fw.classify_many({
        "scraped-from-censys.example": ServerClass.UNKNOWN,
        "probed.example": ServerClass.PROBED,
        "attested.example": ServerClass.ATTESTED,
        "partner.acme.example": ServerClass.CONTRACTED,
    })

    print(f"  {'server class':<14} {'read':<26} {'write'}")
    for host, klass in [("scraped-from-censys.example", "unknown"),
                        ("probed.example", "probed"),
                        ("attested.example", "attested"),
                        ("partner.acme.example", "contracted")]:
        cells = []
        for method, name, b in [("tools/list", "", b""), ("tools/call", "write_row", b"{}")]:
            c = mint(KEY, agent_id=42001, chain_id=8453, footprint=FP, tier="A2xH2",
                     mcp_method=method, mcp_name=name, body=b, ttl_seconds=60)
            d = fw.decide(headers(c, method, name), b, server_host=host)
            tag = d.effect.name.lower()
            extra = f" · {d.settlement}" if d.settlement != "none" else ""
            cells.append(f"{tag}{extra}")
        line(f"{klass:<14}{cells[0]:<26}", cells[1])

    print()
    line("unvetted servers", "reachable in observe — sandboxed, output quarantined")
    line("nothing binding", "against a server nobody has vetted")
    line("money moves only", "toward an attested or contracted counterparty")

    # ── 5. obligations travel with the decision ──
    rule("5 · obligations inherited from the counterparty")
    c = mint(KEY, agent_id=42001, chain_id=8453, footprint=FP, tier="A2xH2",
             mcp_method="tools/list", mcp_name="", body=b"", ttl_seconds=60)
    d = fw.decide(headers(c, "tools/list", ""), b"",
                  server_host="scraped-from-censys.example")
    for k, v in d.obligations.to_dict().items():
        line(f"  {k}", str(v))
    line("audit trail", " → ".join(d.checks))

    # ── 6. a free-tier agent meets the same corpus ──
    rule("6 · the same corpus, seen by a free-tier agent")
    c0 = mint(KEY, agent_id=9, chain_id=8453, footprint=FP, tier="A0xH0",
              mcp_method="tools/call", mcp_name="write_row", body=b"{}", ttl_seconds=60)
    d0 = fw.decide(headers(c0, "tools/call", "write_row"), b"{}",
                   server_host="partner.acme.example")
    line("A0 write to contracted server", f"{d0.effect.name.lower()} — {d0.reason[:44]}")
    c0r = mint(KEY, agent_id=9, chain_id=8453, footprint=FP, tier="A0xH0",
               mcp_method="tools/list", mcp_name="", body=b"", ttl_seconds=60)
    d0r = fw.decide(headers(c0r, "tools/list", ""), b"",
                    server_host="partner.acme.example")
    line("A0 read from same server", d0r.effect.name.lower())

    # ── 7. MRTR ──
    rule(f"7 · MRTR — one logical call, several round trips")
    flow = new_flow()
    line("flow id", flow)
    line("round trip 1", "input_required → server asks 'delete this row?'")
    line("round trip 2", "client retries with the answer, new credential, same flow")
    line("audit records", "one logical call with 2 round trips, not 2 calls")

    print("\n" + "=" * 66)
    print("Statelessness didn't break the trust layer — it removed the part")
    print("that needed stickiness. The credential IS the state, and it is")
    print("bound to one call, so it is worth less to steal than a session id.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
