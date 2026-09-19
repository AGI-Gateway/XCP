"""
bench.micro — what each protocol primitive actually costs.

The claim under test is "verify identity and authority on every call". These are
the operations that claim is made of, measured individually so an implementer
can see which ones dominate and where an optimisation would pay.
"""
from __future__ import annotations

import json, os, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.harness import measure, table, Sample

KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
FP = "0x" + "ab" * 32


def run() -> list[Sample]:
    out: list[Sample] = []

    # ── hashing: the floor everything else sits on ──
    from receipts.receipt import digest, canonical
    payload = {"tool": "search", "arguments": {"q": "x" * 200}}
    out.append(measure("keccak256 (small payload)",
                       lambda: digest(canonical(payload)), n=5000))

    # ── stateless request credential: minted and verified per call ──
    from trustfirewall.stateless import mint, verify, scope_for, bind_digest
    body = json.dumps(payload).encode()
    out.append(measure("scope_for (headers only, no body parse)",
                       lambda: scope_for("tools/call", "search"), n=20000,
                       note="the header-speed authorization path"))
    out.append(measure("bind_digest (call binding)",
                       lambda: bind_digest("tools/call", "search", body), n=5000))
    cred = mint(KEY, agent_id=42001, chain_id=8453, footprint=FP, tier="A2xH2",
                mcp_method="tools/call", mcp_name="search", body=body)
    out.append(measure("credential mint (EIP-712 sign)",
                       lambda: mint(KEY, agent_id=42001, chain_id=8453,
                                    footprint=FP, tier="A2xH2",
                                    mcp_method="tools/call", mcp_name="search",
                                    body=body), n=300,
                       note="client-side, once per call"))
    out.append(measure("credential verify (signature recover)",
                       lambda: verify(cred, mcp_method="tools/call",
                                      mcp_name="search", body=body), n=300,
                       note="gateway-side, once per call — the dominant cost"))
    wire = cred.to_header()
    from trustfirewall.stateless import RequestCredential
    out.append(measure("credential parse from header",
                       lambda: RequestCredential.from_header(wire), n=5000))

    # ── the lattice and the firewall ──
    from trust.tiers import resolve, AgentTier, HumanTier
    out.append(measure("trust lattice resolve",
                       lambda: resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE),
                       n=20000))
    from trustfirewall import TrustFirewall, ServerClass
    fw = TrustFirewall(posture="enforce"); fw.load_lattice()
    fw.classify("api.example", ServerClass.CONTRACTED)
    hdrs = {"mcp-method": "tools/call", "mcp-name": "search",
            "xcp-request-credential": wire}
    out.append(measure("trust firewall decide (full)",
                       lambda: fw.decide(hdrs, body, server_host="api.example"),
                       n=300, note="includes credential verification"))

    # ── abuse controls: on the hot path of every request ──
    from trustfirewall.limits import RateLimiter
    lim = RateLimiter(global_rate_per_min=10**9, global_burst=10**9)
    out.append(measure("rate limiter check",
                       lambda: lim.check(agent_key="a", tier="A2xH2",
                                         method="tools/call"), n=20000,
                       note="runs on every request, pre- and post-auth"))

    # ── receipts and settlement ──
    from receipts import CallChain, TaskSpec, build_receipt, sign_receipt
    chain = CallChain()
    for i in range(50):
        chain.record(2002, "mcp:tools/x", "x", {"i": i}, {"r": i})
    out.append(measure("call chain append",
                       lambda: chain.record(2002, "mcp:tools/x", "x",
                                            {"i": 1}, {"r": 1}), n=3000,
                       note="O(1) per call — rides on existing audit"))
    verify_chain = CallChain([r for r in chain.records[:50]])
    out.append(measure("call chain verify (50 records)",
                       lambda: verify_chain.verify(), n=500))
    task = TaskSpec(task_id="t", payer_agent=1, payee_agent=2,
                    description="d", amount_minor=100, rail="x402",
                    deadline=int(time.time()) + 3600)
    out.append(measure("receipt build + sign",
                       lambda: sign_receipt(KEY, build_receipt(
                           task, verify_chain, {"out": 1})), n=200))

    # ── transport commitments ──
    from federation.transport import merkle_root, merkle_proof, verify_proof
    leaves = [f"0x{i:064x}" for i in range(1000)]
    out.append(measure("merkle root (1000 receipts)",
                       lambda: merkle_root(leaves), n=50, unit="ms",
                       note="once per epoch, not per call"))
    proof = merkle_proof(leaves, leaves[500])
    out.append(measure("merkle proof verify",
                       lambda: verify_proof(leaves[500], proof,
                                            merkle_root(leaves)), n=50,
                       unit="ms", note="only on a challenge"))

    # ── sealed credentials ──
    try:
        from vault.sealed import generate_recipient_key, seal, unseal
        priv, pub = generate_recipient_key()
        blob = seal("sk_live_secret", pub, context="tools/call:x")
        out.append(measure("sealed credential seal (X25519+AESGCM)",
                           lambda: seal("sk_live_secret", pub,
                                        context="tools/call:x"), n=500))
        out.append(measure("sealed credential unseal",
                           lambda: unseal(blob, priv, pub,
                                          context="tools/call:x"), n=500,
                           note="per call, only for hosted wrappers"))
    except Exception as e:
        print(f"  (sealed credentials skipped: {e})")

    # ── node identity ──
    from federation.identity import NodeIdentity, sign_binding, verify_binding
    ident = NodeIdentity.generate()
    b = sign_binding(ident, FP, domain="a.example", sequence=1)
    out.append(measure("cert binding verify",
                       lambda: verify_binding(b, expected_node_id=ident.node_id,
                                              tls_footprint=FP), n=300,
                       note="once per peer fetch, not per call"))

    # ── privacy ──
    from privacy import KeyRing, seal as pseal
    ring = KeyRing()
    out.append(measure("crypto-shred seal (per record)",
                       lambda: pseal(ring, "sub_a", payload), n=2000,
                       note="only if personal data is recorded"))
    return out


if __name__ == "__main__":
    samples = run()
    print(table(samples, "Protocol primitives"))
    Path("/tmp/bench-micro.json").write_text(
        json.dumps([s.to_dict() for s in samples], indent=2))
