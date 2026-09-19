"""
xcp_verifier.py — XCP Verifier Service (Python 3.11+)
=====================================================
The real session/mandate verifier the XCP wrapper calls when you set
XCP_VERIFY_URL. It replaces the wrapper's accept-any stub with the four
ERC-8004x checks, backed by an on-chain read against the Session Registry.

  wrapper ──POST /verify {footprint}──▶ verifier ──verifySession()──▶ chain
          ◀──{valid,agentId,mandateRoot,railsBitmap,revoked}──┘
  wrapper ──POST /mandate {root,proof,scope}──▶ verifier (Merkle + EIP-712)

Endpoints:
  POST /verify    body {footprint}                  -> session binding
  POST /mandate   body {mandateRoot, proof, scope}   -> {ok, reason}
  GET  /revoked/{session_id}                         -> {revoked}
  POST /admin/revoke/{session_id}                    -> push revocation
  GET  /health

What's real here vs. still-stubbed:
  - REAL: the verification *logic* — footprint→binding lookup, mandate Merkle
    inclusion, EIP-712 signature recovery, scope coverage, expiry, revocation,
    short-TTL caching with on-chain invalidation hooks.
  - PLUGGABLE: the chain read. Set CHAIN_RPC + SESSION_REGISTRY to use a real
    web3 provider; otherwise an in-memory registry stands in (seed it via
    /admin/bind for local + CI testing). This keeps the service runnable
    offline while being a drop-in for production by changing two env vars.

Dependencies:
    pip install fastapi "uvicorn[standard]"
    pip install eth-account eth-utils   # EIP-712 recovery + keccak (recommended)
    pip install web3                     # only if using a real CHAIN_RPC

Run:
    uvicorn xcp_verifier:app --host 0.0.0.0 --port 8500
    # then point the wrapper at it:
    XCP_VERIFY_URL=http://localhost:8500 UPSTREAM_URL=... uvicorn xcp_wrap:app

NOTE: ERC-8004x / XCP are draft proposals. The Session Registry ABI used
below matches the ISessionRegistry interface in the fork proposal; verify
against the deployed contract before production.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

# ── optional crypto deps (graceful fallback so the service runs without them) ─
try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_utils import keccak as _keccak
    _ETH = True
except ImportError:
    _ETH = False

    def _keccak(data: bytes) -> bytes:           # sha3-256 fallback (dev only)
        return hashlib.sha3_256(data).digest()


CHAIN_ID = int(os.getenv("CHAIN_ID", "8453"))
CHAIN_RPC = os.getenv("CHAIN_RPC", "")            # e.g. https://sepolia.base.org
SESSION_REGISTRY = os.getenv("SESSION_REGISTRY", "")  # 0x... contract address
CACHE_TTL = int(os.getenv("XCP_CACHE_TTL", "30"))  # seconds (~block time)
ABI_PATH = os.getenv("SESSION_REGISTRY_ABI",
                     str(__import__("pathlib").Path(__file__).resolve().parent.parent
                         / "contracts" / "SessionRegistry.abi.json"))

app = FastAPI(title="XCP Verifier", version="0.1.0-draft")


def _load_abi() -> list:
    """Load the Session Registry ABI from the contract artifact."""
    try:
        return json.loads(__import__("pathlib").Path(ABI_PATH).read_text())["abi"]
    except Exception:
        return SESSION_REGISTRY_ABI_FALLBACK


# ==========================================================================
# Session Registry binding (on-chain read, with in-memory fallback)
# ==========================================================================

@dataclass
class Binding:
    valid: bool
    agent_id: int
    mandate_root: str
    rails_bitmap: int
    not_after: int
    revoked: bool = False

    def to_json(self) -> dict:
        return {"valid": self.valid and not self.revoked
                and self.not_after > int(time.time()),
                "agentId": self.agent_id, "mandateRoot": self.mandate_root,
                "railsBitmap": self.rails_bitmap, "revoked": self.revoked}


# ISessionRegistry.verifySession ABI fallback (used only if the artifact file
# is missing; the canonical ABI lives in contracts/SessionRegistry.abi.json).
SESSION_REGISTRY_ABI_FALLBACK = [{
    "name": "verifySession", "type": "function", "stateMutability": "view",
    "inputs": [{"name": "certFootprint", "type": "bytes32"}],
    "outputs": [
        {"name": "valid", "type": "bool"},
        {"name": "agentId", "type": "uint256"},
        {"name": "mandateRoot", "type": "bytes32"},
        {"name": "railsBitmap", "type": "bytes32"},
    ],
}]


class Registry:
    """
    Reads session bindings. Uses web3 against SESSION_REGISTRY if CHAIN_RPC is
    set; otherwise an in-memory store seeded via /admin/bind (local + CI).
    """

    def __init__(self) -> None:
        self._mem: dict[str, Binding] = {}
        self._revoked: set[str] = set()        # session_ids revoked at runtime
        self._w3 = None
        self._contract = None
        if CHAIN_RPC and SESSION_REGISTRY:
            try:
                from web3 import Web3
                if CHAIN_RPC == "eth-tester":         # in-process EVM for tests
                    from web3 import EthereumTesterProvider
                    self._w3 = Web3(EthereumTesterProvider())
                else:
                    self._w3 = Web3(Web3.HTTPProvider(CHAIN_RPC))
                self._contract = self._w3.eth.contract(
                    address=Web3.to_checksum_address(SESSION_REGISTRY),
                    abi=_load_abi())
                print(f"[verifier] on-chain mode: {SESSION_REGISTRY} via {CHAIN_RPC}")
            except Exception as e:                # fall back to memory
                print(f"[verifier] web3 init failed ({e}); in-memory mode")
        else:
            print("[verifier] in-memory mode (set CHAIN_RPC + SESSION_REGISTRY "
                  "for on-chain)")

    def attach_web3(self, w3, address: str) -> None:
        """Inject a web3 instance + deployed address (used by the chain test)."""
        self._w3 = w3
        self._contract = w3.eth.contract(
            address=w3.to_checksum_address(address), abi=_load_abi())
        print(f"[verifier] on-chain mode (injected): {address}")

    def verify_session(self, footprint: str) -> Optional[Binding]:
        if self._contract is not None:
            try:
                fp = bytes.fromhex(footprint[2:] if footprint.startswith("0x")
                                   else footprint)
                fp = fp.rjust(32, b"\x00")[:32]       # pad/truncate to bytes32
                valid, agent_id, root, rails = \
                    self._contract.functions.verifySession(fp).call()
                return Binding(
                    valid=valid, agent_id=int(agent_id),
                    mandate_root="0x" + bytes(root).hex(),
                    rails_bitmap=int.from_bytes(bytes(rails), "big"),
                    not_after=int(time.time()) + CACHE_TTL,
                    revoked=not valid)
            except Exception as e:
                print(f"[verifier] chain read failed: {e}")
                return None
        # in-memory
        b = self._mem.get(footprint)
        if b and footprint in self._revoked:
            b.revoked = True
        return b

    def bind(self, footprint: str, agent_id: int, mandate_root: str,
             rails: int, ttl: int) -> Binding:
        b = Binding(valid=True, agent_id=agent_id, mandate_root=mandate_root,
                    rails_bitmap=rails, not_after=int(time.time()) + ttl)
        self._mem[footprint] = b
        return b

    def revoke(self, footprint: str) -> None:
        self._revoked.add(footprint)
        if footprint in self._mem:
            self._mem[footprint].revoked = True


registry = Registry()


# ── short-TTL cache with explicit invalidation ───────────────────────────
_cache: dict[str, tuple[float, Binding]] = {}


def cached_verify(footprint: str) -> Optional[Binding]:
    now = time.time()
    if footprint in _cache:
        exp, b = _cache[footprint]
        if exp > now and not b.revoked:
            return b
    b = registry.verify_session(footprint)
    if b:
        _cache[footprint] = (now + CACHE_TTL, b)
    return b


def invalidate(footprint: str) -> None:
    _cache.pop(footprint, None)


# ==========================================================================
# Mandate verification (Merkle inclusion + EIP-712 sponsor signature)
# ==========================================================================

def _scope_covers(granted: str, requested: str) -> bool:
    """A granted scope like 'mcp:tools/research.*' covers 'mcp:tools/research.fetch'."""
    if granted.endswith("*"):
        return requested.startswith(granted[:-1])
    return granted == requested


def verify_merkle(leaf_hex: str, proof: list[str], root_hex: str) -> bool:
    """Standard sorted-pair Merkle inclusion check."""
    try:
        node = bytes.fromhex(leaf_hex[2:] if leaf_hex.startswith("0x") else leaf_hex)
        for sib_hex in proof:
            sib = bytes.fromhex(sib_hex[2:] if sib_hex.startswith("0x") else sib_hex)
            node = _keccak(node + sib if node <= sib else sib + node)
        root = bytes.fromhex(root_hex[2:] if root_hex.startswith("0x") else root_hex)
        return node == root
    except Exception:
        return False


def verify_sponsor_sig(mandate: dict, signature: str) -> Optional[str]:
    """
    Recover the EIP-712 signer of a mandate. Returns the signer address or None.
    Matches the Mandate typed-data in the client templates' sponsor_sign_mandate.
    """
    if not _ETH:
        return "0xUNVERIFIED_NO_ETH_LIB"        # dev fallback
    typed = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "Mandate": [
                {"name": "mandateId", "type": "string"},
                {"name": "delegator", "type": "string"},
                {"name": "scope", "type": "string"},
                {"name": "notAfter", "type": "uint64"},
            ],
        },
        "primaryType": "Mandate",
        "domain": {"name": "ERC8004x", "version": "1", "chainId": CHAIN_ID},
        "message": {
            "mandateId": mandate.get("mandateId", ""),
            "delegator": mandate.get("delegator", ""),
            "scope": json.dumps(mandate.get("scope", [])),
            "notAfter": int(mandate.get("notAfter", 0)),
        },
    }
    try:
        return Account.recover_message(encode_typed_data(full_message=typed),
                                       signature=signature)
    except Exception:
        return None


# ==========================================================================
# Endpoints
# ==========================================================================

@app.post("/verify")
async def verify(request: Request) -> JSONResponse:
    """Session check the wrapper calls on every request."""
    body = await request.json()
    footprint = body.get("footprint", "")
    if not footprint:
        return JSONResponse({"valid": False, "reason": "no footprint"},
                            status_code=400)
    b = cached_verify(footprint)
    if not b:
        return JSONResponse({"valid": False, "reason": "no on-chain binding"})
    return JSONResponse(b.to_json())


@app.post("/mandate")
async def mandate(request: Request) -> JSONResponse:
    """
    Mandate gate the wrapper calls before a tool/agent/rail action.
    body: {mandateRoot, scope, proof:{mandateId, leaf, proof[], signature,
           delegator, mandateScope[], notAfter}}
    """
    body = await request.json()
    root = body.get("mandateRoot", "")
    scope = body.get("scope", "")
    proof = body.get("proof", {})
    if not proof or "leaf" not in proof:
        return JSONResponse({"ok": False, "reason": "no mandate proof"})

    # 1. expiry
    if int(proof.get("notAfter", 0)) and int(proof["notAfter"]) < int(time.time()):
        return JSONResponse({"ok": False, "reason": "mandate expired"})

    # 2. Merkle inclusion against the session's on-chain mandateRoot
    if root and proof.get("proof") is not None:
        if not verify_merkle(proof["leaf"], proof.get("proof", []), root):
            return JSONResponse({"ok": False, "reason": "merkle inclusion failed"})

    # 3. sponsor EIP-712 signature
    sig = proof.get("signature", "")
    signer = verify_sponsor_sig({
        "mandateId": proof.get("mandateId", ""),
        "delegator": proof.get("delegator", ""),
        "scope": proof.get("mandateScope", []),
        "notAfter": proof.get("notAfter", 0),
    }, sig) if sig else None
    if sig and signer is None:
        return JSONResponse({"ok": False, "reason": "bad sponsor signature"})

    # 4. scope coverage
    granted_scopes = proof.get("mandateScope", [])
    if scope and granted_scopes:
        if not any(_scope_covers(g, scope) for g in granted_scopes):
            return JSONResponse({"ok": False,
                                 "reason": f"scope {scope} not granted"})

    return JSONResponse({"ok": True, "signer": signer})


@app.get("/revoked/{session_id}")
async def is_revoked(session_id: str) -> dict:
    return {"sessionId": session_id, "revoked": session_id in registry._revoked}


@app.post("/admin/revoke/{footprint}")
async def admin_revoke(footprint: str, request: Request) -> dict:
    """Guardian/agent kill switch — revoke a session by footprint."""
    registry.revoke(footprint)
    invalidate(footprint)
    return {"revoked": footprint}


@app.post("/admin/bind")
async def admin_bind(request: Request) -> dict:
    """
    Seed an in-memory binding (local + CI only; no-op semantics in on-chain
    mode where bindings come from the contract). Lets tests run without a chain.
    """
    b = await request.json()
    binding = registry.bind(
        footprint=b["footprint"], agent_id=int(b.get("agentId", 42001)),
        mandate_root=b.get("mandateRoot", "0x" + "00" * 32),
        rails=int(b.get("railsBitmap", 0b0011)),
        ttl=int(b.get("ttl", 86400)))
    invalidate(b["footprint"])
    return {"bound": b["footprint"], "binding": binding.to_json()}


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "mode": "on-chain" if registry._contract else "in-memory",
            "eth_crypto": _ETH, "chain_id": CHAIN_ID}
