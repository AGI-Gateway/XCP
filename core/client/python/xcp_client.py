"""
xcp_client — Python client for XCP (Multi-Model Secure Context Protocol).

A small, dependency-light client that implements the XCP session flow against
an XCP gateway:

  1. Load an agent identity (ERC-8004 agentId + signing key).
  2. Open a channel-bound mTLS session; the gateway binds the certificate
     footprint keccak256(DER(cert)) to the agent in the Session Registry.
  3. Call tools (A2T), delegate to peers (A2A), or chain tools (T2T), with a
     mandate proof attached to every governed action.

This module is transport-agnostic at its core: the HTTP/JSON transport used
here talks to the reference gateway in ../gateway. The same XCPSession object
can drive the gRPC streams once you generate stubs from proto/xcp_streams.proto.

Install:
    pip install httpx eth-account cryptography

Status: XCP / ERC-8004x are draft proposals. Pin to a released spec before
production use.
"""

from __future__ import annotations

import hashlib
import json
import ssl
import time
from dataclasses import dataclass, field
from enum import IntFlag
from pathlib import Path
from typing import Any, Optional

import httpx

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    _ETH = True
except ImportError:                       # crypto optional for dry-run/tests
    _ETH = False


# --------------------------------------------------------------------------
# Configuration + identity
# --------------------------------------------------------------------------

DEFAULT_CHAIN_ID = 8453                    # Base mainnet


class Rail(IntFlag):
    """railsBitmap bits (which payment rails a session may use)."""
    X402 = 1 << 0
    AP2  = 1 << 1
    MPP  = 1 << 2
    ACP  = 1 << 3


@dataclass
class AgentIdentity:
    """ERC-8004 identity material held by the agent."""
    agent_id: int
    chain_id: int = DEFAULT_CHAIN_ID
    private_key: Optional[str] = None      # 0x… secp256k1 key (sponsor/self)
    cert_path: Optional[str] = None        # PEM client cert for mTLS
    key_path: Optional[str] = None         # PEM private key for mTLS
    ca_path: Optional[str] = None          # CA bundle to verify the gateway

    @property
    def address(self) -> str:
        if _ETH and self.private_key:
            return Account.from_key(self.private_key).address
        return "0x0000000000000000000000000000000000000000"


@dataclass
class Mandate:
    """A signed, scoped, time-bounded authorization from a sponsor."""
    mandate_id: str
    delegator: str
    scope: list[str]
    not_after: int
    leaf: str = ""
    proof: list[str] = field(default_factory=list)
    signature: str = ""

    def to_header(self) -> str:
        return json.dumps({
            "mandateId": self.mandate_id, "delegator": self.delegator,
            "mandateScope": self.scope, "notAfter": self.not_after,
            "leaf": self.leaf, "proof": self.proof, "signature": self.signature,
        }, separators=(",", ":"))


def cert_footprint(cert_pem: bytes) -> str:
    """Compute keccak256(DER(cert)) — the session key used on-chain.

    Uses keccak if available (via eth-utils); falls back to sha3-256 so the
    module runs without the crypto stack for local testing.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(Encoding.DER)
    try:
        from eth_utils import keccak
        return "0x" + keccak(der).hex()
    except Exception:
        return "0x" + hashlib.sha3_256(der).hexdigest()


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------

@dataclass
class Session:
    """A live XCP session bound to a certificate footprint."""
    agent_id: int
    chain_id: int
    footprint: str
    session_id: str = ""
    mandate_root: str = ""
    rails: int = 0


class XCPError(Exception):
    """Raised on session or mandate failures reported by the gateway."""


class XCPClient:
    """
    XCP client. Opens a channel-bound session to a gateway and drives the
    three interaction types (A2T / A2A / T2T) over HTTP/JSON.

        id = AgentIdentity(agent_id=42001, private_key="0x…",
                           cert_path="client.crt", key_path="client.key",
                           ca_path="ca.crt")
        client = XCPClient("https://gateway.example.com", id)
        client.connect()
        result = client.call_tool("research", "fetch", {"url": "…"},
                                  mandate=my_mandate)
    """

    def __init__(self, gateway_url: str, identity: AgentIdentity,
                 verify_tls: bool = True) -> None:
        self.gateway_url = gateway_url.rstrip("/")
        self.identity = identity
        self.session: Optional[Session] = None
        self._verify_tls = verify_tls
        self._http = self._build_http_client()

    # ---- transport ----

    def _build_http_client(self) -> httpx.Client:
        verify: Any = self._verify_tls
        cert = None
        if self.identity.cert_path and self.identity.key_path:
            cert = (self.identity.cert_path, self.identity.key_path)
        if self.identity.ca_path:
            verify = self.identity.ca_path
        return httpx.Client(cert=cert, verify=verify, timeout=15,
                            http2=False)

    def _headers(self, mandate: Optional[Mandate] = None) -> dict[str, str]:
        if not self.session:
            raise XCPError("not connected — call connect() first")
        h = {
            "Content-Type": "application/json",
            "XCP-Agent-Identity": f"{self.session.agent_id};"
                                  f"{self.session.chain_id};"
                                  f"{self.session.footprint}",
        }
        if mandate:
            h["XCP-Mandate"] = mandate.to_header()
        return h

    # ---- session lifecycle ----

    def connect(self) -> Session:
        """Open a channel-bound session with the gateway."""
        footprint = self._local_footprint()
        body = {
            "agentId": self.identity.agent_id,
            "chainId": self.identity.chain_id,
            "footprint": footprint,
            "address": self.identity.address,
        }
        r = self._http.post(f"{self.gateway_url}/v1/session/open", json=body)
        if r.status_code != 200:
            raise XCPError(f"session open failed: {r.status_code} {r.text}")
        data = r.json()
        self.session = Session(
            agent_id=self.identity.agent_id, chain_id=self.identity.chain_id,
            footprint=footprint, session_id=data.get("sessionId", ""),
            mandate_root=data.get("mandateRoot", ""), rails=data.get("rails", 0))
        return self.session

    def _local_footprint(self) -> str:
        if self.identity.cert_path:
            return cert_footprint(Path(self.identity.cert_path).read_bytes())
        # dry-run footprint from agent id (tests without real certs)
        return "0x" + hashlib.sha3_256(
            f"agent:{self.identity.agent_id}".encode()).hexdigest()

    def close(self) -> None:
        if self.session:
            try:
                self._http.post(f"{self.gateway_url}/v1/session/close",
                                headers=self._headers())
            except Exception:
                pass
        self._http.close()
        self.session = None

    def __enter__(self) -> "XCPClient":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ---- A2T: agent -> tool ----

    def call_tool(self, server: str, tool: str, arguments: dict,
                  mandate: Optional[Mandate] = None) -> dict:
        """Call an MCP tool through the gateway (scope mcp:tools/<tool>)."""
        body = {"server": server, "tool": tool, "arguments": arguments}
        r = self._http.post(f"{self.gateway_url}/v1/a2t/call",
                            json=body, headers=self._headers(mandate))
        return self._handle(r)

    # ---- A2A: agent <-> agent ----

    def delegate(self, peer_did: str, task: dict,
                 mandate: Optional[Mandate] = None) -> dict:
        """Delegate a task to a peer agent (scope a2a:delegate/<peer>)."""
        body = {"peerDid": peer_did, "task": task}
        r = self._http.post(f"{self.gateway_url}/v1/a2a/delegate",
                            json=body, headers=self._headers(mandate))
        return self._handle(r)

    # ---- T2T: tool <-> tool ----

    def chain_tools(self, src: str, dst: str, payload: dict,
                    mandate: Optional[Mandate] = None) -> dict:
        """Chain one tool's output into another (scope t2t:chain/<src>-><dst>)."""
        body = {"src": src, "dst": dst, "payload": payload}
        r = self._http.post(f"{self.gateway_url}/v1/t2t/pipe",
                            json=body, headers=self._headers(mandate))
        return self._handle(r)

    # ---- helpers ----

    def _handle(self, r: httpx.Response) -> dict:
        if r.status_code == 401:
            raise XCPError(f"session rejected: {r.json().get('error')}")
        if r.status_code == 403:
            raise XCPError(f"mandate denied: {r.json().get('error')}")
        if r.status_code != 200:
            raise XCPError(f"gateway error {r.status_code}: {r.text}")
        return r.json()


# --------------------------------------------------------------------------
# Mandate signing (sponsor side)
# --------------------------------------------------------------------------

def sign_mandate(private_key: str, mandate_id: str, delegator: str,
                 scope: list[str], not_after: int,
                 chain_id: int = DEFAULT_CHAIN_ID) -> Mandate:
    """
    Produce a sponsor-signed mandate (EIP-712). The leaf is keccak of the
    canonical fields; for a single-mandate tree the root equals the leaf.
    """
    if not _ETH:
        raise RuntimeError("eth-account required to sign mandates")
    from eth_utils import keccak
    canonical = json.dumps({"mandateId": mandate_id, "delegator": delegator,
                            "scope": scope, "notAfter": not_after},
                           separators=(",", ":"), sort_keys=True).encode()
    leaf = "0x" + keccak(canonical).hex()
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
        "domain": {"name": "ERC8004x", "version": "1", "chainId": chain_id},
        "message": {"mandateId": mandate_id, "delegator": delegator,
                    "scope": json.dumps(scope), "notAfter": not_after},
    }
    sig = Account.sign_message(encode_typed_data(full_message=typed),
                               private_key=private_key).signature.hex()
    return Mandate(mandate_id=mandate_id, delegator=delegator, scope=scope,
                   not_after=not_after, leaf=leaf, proof=[],
                   signature="0x" + sig if not sig.startswith("0x") else sig)


__all__ = ["XCPClient", "AgentIdentity", "Mandate", "Session", "Rail",
           "XCPError", "cert_footprint", "sign_mandate"]
