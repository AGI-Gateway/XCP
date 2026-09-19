"""
xcpsec.supplychain — tool/artifact provenance and pinning (MCP04).

Supply-chain attacks in MCP take the form of rug pulls (a trusted tool changes
its behavior after adoption), schema poisoning (a tool's declared interface is
altered to mislead the model), tool shadowing (a fake tool impersonates a real
one), and tampered dependencies. The defense is provenance: pin what you trust
by cryptographic digest and refuse anything whose digest or signature doesn't
match what was approved.

This module provides:

  1. A canonical **tool manifest** — the exact declared surface of a server's
     tools (names, descriptions, input schemas) hashed into a single digest.
  2. **Digest pinning** — verify a live server's manifest against an approved
     digest, so a rug pull or schema change is detected as a mismatch.
  3. **Signature verification** — a publisher signs the manifest (EIP-712); the
     signer must be in an allowlist of trusted publishers.
  4. **On-chain anchoring** — the manifest digest can be committed as (or into)
     the session's mandate root, so approval is enforced by the same gate that
     authorizes actions. This is what connects supply-chain trust to XCP's
     existing on-chain governance.

Standard library + optional eth-account for signatures. Status: XCP / ERC-8004x
are draft proposals.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_utils import keccak
    _ETH = True
except ImportError:
    _ETH = False


def _digest(data: bytes) -> str:
    if _ETH:
        return "0x" + keccak(data).hex()
    return "0x" + hashlib.sha3_256(data).hexdigest()


def canonical_manifest(tools: list[dict[str, Any]]) -> bytes:
    """
    Produce the canonical byte representation of a tool set. Two servers with the
    same declared tools produce identical bytes; any change to a name,
    description, or input schema changes them.
    """
    normalized = sorted(
        ({"name": t.get("name", ""),
          "description": t.get("description", ""),
          "inputSchema": t.get("inputSchema", {})}
         for t in tools),
        key=lambda t: t["name"])
    return json.dumps(normalized, separators=(",", ":"),
                      sort_keys=True, ensure_ascii=False).encode("utf-8")


def manifest_digest(tools: list[dict[str, Any]]) -> str:
    """keccak/sha3 digest over the canonical manifest."""
    return _digest(canonical_manifest(tools))


@dataclass
class ToolManifest:
    """A signed, pinnable description of a server's tool surface."""
    server: str
    tools: list[dict[str, Any]]
    version: str = "1"
    publisher: str = ""                       # signer address
    signature: str = ""                       # EIP-712 over the digest
    anchored_root: str = ""                   # mandate root this was committed to

    @property
    def digest(self) -> str:
        return manifest_digest(self.tools)

    def to_json(self) -> str:
        return json.dumps({
            "server": self.server, "version": self.version,
            "digest": self.digest, "publisher": self.publisher,
            "signature": self.signature, "anchoredRoot": self.anchored_root,
            "tools": self.tools,
        }, separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "ToolManifest":
        d = json.loads(s)
        return ToolManifest(server=d["server"], tools=d.get("tools", []),
                            version=d.get("version", "1"),
                            publisher=d.get("publisher", ""),
                            signature=d.get("signature", ""),
                            anchored_root=d.get("anchoredRoot", ""))


class SupplyChainError(Exception):
    pass


@dataclass
class SupplyChainVerifier:
    """
    Verifies live servers against approved manifests.

        v = SupplyChainVerifier(trusted_publishers={"0xPUB…"})
        v.pin("research", approved_digest)          # from your approval process
        v.verify_server("research", live_tools)     # raises on mismatch
    """
    trusted_publishers: set[str] = field(default_factory=set)
    _pins: dict[str, str] = field(default_factory=dict)

    # ── pinning ──
    def pin(self, server: str, digest: str) -> None:
        """Record the approved manifest digest for a server."""
        self._pins[server] = digest.lower()

    def pin_manifest(self, manifest: ToolManifest) -> None:
        self._pins[manifest.server] = manifest.digest.lower()

    def verify_server(self, server: str, live_tools: list[dict[str, Any]]) -> str:
        """
        Check a live server's tools against the pinned digest.
        Returns the digest on success; raises SupplyChainError on mismatch
        (rug pull / schema poisoning) or if the server isn't pinned.
        """
        live = manifest_digest(live_tools).lower()
        pinned = self._pins.get(server)
        if pinned is None:
            raise SupplyChainError(
                f"server '{server}' has no approved manifest (shadow/unknown)")
        if live != pinned:
            raise SupplyChainError(
                f"manifest mismatch for '{server}': live {live[:14]}… != "
                f"approved {pinned[:14]}… (possible rug pull or schema poisoning)")
        return live

    # ── signatures ──
    def verify_signature(self, manifest: ToolManifest,
                         chain_id: int = 8453) -> bool:
        """
        Verify the publisher's EIP-712 signature over the manifest digest and
        that the recovered signer is a trusted publisher.
        """
        if not _ETH:
            raise SupplyChainError("eth-account required for signature checks")
        if not manifest.signature or not manifest.publisher:
            return False
        typed = _manifest_typed_data(manifest.server, manifest.version,
                                     manifest.digest, chain_id)
        recovered = Account.recover_message(
            encode_typed_data(full_message=typed),
            signature=manifest.signature)
        if recovered.lower() != manifest.publisher.lower():
            return False
        return (not self.trusted_publishers
                or recovered.lower() in {p.lower() for p in self.trusted_publishers})

    def verify_full(self, server: str, live_tools: list[dict[str, Any]],
                    manifest: ToolManifest, chain_id: int = 8453) -> None:
        """Pin check + signature check together. Raises on any failure."""
        self.verify_server(server, live_tools)
        if not self.verify_signature(manifest, chain_id):
            raise SupplyChainError(
                f"manifest signature invalid or publisher not trusted for '{server}'")


def _manifest_typed_data(server: str, version: str, digest: str,
                         chain_id: int) -> dict:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "ToolManifest": [
                {"name": "server", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "digest", "type": "string"},
            ],
        },
        "primaryType": "ToolManifest",
        "domain": {"name": "XCPSupplyChain", "version": "1", "chainId": chain_id},
        "message": {"server": server, "version": version, "digest": digest},
    }


def sign_manifest(private_key: str, manifest: ToolManifest,
                  chain_id: int = 8453) -> ToolManifest:
    """Publisher-side: sign a manifest's digest (EIP-712)."""
    if not _ETH:
        raise SupplyChainError("eth-account required to sign manifests")
    typed = _manifest_typed_data(manifest.server, manifest.version,
                                 manifest.digest, chain_id)
    acct = Account.from_key(private_key)
    sig = Account.sign_message(encode_typed_data(full_message=typed),
                               private_key=private_key).signature.hex()
    manifest.publisher = acct.address
    manifest.signature = "0x" + sig if not sig.startswith("0x") else sig
    return manifest


__all__ = [
    "ToolManifest", "SupplyChainVerifier", "SupplyChainError",
    "manifest_digest", "canonical_manifest", "sign_manifest",
]
