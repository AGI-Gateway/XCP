"""
federation.node — a web of XCP nodes with no central authority.

An XCP node is one operator's gateway. A *federation* is what you get when nodes
verify each other directly instead of consulting a registry somebody owns. That
is the difference between an agent platform and an agentic internet: nobody has
to be asked for permission, and nobody can be de-listed.

WHAT A NODE NEEDS TO PROVE ITSELF
---------------------------------
Exactly what a website needs, and nothing more:

    a domain you control  +  a TLS certificate for it

The node's identity is the footprint of its certificate,
`keccak256(DER(cert))`, published at a well-known path on its own domain. A peer
verifies it by fetching that record over TLS *from that domain* and checking the
footprint matches the certificate the TLS handshake actually presented. If they
match, the domain owner published it — no third party consulted, no account
created, no registry queried.

BE HONEST ABOUT THE DEPENDENCIES
--------------------------------
"No centralised dependencies" is a claim worth stating precisely, because the
loose version is false.

Still depended on:
  · DNS — to resolve a domain to a host
  · Certificate authorities — to attest the domain↔key binding

Those are the web's existing trust roots. This design deliberately inherits them
rather than inventing a replacement, because an agentic internet that requires
its own naming system and its own PKI will not be adopted. They are federated,
not centralised: many registrars, many CAs, no single operator. You can narrow
them further with DANE/TLSA or a private CA inside a consortium.

NOT depended on:
  · any registry, index or directory that one party operates
  · any blockchain — chain anchoring is OPTIONAL and off by default
  · any vendor's API, account, key or approval
  · this project, its maintainers, or any of its infrastructure

A node that never talks to us works exactly as well as one that does. That is
the test of whether infrastructure is actually open.

TRUST THAT TRAVELS
------------------
Direct peering does not scale to a web — you cannot hand-verify thousands of
nodes. So trust propagates transitively, with two hard limits that make it safe:

    it DECAYS   — a peer-of-a-peer is never trusted more than the weakest link
    it is CAPPED — beyond a small hop count it converges to nothing

Without decay, transitive trust is a security hole: one compromised node would
launder trust to everything it vouches for. With decay, a chain of vouching gets
weaker with distance, exactly like it should.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Iterable, Optional

try:
    from eth_utils import keccak as _keccak
    _ETH = True
except ImportError:                                   # pragma: no cover
    _ETH = False

NODE_RECORD_PATH = "/.well-known/xcp-node.json"
NODE_SPEC_VERSION = "0.1-draft"

# Transitive trust: how much of a peer's trust survives one extra hop, and how
# far it may travel at all. Both are deliberately conservative.
DECAY_PER_HOP = 0.5
MAX_HOPS = 3


def digest(data: bytes) -> str:
    if _ETH:
        return "0x" + _keccak(data).hex()
    return "0x" + hashlib.sha3_256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


class FederationError(Exception):
    pass


class PeerTrust(IntEnum):
    """How a node came to trust a peer. Ascending."""
    UNKNOWN = 0      # seen, never verified
    VERIFIED = 1     # its node record matches the cert served from its domain
    PEERED = 2       # mutual: we verified it and it verified us
    ATTESTED = 3     # a peer we already trust has signed an attestation for it

    @property
    def label(self) -> str:
        return {0: "unknown", 1: "verified", 2: "peered", 3: "attested"}[int(self)]


# ── the node's own record ──────────────────────────────────────────────────

@dataclass
class NodeRecord:
    """
    What a node publishes at `/.well-known/xcp-node.json`. Self-describing, so a
    peer needs nothing but this file and the TLS connection that served it.
    """
    domain: str
    node_id: str                       # keccak256(DER(node cert))
    gateway_url: str
    spec_version: str = NODE_SPEC_VERSION
    mcp_spec: str = "2026-07-28"
    operator: str = "anonymous"
    # what this node is willing to do with peers
    accepts_peering: bool = True
    federates_catalogs: bool = True    # will ingest peers' ARD catalogs
    relays_revocations: bool = True    # will gossip revocations onward
    # optional, NOT required
    chain_id: int = 0                  # 0 = no chain anchoring
    session_registry: str = ""
    seed_peers: list[str] = field(default_factory=list)   # domains, for bootstrap
    published_at: int = 0

    def validate(self) -> list[str]:
        p = []
        if not self.domain or "/" in self.domain:
            p.append("domain must be a bare hostname")
        if not self.node_id.startswith("0x") or len(self.node_id) < 34:
            p.append("node_id must be a 0x-prefixed certificate footprint")
        if not self.gateway_url.startswith("https://"):
            p.append("gateway_url must be https")
        return p

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "NodeRecord":
        known = {f for f in NodeRecord.__dataclass_fields__}
        return NodeRecord(**{k: v for k, v in d.items() if k in known})


def build_node_record(domain: str, cert_pem: bytes, gateway_url: str,
                      **kw: Any) -> NodeRecord:
    """Build the record a node serves at its well-known path."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(Encoding.DER)
    rec = NodeRecord(domain=domain, node_id=digest(der),
                     gateway_url=gateway_url,
                     published_at=int(time.time()), **kw)
    problems = rec.validate()
    if problems:
        raise FederationError("; ".join(problems))
    return rec


# ── peers ──────────────────────────────────────────────────────────────────

@dataclass
class Peer:
    domain: str
    node_id: str
    gateway_url: str = ""
    trust: PeerTrust = PeerTrust.UNKNOWN
    hops: int = 1                      # 1 = direct
    weight: float = 1.0                # decayed trust weight
    introduced_by: str = ""            # which peer vouched, if transitive
    last_seen: int = 0
    revoked: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["trust"] = self.trust.label
        return d


@dataclass
class Attestation:
    """One node vouching for another. The unit of transitive trust."""
    subject_domain: str
    subject_node_id: str
    issuer_domain: str
    issuer_node_id: str
    trust: PeerTrust
    issued_at: int
    expires_at: int
    signature: str = ""

    def payload(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("signature", None)
        d["trust"] = int(self.trust)
        return d

    @property
    def att_digest(self) -> str:
        return digest(canonical(self.payload()))

    def expired(self, now: Optional[int] = None) -> bool:
        return (now or int(time.time())) > self.expires_at


# ── verification: the whole point ──────────────────────────────────────────

def verify_node_record(record: NodeRecord, tls_cert_der: bytes,
                       served_from_domain: str) -> list[str]:
    """
    Verify a peer with no third party involved.

    Three checks, all local:
      1. the record is well-formed
      2. the record was served from the domain it claims
      3. the node_id in the record matches the certificate the TLS handshake
         actually presented

    If all three hold, the domain owner published this record. That is the
    entire trust argument, and it is the same one the web already runs on.
    """
    problems = record.validate()
    if served_from_domain.lower() != record.domain.lower():
        problems.append(
            f"record claims {record.domain} but was served from {served_from_domain}")
    actual = digest(tls_cert_der)
    if actual.lower() != record.node_id.lower():
        problems.append("node_id does not match the certificate presented over TLS")
    return problems


# ── the federation ─────────────────────────────────────────────────────────

@dataclass
class Federation:
    """
    One node's view of the web. Purely local: there is no shared state, no
    consensus, and no authority. Two nodes may legitimately disagree about who
    is trustworthy, and nothing breaks.

        fed = Federation(self_domain="node-a.example", self_node_id="0x…")
        fed.add_verified_peer("node-b.example", "0x…", "https://node-b.example")
        fed.ingest_attestation(att)          # b vouches for c
        fed.trust_of("node-c.example")       # transitive, decayed
    """
    self_domain: str
    self_node_id: str
    decay_per_hop: float = DECAY_PER_HOP
    max_hops: int = MAX_HOPS
    min_weight: float = 0.1              # below this, treat as unknown
    peers: dict[str, Peer] = field(default_factory=dict)
    revocations: set[str] = field(default_factory=set)   # node_ids

    # ---- direct peering ----
    def add_verified_peer(self, domain: str, node_id: str, gateway_url: str = "",
                          mutual: bool = False, now: Optional[int] = None) -> Peer:
        p = Peer(domain=domain.lower(), node_id=node_id, gateway_url=gateway_url,
                 trust=PeerTrust.PEERED if mutual else PeerTrust.VERIFIED,
                 hops=1, weight=1.0, last_seen=now or int(time.time()))
        self.peers[p.domain] = p
        return p

    # ---- transitive trust ----
    def ingest_attestation(self, att: Attestation,
                           now: Optional[int] = None) -> Optional[Peer]:
        """
        Accept a vouching from a peer we already trust. Trust decays by hop, so a
        peer-of-a-peer is never trusted as much as a peer, and it can never
        exceed the trust we place in the introducer.
        """
        now = now or int(time.time())
        if att.expired(now):
            return None
        issuer = self.peers.get(att.issuer_domain.lower())
        if issuer is None or issuer.revoked:
            return None                       # we don't trust the introducer
        if att.subject_node_id in self.revocations:
            return None
        subject = att.subject_domain.lower()
        if subject == self.self_domain.lower():
            return None                       # ignore vouching for ourselves
        hops = issuer.hops + 1
        if hops > self.max_hops:
            return None
        weight = issuer.weight * self.decay_per_hop
        if weight < self.min_weight:
            return None
        existing = self.peers.get(subject)
        # a direct relationship always beats an introduced one
        if existing and existing.hops <= hops and existing.weight >= weight:
            return existing
        p = Peer(domain=subject, node_id=att.subject_node_id,
                 trust=min(PeerTrust.ATTESTED, att.trust), hops=hops,
                 weight=weight, introduced_by=att.issuer_domain,
                 last_seen=now)
        self.peers[subject] = p
        return p

    def trust_of(self, domain: str) -> tuple[PeerTrust, float]:
        p = self.peers.get(domain.lower())
        if p is None or p.revoked or p.node_id in self.revocations:
            return PeerTrust.UNKNOWN, 0.0
        return p.trust, p.weight

    # ---- revocation gossip (no chain required) ----
    def revoke(self, node_id: str) -> list[str]:
        """
        Mark a node revoked locally and return the peers to gossip it to.
        Without a chain, revocation is eventually-consistent: it spreads by
        gossip and is backstopped by short credential TTLs, so a compromised
        node ages out in seconds even if the gossip never reaches you.
        """
        self.revocations.add(node_id)
        for p in self.peers.values():
            if p.node_id == node_id:
                p.revoked = True
        return [p.gateway_url or p.domain for p in self.peers.values()
                if not p.revoked and p.trust >= PeerTrust.VERIFIED]

    def ingest_revocation(self, node_id: str, from_domain: str) -> bool:
        """Accept a revocation only from a peer we actually trust."""
        src = self.peers.get(from_domain.lower())
        if src is None or src.revoked or src.trust < PeerTrust.VERIFIED:
            return False
        self.revoke(node_id)
        return True

    # ---- views ----
    def reachable(self, min_trust: PeerTrust = PeerTrust.VERIFIED) -> list[Peer]:
        return sorted(
            (p for p in self.peers.values()
             if not p.revoked and p.trust >= min_trust and p.weight >= self.min_weight),
            key=lambda p: (-p.weight, p.domain))

    def bootstrap_targets(self, record: NodeRecord) -> list[str]:
        """
        Joining without a central registry: start from any node you already know
        — a colleague's, a vendor's, one listed in an ARD catalog, one printed in
        a README. Seeds are a convenience, not an authority; a node with a
        different seed list reaches the same web.
        """
        return [d for d in record.seed_peers if d.lower() != self.self_domain.lower()]

    def summary(self) -> dict[str, Any]:
        return {
            "self": self.self_domain,
            "peers": len(self.peers),
            "direct": sum(1 for p in self.peers.values() if p.hops == 1 and not p.revoked),
            "transitive": sum(1 for p in self.peers.values() if p.hops > 1 and not p.revoked),
            "revoked": sum(1 for p in self.peers.values() if p.revoked),
            "maxHops": self.max_hops,
            "decayPerHop": self.decay_per_hop,
            "chainRequired": False,
        }


__all__ = [
    "NodeRecord", "Peer", "Attestation", "Federation", "PeerTrust",
    "build_node_record", "verify_node_record", "digest", "canonical",
    "FederationError", "NODE_RECORD_PATH", "NODE_SPEC_VERSION",
    "DECAY_PER_HOP", "MAX_HOPS",
]
