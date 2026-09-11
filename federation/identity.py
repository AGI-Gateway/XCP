"""
federation.identity — a node identity that survives certificate rotation.

THE FLAW THIS FIXES
-------------------
Node identity was the certificate footprint itself:

    node_id = keccak256(DER(cert))

That makes identity an *ephemeral credential*. Let's Encrypt renews every 60–90
days, and on each renewal:

  · every peer that recorded you sees a stranger
  · attestations other nodes issued for your old id become worthless
  · revocations keyed to the old id do not cover the new one
  · re-peering is manual, so a federation degrades a little every quarter

A trust network whose members lose their identity four times a year is not a
trust network. This is the same mistake as identifying a person by their current
passport number.

THE FIX
-------
Split the two things that were conflated, exactly as the SessionRegistry already
does one layer down — a *stable* agent identity, with a *rotating* certificate
bound underneath it:

    node_id       keccak(stable public key)      never changes
    cert binding  footprint + seq + validity,    rotates freely,
                  SIGNED by the stable key       signed by the same identity

A peer verifies three things, all locally: the record came from the domain it
claims, the cert binding is signed by the stable key, and the footprint in the
binding matches the certificate the live TLS connection actually presented.
Rotation then needs no re-peering at all — the operator publishes a new signed
binding and peers pick it up on their next fetch.

TWO THINGS THAT WOULD OTHERWISE BREAK IT
----------------------------------------
**Overlap.** During a rotation both the old and the new certificate are briefly
in service. A record carries the current binding and the previous one, so a peer
that connects mid-rotation still verifies instead of alarming.

**Downgrade.** Without ordering, an attacker could replay an *old* binding to
make a peer accept a certificate that has since been rotated away from — perhaps
one whose key they stole. Bindings carry a monotonic sequence, and a peer must
refuse any binding whose sequence is not greater than the newest it has seen.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_utils import keccak as _keccak
    _ETH = True
except ImportError:                                   # pragma: no cover
    _ETH = False

IDENTITY_SPEC_VERSION = "0.2-draft"
# How long a peer keeps accepting the previous certificate after a rotation.
ROTATION_GRACE = 48 * 3600


def digest(data: bytes) -> str:
    if _ETH:
        return "0x" + _keccak(data).hex()
    return "0x" + hashlib.sha3_256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


class IdentityError(Exception):
    pass


# ── the stable half ────────────────────────────────────────────────────────

def node_id_from_address(address: str) -> str:
    """A node's permanent identifier, derived from its long-lived key."""
    return digest(address.lower().encode("utf-8"))


@dataclass
class NodeIdentity:
    """
    The operator's long-lived key. This is the thing peers actually trust; the
    certificate is just how it proves itself on a given day.

    Keep the private key offline or in a secret backend. Losing it means losing
    the node's identity and every attestation anyone made about it — rotating a
    certificate is routine, rotating this is not.
    """
    address: str
    private_key: Optional[str] = None

    @property
    def node_id(self) -> str:
        return node_id_from_address(self.address)

    @staticmethod
    def generate() -> "NodeIdentity":
        if not _ETH:
            raise IdentityError("eth-account required to generate a node identity")
        acct = Account.create()
        return NodeIdentity(address=acct.address, private_key=acct.key.hex())

    @staticmethod
    def from_key(private_key: str) -> "NodeIdentity":
        if not _ETH:
            raise IdentityError("eth-account required")
        acct = Account.from_key(private_key)
        return NodeIdentity(address=acct.address, private_key=private_key)


# ── the rotating half ──────────────────────────────────────────────────────

@dataclass
class CertBinding:
    """
    A signed statement: *this stable identity currently presents this
    certificate*. Rotating a certificate means publishing a new one of these.
    """
    node_id: str
    cert_footprint: str
    sequence: int                  # strictly increasing; blocks downgrade replay
    not_before: int
    not_after: int
    domain: str = ""
    signer: str = ""
    signature: str = ""
    spec_version: str = IDENTITY_SPEC_VERSION

    def payload(self) -> dict[str, Any]:
        return {"nodeId": self.node_id, "certFootprint": self.cert_footprint,
                "sequence": self.sequence, "notBefore": self.not_before,
                "notAfter": self.not_after, "domain": self.domain}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "CertBinding":
        known = {f for f in CertBinding.__dataclass_fields__}
        return CertBinding(**{k: v for k, v in d.items() if k in known})

    def active(self, now: Optional[int] = None, grace: int = 0) -> bool:
        n = now or int(time.time())
        return self.not_before <= n <= self.not_after + grace


def _typed(payload: dict[str, Any], chain_id: int) -> dict:
    return {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"},
                             {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}],
            "CertBinding": [
                {"name": "nodeId", "type": "string"},
                {"name": "certFootprint", "type": "string"},
                {"name": "sequence", "type": "uint64"},
                {"name": "notBefore", "type": "uint64"},
                {"name": "notAfter", "type": "uint64"},
                {"name": "domain", "type": "string"}],
        },
        "primaryType": "CertBinding",
        "domain": {"name": "XCPNodeIdentity", "version": "1", "chainId": chain_id},
        "message": payload,
    }


def sign_binding(identity: NodeIdentity, cert_footprint: str, *, domain: str,
                 sequence: int, ttl: int = 90 * 86400,
                 now: Optional[int] = None, chain_id: int = 8453) -> CertBinding:
    """Attest that this identity is currently presenting this certificate."""
    if not _ETH:
        raise IdentityError("eth-account required to sign a certificate binding")
    if not identity.private_key:
        raise IdentityError("signing needs the node's private key")
    n = now or int(time.time())
    b = CertBinding(node_id=identity.node_id, cert_footprint=cert_footprint,
                    sequence=sequence, not_before=n, not_after=n + ttl,
                    domain=domain, signer=identity.address)
    sig = Account.sign_message(
        encode_typed_data(full_message=_typed(b.payload(), chain_id)),
        private_key=identity.private_key).signature.hex()
    b.signature = sig if sig.startswith("0x") else "0x" + sig
    return b


def verify_binding(b: CertBinding, *, expected_node_id: str = "",
                   expected_domain: str = "", tls_footprint: str = "",
                   now: Optional[int] = None, grace: int = 0,
                   min_sequence: int = 0, chain_id: int = 8453) -> list[str]:
    """
    Check a binding. Returns problems; empty means this certificate genuinely
    belongs to this stable identity right now.
    """
    problems: list[str] = []
    n = now or int(time.time())

    if expected_node_id and b.node_id.lower() != expected_node_id.lower():
        problems.append("binding is for a different node identity")
    if expected_domain and b.domain and b.domain.lower() != expected_domain.lower():
        problems.append(f"binding claims {b.domain}, served from {expected_domain}")
    if tls_footprint and b.cert_footprint.lower() != tls_footprint.lower():
        problems.append("bound footprint does not match the certificate "
                        "presented over TLS")
    if not b.active(n, grace):
        problems.append("binding is expired or not yet valid")
    if b.sequence < min_sequence:
        problems.append(
            f"binding sequence {b.sequence} is older than {min_sequence} — "
            "refusing a replayed binding for a rotated-away certificate")
    if not b.signature:
        problems.append("binding is unsigned")
    elif _ETH:
        try:
            rec = Account.recover_message(
                encode_typed_data(full_message=_typed(b.payload(), chain_id)),
                signature=b.signature)
            if b.signer and rec.lower() != b.signer.lower():
                problems.append("signature does not match the declared signer")
            if node_id_from_address(rec) != b.node_id:
                problems.append("signer is not the node identity it claims to be")
        except Exception as e:
            problems.append(f"binding signature failed to recover: {e}")
    return problems


# ── rotation ───────────────────────────────────────────────────────────────

@dataclass
class BindingSet:
    """
    What a node publishes: the certificate it presents now, plus the one it just
    rotated away from, so a peer connecting mid-rotation still verifies.
    """
    current: CertBinding
    previous: Optional[CertBinding] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"current": self.current.to_dict()}
        if self.previous:
            d["previous"] = self.previous.to_dict()
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "BindingSet":
        prev = d.get("previous")
        return BindingSet(current=CertBinding.from_dict(d["current"]),
                          previous=CertBinding.from_dict(prev) if prev else None)

    @property
    def sequence(self) -> int:
        return self.current.sequence


def rotate(identity: NodeIdentity, new_cert_footprint: str, *, domain: str,
           existing: Optional[BindingSet] = None, ttl: int = 90 * 86400,
           now: Optional[int] = None) -> BindingSet:
    """
    Publish a new certificate without changing the node's identity.

    This is the whole point: a renewal is a new *binding*, not a new node. Peers
    pick it up on their next fetch, attestations others issued still apply, and
    revocations keyed to the node id still bite.
    """
    seq = (existing.sequence + 1) if existing else 1
    b = sign_binding(identity, new_cert_footprint, domain=domain,
                     sequence=seq, ttl=ttl, now=now)
    return BindingSet(current=b,
                      previous=existing.current if existing else None)


def accept(bs: BindingSet, *, tls_footprint: str, expected_node_id: str = "",
           expected_domain: str = "", known_sequence: int = 0,
           now: Optional[int] = None,
           grace: int = ROTATION_GRACE) -> tuple[bool, str, list[str]]:
    """
    Peer-side check. Tries the current binding, then the previous one within the
    rotation grace window.

    Returns (accepted, which, problems).
    """
    cur = verify_binding(bs.current, expected_node_id=expected_node_id,
                         expected_domain=expected_domain,
                         tls_footprint=tls_footprint, now=now,
                         min_sequence=known_sequence)
    if not cur:
        return True, "current", []
    if bs.previous is not None:
        prev = verify_binding(bs.previous, expected_node_id=expected_node_id,
                              expected_domain=expected_domain,
                              tls_footprint=tls_footprint, now=now,
                              grace=grace, min_sequence=0)
        if not prev:
            # Mid-rotation: the peer is still serving the old certificate while
            # the new binding is already published. Accept, but say so.
            return True, "previous", ["serving the previous certificate "
                                      "(rotation in progress)"]
    return False, "none", cur


__all__ = [
    "NodeIdentity", "CertBinding", "BindingSet", "IdentityError",
    "sign_binding", "verify_binding", "rotate", "accept",
    "node_id_from_address", "digest", "ROTATION_GRACE",
    "IDENTITY_SPEC_VERSION",
]
