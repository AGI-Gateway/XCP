"""
vault.sealed — credentials the gateway cannot read.

THE PROBLEM THIS SOLVES
-----------------------
A hosted wrapper needs the caller's upstream credential — their Stripe key, their
Jira token. The obvious design forwards it through the gateway, which means
whoever operates the gateway can read every user's API key. For a trust layer
that is disqualifying: `vault/README.md` says XCP is never the system of record
for your credentials, and an operator who can read them is exactly that.

So the credential is **sealed to the wrapper**, not handed to the gateway:

    caller  --seal(cred, wrapper_pubkey)-->  gateway  --opaque blob-->  wrapper
                                             (cannot open it)          (unseals,
                                                                        uses once,
                                                                        discards)

The gateway still does its job — verify the session, gate the mandate, route —
but the bytes it forwards are ciphertext it has no key for. That preserves the
property the whole system rests on: the gateway is a verifier and a router,
never a custodian.

CONSTRUCTION
------------
Standard sealed-box: an ephemeral X25519 keypair per message, HKDF-SHA256 over
the shared secret, AES-256-GCM for the payload. The ephemeral public key travels
with the ciphertext; the sender discards its private half immediately, so even
the sender cannot decrypt afterwards.

Binding: the recipient's public key and a caller-supplied context string are
mixed into the AAD, so a blob sealed for one wrapper cannot be replayed against
another, and one sealed for `tools/call:charge` cannot be reused for a different
operation.

WHAT THIS DOES NOT DO
---------------------
It does not protect against a malicious *wrapper* — whoever runs the wrapper can
obviously read what it unseals, because it has to use the credential upstream.
The guarantee is narrower and worth stating precisely: **the gateway operator is
removed from the trust set.** If you do not trust the wrapper operator either,
run the wrapper yourself; that is what `credential_source="operator"` is for.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    _CRYPTO = True
except ImportError:                                   # pragma: no cover
    _CRYPTO = False

SEALED_VERSION = 1
HKDF_INFO = b"xcp-sealed-credential-v1"


class SealError(Exception):
    pass


def _require() -> None:
    if not _CRYPTO:
        raise SealError("the `cryptography` package is required for sealed credentials")


# ── key material ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RecipientKey:
    """A wrapper's public key. Safe to publish; it is how callers seal to it."""
    public_b64: str

    def raw(self) -> bytes:
        return base64.urlsafe_b64decode(self.public_b64 + "==")

    def to_dict(self) -> dict:
        return {"alg": "X25519", "version": SEALED_VERSION,
                "publicKey": self.public_b64}


def generate_recipient_key() -> tuple[str, RecipientKey]:
    """
    Create a wrapper's keypair. The private half stays in the wrapper's process
    or its own secret store; the public half is published at
    `/xcp/credential-key` so callers can seal to it.
    """
    _require()
    priv = X25519PrivateKey.generate()
    priv_b = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    pub_b = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return (base64.urlsafe_b64encode(priv_b).decode().rstrip("="),
            RecipientKey(base64.urlsafe_b64encode(pub_b).decode().rstrip("=")))


def seal_public_from_private(private_b64: str) -> "RecipientKey":
    """Recover the published public key from a persisted private key."""
    _require()
    priv = X25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(private_b64 + "=="))
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return RecipientKey(base64.urlsafe_b64encode(pub).decode().rstrip("="))


def _derive(shared: bytes, recipient_pub: bytes, context: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=HKDF_INFO + b"|" + recipient_pub + b"|"
                     + context.encode("utf-8")).derive(shared)


# ── seal / unseal ──────────────────────────────────────────────────────────

def seal(credential: str, recipient: RecipientKey, context: str = "") -> str:
    """
    Seal a credential to a wrapper. Returns a compact base64url blob safe to put
    in a header and route through infrastructure you do not trust to read it.

    `context` binds the blob to an intended use (e.g. "tools/call:CreateCharge").
    Reusing it for a different context fails to open.
    """
    _require()
    if not credential:
        raise SealError("refusing to seal an empty credential")
    recipient_pub = recipient.raw()
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    key = _derive(shared, recipient_pub, context)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, credential.encode("utf-8"),
                             recipient_pub + context.encode("utf-8"))
    eph_pub = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    # the sender's ephemeral private key goes out of scope here and is never
    # retained, so even the sender cannot reopen this blob
    blob = {"v": SEALED_VERSION,
            "epk": base64.urlsafe_b64encode(eph_pub).decode().rstrip("="),
            "n": base64.urlsafe_b64encode(nonce).decode().rstrip("="),
            "ct": base64.urlsafe_b64encode(ct).decode().rstrip("=")}
    return base64.urlsafe_b64encode(
        json.dumps(blob, separators=(",", ":")).encode()).decode().rstrip("=")


def unseal(blob_b64: str, private_b64: str, recipient: RecipientKey,
           context: str = "") -> str:
    """
    Open a sealed credential. Only the wrapper holding the private key can do
    this — not the gateway, and not the original sender.
    """
    _require()
    try:
        blob = json.loads(base64.urlsafe_b64decode(blob_b64 + "==="[:(-len(blob_b64)) % 4]))
    except Exception as e:
        raise SealError(f"malformed sealed credential: {e}")
    if blob.get("v") != SEALED_VERSION:
        raise SealError(f"unsupported sealed-credential version {blob.get('v')}")
    try:
        priv = X25519PrivateKey.from_private_bytes(
            base64.urlsafe_b64decode(private_b64 + "=="))
        epk = X25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode(blob["epk"] + "=="))
        recipient_pub = recipient.raw()
        key = _derive(priv.exchange(epk), recipient_pub, context)
        pt = AESGCM(key).decrypt(
            base64.urlsafe_b64decode(blob["n"] + "=="),
            base64.urlsafe_b64decode(blob["ct"] + "=="),
            recipient_pub + context.encode("utf-8"))
    except SealError:
        raise
    except Exception:
        # deliberately uninformative: a padding/AAD oracle is a real attack
        raise SealError("could not open the sealed credential "
                        "(wrong recipient, wrong context, or tampered)")
    return pt.decode("utf-8")


__all__ = ["RecipientKey", "generate_recipient_key", "seal", "unseal",
           "seal_public_from_private",
           "SealError", "SEALED_VERSION"]


# ── delegation chains ──────────────────────────────────────────────────────
#
# Sealing is single-hop: a caller seals to one wrapper's key. A multi-hop
# workflow — agent to gateway to wrapper to a second wrapper — therefore forces
# the caller to hold a key for every hop and re-seal N times. In practice that
# means callers stop sealing and hand over a bearer credential instead, which
# loses the property the whole mechanism exists for.
#
# A delegation chain lets a holder pass a sealed credential onward WITHOUT ever
# seeing the plaintext of a credential sealed to someone else, and without the
# originator having to know the downstream topology in advance.
#
# The construction is deliberately modest and its limit is worth stating up
# front: re-sealing requires the intermediate hop to hold the plaintext
# momentarily, because it must encrypt to the next recipient. What the chain
# adds is not secrecy from the hop — that is impossible for any relay that is
# not doing proxy re-encryption — but ACCOUNTABILITY: every hop is named, the
# chain is bound into the AAD, and a recipient can refuse a chain that grew
# longer than the originator permitted or that passed through a hop they do not
# accept.
#
# If you need secrecy from intermediate hops, do not delegate: seal directly to
# the final recipient.


@dataclass
class Delegation:
    """One hop's record in a chain. Signed by the hop that performed it."""
    from_node: str
    to_node: str
    at: int
    reason: str = ""

    def to_dict(self) -> dict:
        return {"from": self.from_node, "to": self.to_node, "at": self.at,
                "reason": self.reason[:120]}


@dataclass
class ChainedCredential:
    """A sealed credential plus the provenance of how it got here."""
    blob: str
    origin: str                      # who sealed it first
    hops: list                       # list[Delegation]
    max_hops: int = 3

    @property
    def depth(self) -> int:
        return len(self.hops)

    def context(self) -> str:
        """
        The AAD context binds the chain so far. A hop cannot silently rewrite
        history: changing the recorded path changes the context, and the blob
        then fails to open.
        """
        path = "|".join(f"{h.from_node}>{h.to_node}" for h in self.hops)
        return f"chain:{self.origin}:{self.depth}:{path}"

    def to_dict(self) -> dict:
        return {"blob": self.blob, "origin": self.origin, "maxHops": self.max_hops,
                "hops": [h.to_dict() for h in self.hops], "depth": self.depth}

    @staticmethod
    def from_dict(d: dict) -> "ChainedCredential":
        return ChainedCredential(
            blob=d["blob"], origin=d["origin"], max_hops=int(d.get("maxHops", 3)),
            hops=[Delegation(h["from"], h["to"], int(h["at"]), h.get("reason", ""))
                  for h in d.get("hops", [])])


def seal_chained(credential: str, recipient: "RecipientKey", *, origin: str,
                 max_hops: int = 3) -> ChainedCredential:
    """
    Seal a credential that MAY be delegated onward, up to `max_hops` times.

    `max_hops` is the originator's budget and cannot be raised downstream —
    a hop that inflated it would be granting itself authority the originator
    withheld.
    """
    if max_hops < 0:
        raise SealError("max_hops cannot be negative")
    c = ChainedCredential(blob="", origin=origin, hops=[], max_hops=max_hops)
    c.blob = seal(credential, recipient, context=c.context())
    return c


def open_chained(chained: ChainedCredential, private_b64: str,
                 recipient: "RecipientKey") -> str:
    """Open a chained credential at the current hop."""
    return unseal(chained.blob, private_b64, recipient, context=chained.context())


def delegate(chained: ChainedCredential, private_b64: str,
             recipient: "RecipientKey", next_recipient: "RecipientKey", *,
             from_node: str, to_node: str, reason: str = "",
             now: Optional[int] = None) -> ChainedCredential:
    """
    Pass a sealed credential to the next hop.

    The budget is checked BEFORE the plaintext is recovered, so a chain that has
    run out of hops never causes a decryption that was not permitted.
    """
    if chained.depth >= chained.max_hops:
        raise SealError(
            f"delegation budget exhausted: the originator permitted "
            f"{chained.max_hops} hop(s) and this is hop {chained.depth + 1}")
    # A node that already handled this credential must not receive it again.
    # Checking only to_node missed the case of delegating BACK to an earlier
    # hop, which appears in the chain as a from_node.
    seen = {chained.origin}
    for h in chained.hops:
        seen.add(h.from_node)
        seen.add(h.to_node)
    if to_node in seen:
        raise SealError(
            f"{to_node!r} already appears in this chain; a loop would let a hop "
            "see the credential twice and inflate the recorded path")

    plaintext = open_chained(chained, private_b64, recipient)
    extended = ChainedCredential(
        blob="", origin=chained.origin, max_hops=chained.max_hops,
        hops=list(chained.hops) + [
            Delegation(from_node=from_node, to_node=to_node,
                       at=now or int(time.time()), reason=reason)])
    extended.blob = seal(plaintext, next_recipient, context=extended.context())
    del plaintext
    return extended


def acceptable(chained: ChainedCredential, *, allowed_hops: Optional[set] = None,
               max_depth: Optional[int] = None) -> list[str]:
    """
    A recipient's own check on a chain it has been handed. Returns problems.

    The originator sets a budget; the RECIPIENT decides whether it accepts the
    path that was actually taken. Both halves are needed: a budget alone says
    nothing about who the credential passed through.
    """
    problems: list[str] = []
    if chained.depth > chained.max_hops:
        problems.append(f"chain is {chained.depth} hops but the originator "
                        f"permitted {chained.max_hops}")
    if max_depth is not None and chained.depth > max_depth:
        problems.append(f"chain is deeper than this recipient accepts "
                        f"({chained.depth} > {max_depth})")
    if allowed_hops is not None:
        for h in chained.hops:
            if h.to_node not in allowed_hops and h.to_node != chained.origin:
                problems.append(f"chain passed through {h.to_node!r}, which this "
                                "recipient does not accept")
    visited = [chained.origin]
    for h in chained.hops:
        visited.append(h.to_node)
    if len(visited) != len(set(visited)):
        problems.append("chain contains a loop")
    return problems


__all__ += ["Delegation", "ChainedCredential", "seal_chained", "open_chained",
            "delegate", "acceptable"]
