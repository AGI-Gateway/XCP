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
