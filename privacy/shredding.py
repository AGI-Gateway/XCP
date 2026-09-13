"""
privacy.shredding — erase the content, keep the proof.

THE TENSION
-----------
`receipts.CallChain` is built so that removing a record changes the root. That is
the whole point: it is what makes the audit tamper-evident. It is also what makes
the record undeletable, which collides directly with a subject's right to
erasure.

Neither obvious answer works. Deleting the record destroys the integrity property
the audit exists for, and everyone downstream who verified that root now sees a
broken chain. Refusing erasure because the data structure is append-only is not a
lawful basis — "our database does not support it" has never been a defence.

CRYPTO-SHREDDING
----------------
Do not put the personal payload in the chain. Encrypt it under a key belonging to
one data subject, and commit to the **ciphertext**:

    leaf = H(ciphertext)        stable forever — the chain never breaks
    plaintext                   readable only with the subject's key

Erasure destroys the key. The ciphertext remains, now indistinguishable from
noise; the chain still verifies as a sequence and every party who recorded that
root is still correct. What is lost is exactly what should be lost: the content.

WHY HASHING ALONE IS NOT ENOUGH
-------------------------------
A hash of personal data is still personal data when it is linkable. Anyone
holding a candidate value can confirm a match, so hashing is pseudonymisation,
not anonymisation. Digesting a field does not discharge an erasure obligation —
which is why this module destroys *keys* rather than relying on `args_digest`.

After shredding, the ciphertext is no longer linkable to a person by anyone
without the destroyed key, which is the condition that makes it effectively
anonymous rather than merely pseudonymous.

WHAT THIS DOES NOT DO
---------------------
It does not reach copies held by peers. A federation that gossiped a payload
cannot un-gossip it, which is a reason this codebase keeps personal data out of
anything it publishes: transport commitments carry totals, never counterparties,
and catalogs carry no personal data at all. Erasure is scoped to what this node
holds, and a processor agreement has to cover the rest.

Status: XCP is a draft proposal. This is a design, not legal advice.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO = True
except ImportError:                                   # pragma: no cover
    _CRYPTO = False

try:
    from eth_utils import keccak as _keccak
    _KECCAK = True
except ImportError:                                   # pragma: no cover
    _KECCAK = False

SHRED_VERSION = 1


def digest(data: bytes) -> str:
    if _KECCAK:
        return "0x" + _keccak(data).hex()
    return "0x" + hashlib.sha3_256(data).hexdigest()


class ShredError(Exception):
    pass


def _require() -> None:
    if not _CRYPTO:
        raise ShredError("the `cryptography` package is required for shredding")


@dataclass
class SealedPayload:
    """
    Personal data at rest. The chain commits to `commitment`, which never
    changes — not to anything that has to be deleted later.
    """
    subject: str                 # pseudonymous subject id, never a name
    nonce: str
    ciphertext: str
    commitment: str              # H(ciphertext) — what the chain records
    created_at: int
    data_class: str = "call_chain"
    version: int = SHRED_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "nonce": self.nonce,
                "ciphertext": self.ciphertext, "commitment": self.commitment,
                "createdAt": self.created_at, "dataClass": self.data_class,
                "version": self.version}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "SealedPayload":
        return SealedPayload(
            subject=d["subject"], nonce=d["nonce"], ciphertext=d["ciphertext"],
            commitment=d["commitment"], created_at=int(d.get("createdAt", 0)),
            data_class=d.get("dataClass", "call_chain"),
            version=int(d.get("version", SHRED_VERSION)))


class KeyRing:
    """
    One key per data subject, and the ability to destroy one.

    Deliberately minimal: this is the component whose correctness decides
    whether an erasure request was actually honoured, so it should be small
    enough to read in full. In production the keys belong in the same managed
    backend as everything else — see `vault/` — and `destroy` must remove them
    from backups too, which is an operational obligation this code cannot
    discharge on its own.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}
        self._shredded: dict[str, int] = {}      # subject -> when

    def key_for(self, subject: str, create: bool = True) -> bytes:
        if subject in self._shredded:
            raise ShredError(
                f"subject {subject!r} was erased at {self._shredded[subject]}; "
                "refusing to mint a new key, which would silently un-erase them")
        k = self._keys.get(subject)
        if k is None:
            if not create:
                raise ShredError(f"no key for subject {subject!r}")
            _require()
            k = AESGCM.generate_key(bit_length=256)
            self._keys[subject] = k
        return k

    def destroy(self, subject: str, now: Optional[int] = None) -> bool:
        """
        Erase a subject. Irreversible by design: everything encrypted to this
        key becomes unreadable, including by us.
        """
        existed = subject in self._keys
        self._keys.pop(subject, None)
        self._shredded[subject] = now or int(time.time())
        return existed

    def is_shredded(self, subject: str) -> bool:
        return subject in self._shredded

    def subjects(self) -> list[str]:
        return sorted(self._keys)

    def stats(self) -> dict[str, int]:
        return {"activeSubjects": len(self._keys),
                "shreddedSubjects": len(self._shredded)}


def seal(ring: KeyRing, subject: str, payload: Any,
         data_class: str = "call_chain",
         now: Optional[int] = None) -> SealedPayload:
    """Encrypt a personal payload and return what the chain should commit to."""
    _require()
    key = ring.key_for(subject)
    nonce = os.urandom(12)
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True,
                     ensure_ascii=False).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, raw, subject.encode("utf-8"))
    import base64
    ct_b64 = base64.b64encode(ct).decode()
    return SealedPayload(
        subject=subject,
        nonce=base64.b64encode(nonce).decode(),
        ciphertext=ct_b64,
        commitment=digest(ct),          # stable: survives erasure
        created_at=now or int(time.time()),
        data_class=data_class)


def unseal(ring: KeyRing, sealed: SealedPayload) -> Any:
    """
    Read a payload back. Raises after erasure — which is the point, and the
    error says so plainly rather than looking like corruption.
    """
    import base64
    if ring.is_shredded(sealed.subject):
        raise ShredError(
            f"payload belongs to erased subject {sealed.subject!r}; the key was "
            "destroyed and the content is unrecoverable. The commitment remains "
            "valid, so any chain containing it still verifies.")
    _require()
    key = ring.key_for(sealed.subject, create=False)
    try:
        raw = AESGCM(key).decrypt(base64.b64decode(sealed.nonce),
                                  base64.b64decode(sealed.ciphertext),
                                  sealed.subject.encode("utf-8"))
    except Exception:
        raise ShredError("could not decrypt (wrong key or tampered ciphertext)")
    return json.loads(raw)


def commitment_survives(sealed: SealedPayload) -> bool:
    """
    The property the whole design rests on: after erasure the commitment still
    matches the ciphertext, so a chain built over it continues to verify.
    """
    import base64
    return digest(base64.b64decode(sealed.ciphertext)) == sealed.commitment


def pseudonymise(identifier: str, salt: bytes = b"") -> str:
    """
    Derive a stable subject id from a real identifier.

    This is pseudonymisation, NOT anonymisation: with the salt and a candidate
    identifier anyone can reproduce the output. It keeps names out of records
    that will be widely copied; it does not remove an erasure obligation, and
    the erasure mechanism is key destruction, not this.
    """
    return "sub_" + hashlib.sha256(salt + identifier.encode("utf-8")).hexdigest()[:32]


__all__ = ["KeyRing", "SealedPayload", "seal", "unseal", "commitment_survives",
           "pseudonymise", "digest", "ShredError", "SHRED_VERSION"]
