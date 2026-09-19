"""
trustfirewall.delegation — authority that can be passed on, and only downward.

THE PROBLEM
-----------
Sealed credentials solved custody: a caller encrypts an upstream secret to the
wrapper that needs it, so the gateway forwards ciphertext it cannot read. That
works for one hop. It does not work for the workflows people actually build,
where an agent calls an agent that calls a tool, because the original caller
would have to hold a key for every wrapper in a chain it may not know in advance.

The naive fix is to let the first hop re-issue authority downstream. That is also
how delegation systems become authority-laundering machines: each hop grants what
it was given, and somewhere down the chain a capability appears that nobody
upstream actually approved.

WHAT THIS ENFORCES
------------------
A delegation is a signed link from one agent to the next, and every link is
checked against three invariants that hold for the whole chain:

  · **Scope narrows monotonically.** Each hop may pass on a subset of what it
    holds, never a superset. There is no operation that widens authority.
  · **Depth is bounded and declared.** The root sets the maximum hops. A chain
    cannot extend itself by adding another link.
  · **Lifetime never extends.** Each link expires no later than its parent, so
    a long-lived delegation cannot be manufactured from a short-lived one.

The result is that the root principal's grant is an upper bound on everything
that happens beneath it, and a verifier can establish that from the chain alone
without consulting any of the intermediate parties.

WHAT THIS DOES NOT DO
---------------------
It does not make an intermediate hop trustworthy. A hop that holds authority can
use it — that is what holding authority means. What the chain guarantees is that
it cannot use *more* than it was given, and that whatever it did is attributable
to a specific link that a named party signed.

Status: XCP is a draft proposal.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    _ETH = True
except ImportError:                                   # pragma: no cover
    _ETH = False

MAX_DEPTH = 5
DEFAULT_TTL = 300


class DelegationError(Exception):
    pass


def _digest(obj: Any) -> str:
    return "0x" + hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass
class Link:
    """One hop. Signed by the delegator, naming exactly what it passes on."""
    delegator: str            # agent id or node id issuing this link
    delegate: str             # who receives it
    scopes: tuple[str, ...]   # must be a subset of the parent's scopes
    not_after: int
    depth: int                # 0 for the root grant
    max_depth: int = MAX_DEPTH
    parent: str = ""          # digest of the link above; "" at the root
    reversibility_cap: str = "reversible"
    signer: str = ""
    signature: str = ""

    def payload(self) -> dict[str, Any]:
        return {"delegator": self.delegator, "delegate": self.delegate,
                "scopes": list(self.scopes), "notAfter": self.not_after,
                "depth": self.depth, "maxDepth": self.max_depth,
                "parent": self.parent,
                "reversibilityCap": self.reversibility_cap}

    @property
    def digest(self) -> str:
        return _digest(self.payload())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["scopes"] = list(self.scopes)
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Link":
        known = set(Link.__dataclass_fields__)
        kw = {k: v for k, v in d.items() if k in known}
        kw["scopes"] = tuple(kw.get("scopes", ()))
        return Link(**kw)


def _typed(payload: dict[str, Any], chain_id: int) -> dict:
    return {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"},
                             {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}],
            "Delegation": [
                {"name": "delegator", "type": "string"},
                {"name": "delegate", "type": "string"},
                {"name": "scopeDigest", "type": "string"},
                {"name": "notAfter", "type": "uint64"},
                {"name": "depth", "type": "uint8"},
                {"name": "maxDepth", "type": "uint8"},
                {"name": "parent", "type": "string"},
                {"name": "reversibilityCap", "type": "string"}],
        },
        "primaryType": "Delegation",
        "domain": {"name": "XCPDelegation", "version": "1", "chainId": chain_id},
        "message": {
            "delegator": payload["delegator"], "delegate": payload["delegate"],
            "scopeDigest": _digest(sorted(payload["scopes"])),
            "notAfter": payload["notAfter"], "depth": payload["depth"],
            "maxDepth": payload["maxDepth"], "parent": payload["parent"],
            "reversibilityCap": payload["reversibilityCap"]},
    }


def sign_link(private_key: str, link: Link, chain_id: int = 8453) -> Link:
    if not _ETH:
        raise DelegationError("eth-account required to sign a delegation")
    acct = Account.from_key(private_key)
    sig = Account.sign_message(
        encode_typed_data(full_message=_typed(link.payload(), chain_id)),
        private_key=private_key).signature.hex()
    link.signer = acct.address
    link.signature = sig if sig.startswith("0x") else "0x" + sig
    return link


def grant(private_key: str, *, delegator: str, delegate: str,
          scopes: Iterable[str], ttl: int = DEFAULT_TTL,
          max_depth: int = MAX_DEPTH, reversibility_cap: str = "reversible",
          now: Optional[int] = None, chain_id: int = 8453) -> Link:
    """Issue a root grant. This is the ceiling for everything beneath it."""
    n = now or int(time.time())
    return sign_link(private_key, Link(
        delegator=delegator, delegate=delegate, scopes=tuple(sorted(set(scopes))),
        not_after=n + ttl, depth=0, max_depth=max(1, min(max_depth, MAX_DEPTH)),
        parent="", reversibility_cap=reversibility_cap), chain_id)


def extend(private_key: str, parent: Link, *, delegate: str,
           scopes: Iterable[str], ttl: Optional[int] = None,
           reversibility_cap: Optional[str] = None,
           now: Optional[int] = None, chain_id: int = 8453) -> Link:
    """
    Pass a subset onward. Refuses at the point of issue rather than leaving an
    invalid link to be caught later — an authority that cannot be created is
    safer than one that merely fails to verify.
    """
    n = now or int(time.time())
    want = set(scopes)
    held = set(parent.scopes)
    if not want:
        raise DelegationError("a delegation with no scopes grants nothing")
    if not want <= held:
        raise DelegationError(
            f"cannot delegate scopes the delegator does not hold: "
            f"{sorted(want - held)}")
    if parent.depth + 1 >= parent.max_depth:
        raise DelegationError(
            f"delegation depth {parent.max_depth} reached; a chain cannot "
            "extend its own limit")
    not_after = min(parent.not_after, n + (ttl or DEFAULT_TTL))
    if not_after <= n:
        raise DelegationError("parent delegation has already expired")

    order = ("reversible", "recoverable", "costly", "irreversible")
    cap = reversibility_cap or parent.reversibility_cap
    if order.index(cap) > order.index(parent.reversibility_cap):
        raise DelegationError(
            f"cannot raise the reversibility cap from "
            f"{parent.reversibility_cap} to {cap}")

    return sign_link(private_key, Link(
        delegator=parent.delegate, delegate=delegate,
        scopes=tuple(sorted(want)), not_after=not_after,
        depth=parent.depth + 1, max_depth=parent.max_depth,
        parent=parent.digest, reversibility_cap=cap), chain_id)


def verify_chain(chain: list[Link], *, required_scope: str = "",
                 now: Optional[int] = None,
                 chain_id: int = 8453) -> list[str]:
    """
    Check a whole chain, root first. Returns problems; empty means the final
    delegate genuinely holds what it claims.
    """
    problems: list[str] = []
    n = now or int(time.time())
    if not chain:
        return ["empty delegation chain"]
    if chain[0].depth != 0 or chain[0].parent:
        problems.append("chain does not start at a root grant")

    for i, link in enumerate(chain):
        if link.not_after <= n:
            problems.append(f"link {i} has expired")
        if not link.signature:
            problems.append(f"link {i} is unsigned")
        elif _ETH:
            try:
                rec = Account.recover_message(
                    encode_typed_data(
                        full_message=_typed(link.payload(), chain_id)),
                    signature=link.signature)
                if link.signer and rec.lower() != link.signer.lower():
                    problems.append(f"link {i} signature does not match signer")
            except Exception as e:
                problems.append(f"link {i} signature failed to recover: {e}")

        if i == 0:
            continue
        prev = chain[i - 1]
        if link.parent != prev.digest:
            problems.append(f"link {i} does not follow link {i-1}")
        if link.delegator != prev.delegate:
            problems.append(
                f"link {i} is issued by {link.delegator}, but link {i-1} "
                f"delegated to {prev.delegate}")
        if not set(link.scopes) <= set(prev.scopes):
            problems.append(
                f"link {i} WIDENS scope beyond its parent: "
                f"{sorted(set(link.scopes) - set(prev.scopes))}")
        if link.not_after > prev.not_after:
            problems.append(f"link {i} outlives its parent")
        if link.depth != prev.depth + 1:
            problems.append(f"link {i} has a non-sequential depth")
        if link.max_depth != prev.max_depth:
            problems.append(f"link {i} changes the depth limit")

    if len(chain) > chain[0].max_depth:
        problems.append("chain is longer than the root permitted")
    if required_scope and required_scope not in set(chain[-1].scopes):
        problems.append(
            f"the final delegate does not hold {required_scope!r}")
    return problems


def effective_scopes(chain: list[Link]) -> set[str]:
    """What the last delegate actually holds: the intersection of every hop."""
    if not chain:
        return set()
    out = set(chain[0].scopes)
    for link in chain[1:]:
        out &= set(link.scopes)
    return out


def principal_of(chain: list[Link]) -> str:
    """Who is ultimately accountable. Always the root, never an intermediary."""
    return chain[0].delegator if chain else ""


__all__ = ["Link", "grant", "extend", "verify_chain", "effective_scopes",
           "principal_of", "sign_link", "DelegationError", "MAX_DEPTH"]
