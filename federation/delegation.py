"""
federation.delegation — an agent in one datacentre asking an agent in another.

WHAT WAS WRONG
--------------
`/v1/a2a/delegate` authorised a delegation and said so. Independent review
(finding B.4.5) observed that it returned `accepted: True`, which a caller could
reasonably read as delivery, and nothing had been delivered: the handler's own
comment admitted "here we echo an accepted delegation". The fix at the time was
to stop making the claim -- it now returns `delivered: false` -- and §9.3 of the
draft was tightened to require it:

    Authorisation to delegate an action to another agent MUST NOT be reported
    as, or relied upon as, evidence that the action was delivered. The
    destination identity MUST authenticate independently before execution.

That was a correction to a false claim, not a capability. Cross-boundary A2A
did not exist. This module is the capability.

THE SHAPE
---------
The originating gateway mints a DelegationTicket, signed with its NODE key, that
says: *I verified this agent, at this tier, holding a mandate for this scope,
asking for this exact task.* The destination gateway redeems it, and redemption
is where the authentication happens:

    1. the ticket is signed by a node this destination already peers with
    2. that node is a member of the same cluster, if the cluster is closed
    3. the ticket names THIS destination as its audience, and has not expired
    4. the task digest matches the task actually presented
    5. the asserted tier is NARROWED under the destination's own ceiling
    6. the hop budget is not exhausted and the path has no loop

AUTHORITY NARROWS AT A BOUNDARY, NEVER WIDENS
---------------------------------------------
Step 5 is the one that matters, and it is the reason a ticket carries a tier at
all rather than the destination simply trusting the originator. The origin
asserts what it verified; the destination decides what that is worth HERE. A
ticket claiming A2xH2 gets A1xH1 at a destination whose ceiling is A1xH1, and
an originating datacentre cannot lift an agent above what the destination's own
entitlements allow.

This is the same invariant `trustfirewall/oauth_bridge.widens()` enforces when
an OAuth grant becomes a mandate, and that `trust/tiers._apply_entitlements`
enforces when an employer's IdP attributes meet a lattice cell -- "entitlements
may only restrict". Applied here to the hop between two datacentres, because a
trust boundary is exactly where a widening would be most useful to an attacker
and least visible to an operator.

WHAT A TICKET IS NOT
--------------------
It is not a credential for the destination's tools. It authorises one task, by
digest, for a bounded time. The destination still runs its own mandate gate,
its own argument firewall and its own limits against the narrowed tier: a
delegated call is a call, and arrives with less authority than a local one
rather than more.

Status: XCP is a draft proposal.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_utils import keccak as _keccak
    _ETH = True
except ImportError:                                   # pragma: no cover
    _ETH = False

DELEGATION_SPEC_VERSION = "0.1-draft"

#: A ticket is redeemed within seconds of being minted, by a gateway the
#: originator is already peered with. Longer buys nothing and widens replay.
DEFAULT_TICKET_TTL = 120

#: How many boundaries one delegation may cross. Three is the same ceiling the
#: federation already applies to transitive trust, for the same reason: beyond
#: it, nobody in the chain can reason about what they are participating in.
DEFAULT_MAX_HOPS = 3


def digest(data: bytes) -> str:
    if _ETH:
        return "0x" + _keccak(data).hex()
    return "0x" + hashlib.sha3_256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


class DelegationError(Exception):
    pass


def task_digest(task: Any) -> str:
    """
    Commit to the task, so a ticket authorises ONE task and not a shape of task.

    Canonical JSON rather than the raw bytes: the originator and the
    destination may serialise the same object differently, and a digest over
    whichever bytes happened to arrive would fail for two honest parties while
    a canonical one fails only for a changed task.
    """
    return digest(canonical(task if task is not None else {}))


# ── tiers ──────────────────────────────────────────────────────────────────

def canonical_tier(cell: str) -> str:
    """
    A lattice cell in exactly the spelling the lattice uses, "A2xH1".

    Case matters because the cell is a SIGNED field and is compared against
    `trust.tiers` cell strings. Normalising with .upper() produced "A2XH2",
    which compares unequal to the lattice's own "A2xH2" -- it first showed up
    as a ticket reporting that it had been narrowed when nothing had been.
    """
    a, h = parse_tier(cell)
    return format_tier(a, h)


def parse_tier(cell: str) -> tuple[int, int]:
    """"A2xH1" -> (2, 1). Strict: a tier that cannot be parsed is not a tier."""
    s = (cell or "").strip().upper()
    if len(s) != 5 or s[0] != "A" or s[2] != "X" or s[3] != "H":
        raise DelegationError(f"not a lattice cell: {cell!r}")
    if not (s[1].isdigit() and s[4].isdigit()):
        raise DelegationError(f"not a lattice cell: {cell!r}")
    a, h = int(s[1]), int(s[4])
    if not (0 <= a <= 2 and 0 <= h <= 2):
        raise DelegationError(f"lattice cell out of range: {cell!r}")
    return a, h


def format_tier(agent: int, human: int) -> str:
    return f"A{agent}xH{human}"


def narrow_tier(asserted: str, ceiling: str) -> str:
    """
    The weaker of two cells, leg by leg.

    Component-wise rather than by some ordering of the nine cells, because the
    two legs mean different things -- what backs the agent and what backs the
    human -- and a destination that caps the human leg has said nothing about
    the agent leg. A2xH2 under a ceiling of A1xH2 is A1xH2; under A2xH0 it is
    A2xH0.

    The lattice's own rule, that the effective ceiling is the weaker leg, is
    what makes this the right operation: narrowing either leg narrows the cell.
    """
    aa, ah = parse_tier(asserted)
    ca, ch = parse_tier(ceiling)
    return format_tier(min(aa, ca), min(ah, ch))


def widens(asserted: str, effective: str) -> bool:
    """True if `effective` grants more than `asserted` on either leg."""
    aa, ah = parse_tier(asserted)
    ea, eh = parse_tier(effective)
    return ea > aa or eh > ah


# ── the ticket ─────────────────────────────────────────────────────────────

@dataclass
class DelegationHop:
    """One boundary crossed. The path is signed, so it cannot be rewritten."""
    node_id: str
    domain: str
    at: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"nodeId": self.node_id, "domain": self.domain, "at": self.at}


@dataclass
class DelegationTicket:
    # who issued it, and what they are
    origin_node: str                 # node_id of the originating gateway
    origin_domain: str
    cluster_id: str = ""
    # what the origin verified about the caller
    agent_id: int = 0
    chain_id: int = 0
    footprint: str = ""
    asserted_tier: str = "A0xH0"
    # what is being delegated
    audience: str = ""               # the destination domain
    peer: str = ""                   # the destination AGENT, as the caller named it
    scope: str = ""
    task: str = ""                   # task_digest(task)
    # bounds
    hops: list = field(default_factory=list)
    max_hops: int = DEFAULT_MAX_HOPS
    issued_at: int = 0
    expires_at: int = 0
    nonce: str = ""
    spec_version: str = DELEGATION_SPEC_VERSION
    signature: str = ""

    @property
    def depth(self) -> int:
        return len(self.hops)

    def expired(self, now: Optional[int] = None) -> bool:
        return (now or int(time.time())) > self.expires_at

    def payload(self) -> dict[str, Any]:
        return {"originNode": self.origin_node,
                "originDomain": self.origin_domain.lower(),
                "clusterId": self.cluster_id, "agentId": self.agent_id,
                "chainId": self.chain_id, "footprint": self.footprint,
                "assertedTier": self.asserted_tier,
                "audience": self.audience.lower(), "peer": self.peer,
                "scope": self.scope, "task": self.task,
                # The PATH is signed, not just its length. A hop that could
                # rewrite history would hide where a delegation had been, and
                # the loop check below is only as good as the path it reads.
                "path": digest(canonical([h.to_dict() if isinstance(h, DelegationHop)
                                          else h for h in self.hops])),
                "maxHops": self.max_hops, "issuedAt": self.issued_at,
                "expiresAt": self.expires_at, "nonce": self.nonce}

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["hops"] = [h.to_dict() if isinstance(h, DelegationHop) else h
                     for h in self.hops]
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "DelegationTicket":
        if not isinstance(d, dict):
            raise DelegationError("ticket must be an object")
        known = set(DelegationTicket.__dataclass_fields__)
        try:
            kw = {k: v for k, v in d.items() if k in known}
            kw["hops"] = [DelegationHop(node_id=str(h["nodeId"]),
                                        domain=str(h["domain"]),
                                        at=int(h.get("at") or 0))
                          for h in (d.get("hops") or [])]
            return DelegationTicket(**kw)
        except (KeyError, TypeError, ValueError) as e:
            raise DelegationError(f"malformed ticket: {e}")


def _typed(payload: dict[str, Any], chain_id: int) -> dict:
    return {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"},
                             {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}],
            "DelegationTicket": [
                {"name": "originNode", "type": "string"},
                {"name": "originDomain", "type": "string"},
                {"name": "clusterId", "type": "string"},
                {"name": "agentId", "type": "uint256"},
                {"name": "chainId", "type": "uint256"},
                {"name": "footprint", "type": "string"},
                {"name": "assertedTier", "type": "string"},
                {"name": "audience", "type": "string"},
                {"name": "peer", "type": "string"},
                {"name": "scope", "type": "string"},
                {"name": "task", "type": "string"},
                {"name": "path", "type": "string"},
                {"name": "maxHops", "type": "uint64"},
                {"name": "issuedAt", "type": "uint64"},
                {"name": "expiresAt", "type": "uint64"},
                {"name": "nonce", "type": "string"}],
        },
        "primaryType": "DelegationTicket",
        "domain": {"name": "XCPDelegation", "version": "1",
                   "chainId": chain_id},
        "message": payload,
    }


def mint(node_key: str, *, origin_node: str, origin_domain: str,
         audience: str, agent_id: int, chain_id: int, footprint: str,
         asserted_tier: str, scope: str, task: Any, peer: str = "",
         cluster_id: str = "", hops: Optional[list] = None,
         max_hops: int = DEFAULT_MAX_HOPS, ttl: int = DEFAULT_TICKET_TTL,
         now: Optional[int] = None,
         eip712_chain_id: int = 8453) -> DelegationTicket:
    """
    Mint a ticket for one task, for one destination.

    Signed with the originating gateway's NODE key, not the agent's: the claim
    being made is "this gateway verified this agent", which only the gateway
    can honestly assert. The agent's own mandate was already checked upstream
    of this and is not re-presented across the boundary -- the destination has
    no way to verify a mandate rooted in the origin's registry, and a ticket it
    cannot check would be decoration.
    """
    if not _ETH:
        raise DelegationError("eth-account required to mint a delegation ticket")
    if not audience.strip():
        raise DelegationError("a ticket must name its destination")
    parse_tier(asserted_tier)
    if max_hops < 1:
        raise DelegationError("max_hops starts at 1")
    n = now or int(time.time())
    t = DelegationTicket(
        origin_node=origin_node, origin_domain=origin_domain.strip().lower(),
        cluster_id=cluster_id, agent_id=int(agent_id), chain_id=int(chain_id),
        footprint=footprint, asserted_tier=canonical_tier(asserted_tier),
        audience=audience.strip().lower(), peer=peer, scope=scope,
        task=task_digest(task), hops=list(hops or []), max_hops=max_hops,
        issued_at=n, expires_at=n + max(1, ttl),
        nonce=secrets.token_hex(16))
    sig = Account.sign_message(
        encode_typed_data(full_message=_typed(t.payload(), eip712_chain_id)),
        private_key=node_key).signature.hex()
    t.signature = sig if sig.startswith("0x") else "0x" + sig
    return t


@dataclass
class Admission:
    """The destination's own decision about a ticket."""
    admitted: bool
    effective_tier: str = ""
    problems: list = field(default_factory=list)
    narrowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"admitted": self.admitted,
                "effectiveTier": self.effective_tier,
                "narrowed": self.narrowed,
                "problems": list(self.problems)}


def admit(ticket: DelegationTicket, *, audience: str, self_node_id: str,
          ceiling: str = "A2xH2", task: Any = None,
          origin_is_peer: bool = False, origin_in_cluster: Optional[bool] = None,
          expected_cluster_id: str = "", max_ttl: int = DEFAULT_TICKET_TTL,
          now: Optional[int] = None, eip712_chain_id: int = 8453) -> Admission:
    """
    The destination's independent decision. Returns an Admission.

    `origin_is_peer` and `origin_in_cluster` are the caller's -- the gateway's
    -- answers about who signed this, because only it holds the peer table and
    the charter. Passing them in rather than reaching for globals keeps this
    function testable and keeps the gateway honest about what it checked.

    `origin_in_cluster=None` means the destination is not in a closed cluster
    and membership is not a condition. `False` means it is, and the originator
    is not a member.
    """
    problems: list[str] = []
    n = now or int(time.time())

    if ticket.audience.lower() != audience.strip().lower():
        # A ticket minted for one datacentre must not be redeemable at another,
        # or one captured ticket spends everywhere the origin peers.
        problems.append("ticket was minted for a different destination")
    if ticket.expired(n):
        problems.append("ticket has expired")
    if ticket.issued_at > n + 5:
        problems.append("ticket is issued in the future")
    if ticket.expires_at - ticket.issued_at > max_ttl:
        problems.append(
            f"ticket lives longer than {max_ttl}s; refusing a credential whose "
            f"expiry does not bound replay")

    if not origin_is_peer:
        # The whole premise. A ticket from a stranger is a stranger's assertion
        # about an agent nobody here has verified.
        problems.append(
            "the originating node is not a verified peer of this node")
    if origin_in_cluster is False:
        problems.append(
            "the originating node is not a member of this node's cluster")
    if expected_cluster_id and ticket.cluster_id and \
            ticket.cluster_id.lower() != expected_cluster_id.lower():
        problems.append("ticket names a different cluster")

    if task is not None and task_digest(task) != ticket.task:
        # Otherwise a ticket authorises a shape of task rather than one task,
        # and whoever carries it chooses what gets run.
        problems.append("the task presented is not the task the ticket "
                        "authorises")

    if ticket.depth >= ticket.max_hops:
        problems.append(
            f"delegation budget exhausted: the originator permitted "
            f"{ticket.max_hops} hop(s) and this is hop {ticket.depth + 1}")
    seen = {ticket.origin_node.lower()}
    for h in ticket.hops:
        seen.add((h.node_id if isinstance(h, DelegationHop)
                  else h.get("nodeId", "")).lower())
    if self_node_id.lower() in seen:
        # A cycle would let two datacentres pass a delegation back and forth
        # until the budget ran out, each one believing the other had checked it.
        problems.append("this node is already on the delegation path; "
                        "refusing a loop")

    if not ticket.signature:
        problems.append("ticket is unsigned")
    elif _ETH:
        try:
            rec = Account.recover_message(
                encode_typed_data(
                    full_message=_typed(ticket.payload(), eip712_chain_id)),
                signature=bytes.fromhex(ticket.signature[2:]))
        except Exception as e:                      # noqa: BLE001
            problems.append(f"ticket signature is malformed: {type(e).__name__}")
        else:
            from .identity import node_id_from_address
            if node_id_from_address(rec).lower() != ticket.origin_node.lower():
                problems.append(
                    "ticket is not signed by the node it claims to come from")

    # The narrowing. Computed even when the ticket is refused, so an operator
    # reading an audit line can see what it WOULD have been granted.
    effective, narrowed = "", False
    try:
        effective = narrow_tier(ticket.asserted_tier, ceiling)
        narrowed = effective != canonical_tier(ticket.asserted_tier)
    except DelegationError as e:
        problems.append(str(e))

    if effective and widens(ticket.asserted_tier, effective):
        # Unreachable by construction -- narrow_tier takes a minimum per leg --
        # and asserted anyway. This is the invariant the whole module exists
        # for, and the cost of checking it is nothing against the cost of it
        # ever being wrong.
        problems.append("INVARIANT: narrowing produced a wider tier")

    return Admission(admitted=not problems, effective_tier=effective,
                     problems=problems, narrowed=narrowed)


def extend(ticket: DelegationTicket, *, node_id: str, domain: str,
           now: Optional[int] = None) -> DelegationTicket:
    """
    Record this node on the path, for a delegation that continues onward.

    Returns an UNSIGNED ticket: the next hop must be minted by whoever extends
    it, because a path is only trustworthy if each entry was signed by the node
    that added it. A caller that merely appends and forwards produces a ticket
    whose signature no longer matches its path, and `admit` refuses it.
    """
    n = now or int(time.time())
    out = DelegationTicket.from_dict(ticket.to_dict())
    out.hops = list(out.hops) + [DelegationHop(node_id=node_id, domain=domain,
                                               at=n)]
    out.signature = ""
    return out


__all__ = ["DELEGATION_SPEC_VERSION", "DEFAULT_TICKET_TTL", "DEFAULT_MAX_HOPS",
           "DelegationError", "DelegationHop", "DelegationTicket", "Admission",
           "mint", "admit", "extend", "task_digest", "parse_tier",
           "format_tier", "canonical_tier", "narrow_tier", "widens",
           "digest", "canonical"]
