"""
trustfirewall.limits — abuse controls for a node that routes for strangers.

WHY THIS IS NOT OPTIONAL
------------------------
A gateway published in a discovery catalog, routing calls on behalf of callers
it has never met, with no rate limit, is an **open relay**. That is not a
theoretical risk: open SMTP relays, open DNS resolvers and open S3 buckets all
became abuse infrastructure within weeks of being discoverable, and this node is
designed to be discovered.

For a project whose whole claim is to be the trust layer, seeding a federation
with a DDoS reflector would be maximally self-defeating.

CAPACITY FOLLOWS AUTHORITY
--------------------------
The trust lattice already encodes how much authority a caller has. It should
encode how much capacity they get, for the same reason: an anonymous agent on an
ephemeral keypair has not earned the right to consume a node's budget, and a
company-backed agent under an enterprise principal has something to lose.

    A0xH0  sandbox            a trickle, tiny burst      no settlement anyway
    A1xH1  consumer commerce  a working allowance
    A2xH2  full settlement    a real allowance
    unverified/anonymous      the harshest bucket        this is where abuse lives

FOUR LIMITS, NOT ONE
--------------------
Rate alone is insufficient, because the failure modes differ:

  · rate        stops sustained flooding
  · burst       absorbs legitimate spikes without becoming a flood
  · concurrency stops slow-loris and connection exhaustion, which a request/sec
                limit does not touch at all
  · body size   stops a single request from consuming the node

Plus a **global ceiling** independent of tiers: many legitimate high-tier callers
can still saturate a node, and a node that dies serving trusted traffic is just
as down as one killed by an attacker.

COST-WEIGHTED
-------------
A `tools/list` and a `t2t:chain` across three hops are not the same thing to
serve. Limits are charged in cost units, not request counts, so an expensive
call consumes proportionally more of the allowance.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional

# Per-request cost in units. Charging every call the same would let the most
# expensive operations through at the same rate as the cheapest.
COST: dict[str, int] = {
    "tools/list": 1,
    "resources/list": 1,
    "prompts/list": 1,
    "resources/read": 2,
    "prompts/get": 2,
    "completion/complete": 2,
    "tools/call": 5,
    "a2a:delegate": 8,
    "t2t:chain": 12,          # multi-hop: the node pays for every leg
    "wrap": 8,                # a generated wrapper adds an upstream round trip
    "_default": 5,
}


@dataclass(frozen=True)
class Allowance:
    """What one tier may consume."""
    rate_per_min: int         # sustained cost units per minute
    burst: int                # bucket depth; absorbs spikes
    concurrency: int          # simultaneous in-flight requests
    max_body_bytes: int       # per request

    @property
    def refill_per_sec(self) -> float:
        return self.rate_per_min / 60.0


# Keyed by lattice cell. Anonymous callers do not appear here and get ANONYMOUS.
ALLOWANCES: dict[str, Allowance] = {
    "A0xH0": Allowance(rate_per_min=60,     burst=30,    concurrency=2,  max_body_bytes=64 * 1024),
    "A0xH1": Allowance(rate_per_min=300,    burst=150,   concurrency=4,  max_body_bytes=256 * 1024),
    "A0xH2": Allowance(rate_per_min=120,    burst=60,    concurrency=2,  max_body_bytes=64 * 1024),
    "A1xH0": Allowance(rate_per_min=600,    burst=300,   concurrency=8,  max_body_bytes=1024 * 1024),
    "A1xH1": Allowance(rate_per_min=3_000,  burst=1_000, concurrency=16, max_body_bytes=4 * 1024 * 1024),
    "A1xH2": Allowance(rate_per_min=6_000,  burst=2_000, concurrency=32, max_body_bytes=8 * 1024 * 1024),
    "A2xH0": Allowance(rate_per_min=3_000,  burst=1_000, concurrency=16, max_body_bytes=4 * 1024 * 1024),
    "A2xH1": Allowance(rate_per_min=6_000,  burst=2_000, concurrency=32, max_body_bytes=8 * 1024 * 1024),
    "A2xH2": Allowance(rate_per_min=30_000, burst=10_000, concurrency=64, max_body_bytes=16 * 1024 * 1024),
}

# Unverified or anonymous. Deliberately austere: this is where abuse arrives.
ANONYMOUS = Allowance(rate_per_min=20, burst=10, concurrency=1,
                      max_body_bytes=32 * 1024)


class LimitError(Exception):
    pass


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    retry_after: int = 0          # seconds, for a 429
    limit: str = ""               # which limit bit: rate | concurrency | body | global
    tier: str = ""
    cost: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason,
                "retryAfter": self.retry_after, "limit": self.limit,
                "tier": self.tier, "cost": self.cost}


class _Bucket:
    """Token bucket in cost units."""

    __slots__ = ("tokens", "updated", "inflight")

    def __init__(self, burst: int) -> None:
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self.inflight = 0

    def take(self, cost: int, a: Allowance, now: float) -> tuple[bool, int]:
        self.tokens = min(float(a.burst),
                          self.tokens + (now - self.updated) * a.refill_per_sec)
        self.updated = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True, 0
        deficit = cost - self.tokens
        return False, max(1, int(deficit / max(a.refill_per_sec, 1e-9)) + 1)


class RateLimiter:
    """
    Per-caller limits with a global ceiling.

        lim = RateLimiter(global_rate_per_min=120_000)
        d = lim.check(agent_key="42001", tier="A2xH2",
                      method="tools/call", body_bytes=len(body))
        if not d.allowed:
            return 429, {"Retry-After": str(d.retry_after)}
        with lim.hold(agent_key="42001", tier="A2xH2"):
            ...

    Thread-safe. Bounded memory by construction: the tracked-caller table is an
    LRU, because a limiter keyed on an attacker-supplied identifier is itself a
    memory-exhaustion vector if it grows without limit.
    """

    def __init__(self, *, global_rate_per_min: int = 120_000,
                 global_burst: int = 40_000, global_concurrency: int = 256,
                 max_tracked: int = 50_000, fail_closed: bool = True) -> None:
        self._buckets: "OrderedDict[str, _Bucket]" = OrderedDict()
        self._lock = threading.Lock()
        self._max_tracked = max_tracked
        self._fail_closed = fail_closed
        self._global = Allowance(global_rate_per_min, global_burst,
                                 global_concurrency, 1 << 62)
        self._global_bucket = _Bucket(global_burst)
        self._global_inflight = 0
        self.rejections: dict[str, int] = {}

    # ---- policy ----
    @staticmethod
    def allowance(tier: str) -> Allowance:
        return ALLOWANCES.get(tier or "", ANONYMOUS)

    @staticmethod
    def cost_of(method: str, scope: str = "") -> int:
        if scope.startswith("t2t:"):
            return COST["t2t:chain"]
        if scope.startswith("a2a:"):
            return COST["a2a:delegate"]
        return COST.get(method, COST["_default"])

    def _evict(self) -> None:
        while len(self._buckets) > self._max_tracked:
            # drop the least recently used caller that has nothing in flight
            for k, b in list(self._buckets.items()):
                if b.inflight == 0:
                    self._buckets.pop(k, None)
                    break
            else:
                break

    def _count(self, kind: str) -> None:
        self.rejections[kind] = self.rejections.get(kind, 0) + 1

    # ---- the check ----
    def check(self, *, agent_key: str, tier: str = "", method: str = "",
              scope: str = "", body_bytes: int = 0,
              now: Optional[float] = None) -> Decision:
        a = self.allowance(tier)
        cost = self.cost_of(method, scope)
        now = now if now is not None else time.monotonic()
        key = f"{tier}|{agent_key or 'anonymous'}"

        if body_bytes > a.max_body_bytes:
            self._count("body")
            return Decision(False, f"request body exceeds {a.max_body_bytes} bytes "
                                   f"for tier {tier or 'anonymous'}",
                            limit="body", tier=tier, cost=cost)
        try:
            with self._lock:
                # global ceiling first: a node dying under trusted traffic is
                # just as down as one killed by an attacker
                ok, retry = self._global_bucket.take(cost, self._global, now)
                if not ok:
                    self._count("global")
                    return Decision(False, "node is at capacity", retry_after=retry,
                                    limit="global", tier=tier, cost=cost)
                if self._global_inflight >= self._global.concurrency:
                    self._count("global_concurrency")
                    return Decision(False, "node concurrency ceiling reached",
                                    retry_after=1, limit="global", tier=tier, cost=cost)

                b = self._buckets.get(key)
                if b is None:
                    b = _Bucket(a.burst)
                    self._buckets[key] = b
                    self._evict()
                self._buckets.move_to_end(key)

                if b.inflight >= a.concurrency:
                    self._count("concurrency")
                    return Decision(False,
                                    f"{a.concurrency} concurrent requests already in "
                                    f"flight for this caller", retry_after=1,
                                    limit="concurrency", tier=tier, cost=cost)
                ok, retry = b.take(cost, a, now)
                if not ok:
                    self._count("rate")
                    return Decision(False,
                                    f"rate limit for tier {tier or 'anonymous'} "
                                    f"({a.rate_per_min}/min)", retry_after=retry,
                                    limit="rate", tier=tier, cost=cost)
        except Exception as e:                       # limiter itself failed
            if self._fail_closed:
                # A public node cannot fail open: that turns any limiter bug into
                # an abuse bypass. A private deployment may prefer availability.
                return Decision(False, f"limiter unavailable: {type(e).__name__}",
                                retry_after=5, limit="global", tier=tier)
            return Decision(True, "limiter unavailable; failing open", tier=tier)
        return Decision(True, tier=tier, cost=cost)

    # ---- concurrency tracking ----
    def hold(self, *, agent_key: str, tier: str = "") -> "_Hold":
        return _Hold(self, f"{tier}|{agent_key or 'anonymous'}")

    def _acquire(self, key: str) -> None:
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(self.allowance(key.split("|", 1)[0]).burst)
                self._buckets[key] = b
            b.inflight += 1
            self._global_inflight += 1

    def _release(self, key: str) -> None:
        with self._lock:
            b = self._buckets.get(key)
            if b is not None and b.inflight > 0:
                b.inflight -= 1
            if self._global_inflight > 0:
                self._global_inflight -= 1

    # ---- introspection ----
    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {"trackedCallers": len(self._buckets),
                    "maxTracked": self._max_tracked,
                    "globalInflight": self._global_inflight,
                    "globalConcurrency": self._global.concurrency,
                    "failClosed": self._fail_closed,
                    "rejections": dict(self.rejections)}


class _Hold:
    def __init__(self, limiter: RateLimiter, key: str) -> None:
        self._l, self._k = limiter, key

    def __enter__(self) -> "_Hold":
        self._l._acquire(self._k)
        return self

    def __exit__(self, *exc: Any) -> None:
        self._l._release(self._k)


__all__ = ["RateLimiter", "Allowance", "Decision", "LimitError",
           "ALLOWANCES", "ANONYMOUS", "COST"]
