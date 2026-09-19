"""
trustfirewall.oauth_bridge — derive an XCP mandate from an OAuth 2.0 grant.

WHY THIS EXISTS
---------------
XCP's adoption cost is dominated by one question an enterprise asks early: do
we have to stand up a second authority? The answer should be no. Almost every
organisation deploying agents already runs OAuth, and the authority they need
is already granted -- what is missing is the binding of that authority to the
individual requests that exercise it.

So a mandate is DERIVED from a grant rather than established alongside one.

THE INVARIANT
-------------
Derivation narrows. It never widens.

A mechanism that can enlarge an existing grant is a privilege escalation path
whatever it is called, and the failure would be quiet: an operator would see a
mandate that looked authoritative and never learn it exceeded the token behind
it. Every path here is written so that widening is impossible rather than
merely discouraged, and the tests attack that property directly.

WHAT THIS IS NOT
----------------
Not a token validator. The caller MUST have already validated the access token
by its own means -- signature, issuer, audience, expiry, introspection. This
takes an ALREADY-VALIDATED set of claims and computes what XCP may permit on
their basis. Accepting an unvalidated token here would move token validation
into a component that has no business performing it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional


class GrantError(Exception):
    pass


@dataclass
class Grant:
    """
    An already-validated OAuth 2.0 grant, as claims.

    Field names follow [RFC9068] (JWT access tokens) and [RFC8693] (token
    exchange) so that the mapping is inspectable against the RFCs rather than
    against this file.
    """
    sub: str = ""                       # the principal
    scope: str = ""                     # space-delimited, RFC 6749 §3.3
    exp: int = 0
    client_id: str = ""
    act: Optional[dict] = None          # RFC 8693 actor chain
    aud: Any = None
    extra: dict = field(default_factory=dict)

    @property
    def scopes(self) -> list[str]:
        return [s for s in (self.scope or "").split(" ") if s]

    def actor_chain(self) -> list[str]:
        """
        Flatten the nested RFC 8693 "act" claim, outermost first.

        The nesting is the representation that makes splicing possible: an
        attacker inserting an entry acquires the authority of the entry above
        it. Flattening it is the precondition for binding the whole path, which
        is what makes insertion detectable.
        """
        chain: list[str] = []
        node = self.act
        seen = 0
        while isinstance(node, dict) and seen < 16:
            sub = node.get("sub")
            if sub:
                chain.append(str(sub))
            node = node.get("act")
            seen += 1
        return chain


#: How an OAuth scope maps into an XCP scope. Deliberately explicit rather than
#: pattern-derived: a mapping an operator cannot read is a mapping they cannot
#: audit, and this one decides what an agent may do.
DEFAULT_SCOPE_MAP: dict[str, tuple[str, ...]] = {
    "read":    ("mcp:tools/search", "mcp:tools/fetch", "mcp:resources/read"),
    "write":   ("mcp:tools/create", "mcp:tools/update"),
    "tools":   ("mcp:tools/*",),
    "payments": ("pay:x402/*",),
}


def map_scopes(grant: Grant,
               scope_map: Optional[dict[str, tuple[str, ...]]] = None,
               passthrough_prefixes: tuple[str, ...] = ("mcp:", "pay:", "a2a:")
               ) -> list[str]:
    """
    Translate OAuth scopes into XCP scopes.

    An OAuth scope with no mapping yields NOTHING. It is not passed through on
    the assumption that an unrecognised scope is harmless -- an unrecognised
    scope is an unknown authority, and defaulting unknown authority to
    permitted is the failure this whole layer exists to prevent.
    """
    m = scope_map or DEFAULT_SCOPE_MAP
    out: list[str] = []
    for s in grant.scopes:
        if s in m:
            out.extend(m[s])
        elif s.startswith(passthrough_prefixes):
            out.append(s)               # already an XCP scope, carried as-is
    seen: set[str] = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def derive_mandate(grant: Grant, *, requested_scope: Optional[list[str]] = None,
                   max_ttl: int = 3600, now: Optional[int] = None,
                   scope_map: Optional[dict] = None) -> dict[str, Any]:
    """
    Build an XCP mandate from a validated grant.

    `requested_scope` lets a caller ask for LESS than the grant allows, which
    is encouraged. Asking for more is silently impossible: the result is
    intersected with what the grant conveys, never unioned.
    """
    n = now or int(time.time())
    if not grant.sub:
        raise GrantError("grant has no subject; a mandate must name a principal")
    if grant.exp and grant.exp <= n:
        raise GrantError("grant has expired")

    allowed = map_scopes(grant, scope_map)
    if not allowed:
        raise GrantError(
            "grant conveys no XCP-recognised scope; refusing to issue a mandate "
            "that would permit nothing while appearing to permit something")

    if requested_scope is not None:
        # Intersection, never union. This is the narrowing invariant.
        allowed = [s for s in allowed if s in set(requested_scope)]
        if not allowed:
            raise GrantError("requested scope is disjoint from the grant")

    # The mandate cannot outlive the token it derives from.
    not_after = n + max_ttl
    if grant.exp:
        not_after = min(not_after, grant.exp)

    chain = grant.actor_chain()
    return {
        "mandateId": f"oauth:{grant.client_id or 'client'}:{n}",
        "principal": grant.sub,
        "mandateScope": allowed,
        "notAfter": not_after,
        "derivedFrom": "oauth2",
        "delegationPath": chain,
        "proof": [],
        "signature": "",
    }


def widens(grant: Grant, mandate: dict[str, Any],
           scope_map: Optional[dict] = None) -> list[str]:
    """
    Check that a mandate does not exceed its grant. Returns violations.

    Exposed as a standalone check so a verifier can apply it to a mandate it
    did not derive itself -- including one an intermediary claims to have
    derived correctly.
    """
    problems: list[str] = []
    allowed = set(map_scopes(grant, scope_map))
    for s in mandate.get("mandateScope") or []:
        if s not in allowed:
            problems.append(f"mandate scope {s!r} is not conveyed by the grant")
    if mandate.get("principal") and grant.sub and \
            mandate["principal"] != grant.sub:
        problems.append("mandate names a principal the grant does not")
    if grant.exp and int(mandate.get("notAfter") or 0) > grant.exp:
        problems.append("mandate outlives the grant it derives from")
    return problems


__all__ = ["Grant", "derive_mandate", "map_scopes", "widens",
           "DEFAULT_SCOPE_MAP", "GrantError"]
