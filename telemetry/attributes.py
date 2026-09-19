"""
telemetry.attributes — trust context on a span, without exporting your users.

WHY THIS FILE EXISTS BEFORE THE EXPORTER
----------------------------------------
Telemetry is a data-exfiltration path with a friendly name. Naive
instrumentation puts agent identifiers, the human principal's tier, tool names,
argument values and counterparty hostnames into spans, and then ships them to a
third-party observability vendor. That would:

  · create a new processor and, usually, an international transfer
  · contradict `privacy/` directly — transport commitments deliberately publish
    totals and never counterparties, and this would publish the counterparties
  · do it silently, because nobody reads the span schema

So the default here is **scrubbed**. Identifiers are pseudonymised with a
per-process salt, argument values never appear at all, and full detail is an
explicit opt-in (`XCP_OTEL_DETAIL=full`) for a self-hosted collector where the
operator has decided the trade.

WHAT IS WORTH RECORDING
-----------------------
A latency number tells you a call was slow. A trust-layer span should tell you
*why a call was refused*, which is the question an operator actually has. So the
attributes carry the decision and its reason, not just timing.

Attribute names follow OpenTelemetry semantic conventions where they exist
(`server.address`, `http.response.status_code`) and use an `xcp.*` namespace
where they do not.
"""

from __future__ import annotations

import hashlib
import os
from enum import Enum
from typing import Any, Optional

# Namespaced so a collector can drop or route them as a group.
NS = "xcp"

A_AGENT = f"{NS}.agent.id"
A_TIER = f"{NS}.trust.tier"
A_SCOPE = f"{NS}.scope"
A_DECISION = f"{NS}.decision"
A_REASON = f"{NS}.decision.reason"
A_STREAM = f"{NS}.stream"
A_POSTURE = f"{NS}.posture"
A_SERVER_CLASS = f"{NS}.server.trust_class"
A_LIMIT = f"{NS}.limit.kind"
A_MANDATE = f"{NS}.mandate.outcome"
A_VERIFIED_BY = f"{NS}.verified_by"
A_PEER = f"{NS}.peer.domain"
A_VERSION = f"{NS}.protocol.version"
A_CRYPTO_FAST = f"{NS}.crypto.fast_path"
A_DETAIL = f"{NS}.telemetry.detail"


class Detail(str, Enum):
    """How much a span is allowed to say."""
    SCRUBBED = "scrubbed"   # default: pseudonymous ids, no values, no hostnames
    HOSTS = "hosts"         # + counterparty hostnames, for routing diagnosis
    FULL = "full"           # + raw agent ids and scopes. Self-hosted only.


def detail_level() -> Detail:
    raw = (os.getenv("XCP_OTEL_DETAIL", "") or "scrubbed").strip().lower()
    try:
        return Detail(raw)
    except ValueError:
        return Detail.SCRUBBED


# Per-process salt. Rotating on restart is deliberate: it stops a vendor
# correlating one agent across deployments indefinitely, at the cost of
# correlation across restarts — which is the right trade for telemetry, where
# the useful window is hours rather than months.
_SALT = os.urandom(16)


def pseudonym(value: Any, prefix: str = "a") -> str:
    """
    Stable within a process, meaningless outside it.

    This is pseudonymisation, not anonymisation: it keeps raw identifiers out of
    a vendor's store while preserving the ability to say "these 400 denials were
    the same caller", which is the thing an operator needs at 3am.
    """
    if value in (None, "", 0):
        return ""
    h = hashlib.blake2s(_SALT + str(value).encode(), digest_size=6).hexdigest()
    return f"{prefix}_{h}"


def scrub_scope(scope: str, level: Optional[Detail] = None) -> str:
    """
    Keep the shape of a scope without the specifics.

        mcp:tools/patient_lookup  ->  mcp:tools/*

    The family is what you need for a dashboard; the tool name can identify a
    workload, a customer, or in the wrong domain a person.
    """
    level = level or detail_level()
    if level is Detail.FULL or not scope:
        return scope
    if ":" in scope and "/" in scope:
        head, _, _tail = scope.partition("/")
        return f"{head}/*"
    return scope.split(":")[0] + ":*" if ":" in scope else "*"


def call_attributes(*, agent_id: Any = None, tier: str = "", scope: str = "",
                    decision: str = "", reason: str = "", stream: str = "",
                    server_host: str = "", server_class: str = "",
                    limit_kind: str = "", mandate: str = "",
                    verified_by: str = "", peer: str = "",
                    level: Optional[Detail] = None) -> dict[str, Any]:
    """
    Build the attribute set for one governed call, honouring the detail level.

    Note what is absent at every level: tool arguments, result payloads, and the
    human principal's identity. Those are never recorded, not even at FULL —
    a debug flag should not be able to turn an observability pipeline into a
    personal-data pipeline.
    """
    level = level or detail_level()
    attrs: dict[str, Any] = {A_DETAIL: level.value}

    if agent_id not in (None, "", 0):
        attrs[A_AGENT] = (str(agent_id) if level is Detail.FULL
                          else pseudonym(agent_id))
    if tier:
        attrs[A_TIER] = tier            # a lattice cell is a category, not an id
    if scope:
        attrs[A_SCOPE] = scrub_scope(scope, level)
    if decision:
        attrs[A_DECISION] = decision
    if reason:
        attrs[A_REASON] = reason[:200]  # the point of the span
    if stream:
        attrs[A_STREAM] = stream
    if server_class:
        attrs[A_SERVER_CLASS] = server_class
    if limit_kind:
        attrs[A_LIMIT] = limit_kind
    if mandate:
        attrs[A_MANDATE] = mandate
    if verified_by:
        attrs[A_VERIFIED_BY] = verified_by

    if server_host:
        attrs["server.address"] = (server_host if level in (Detail.HOSTS, Detail.FULL)
                                   else pseudonym(server_host, "h"))
    if peer:
        attrs[A_PEER] = (peer if level in (Detail.HOSTS, Detail.FULL)
                         else pseudonym(peer, "p"))
    return attrs


#: Attributes a collector should drop if it forwards to a third party. Published
#: so the decision can be enforced in collector config rather than trusted.
SENSITIVE_AT_FULL = (A_AGENT, A_SCOPE, "server.address", A_PEER)


__all__ = ["Detail", "detail_level", "pseudonym", "scrub_scope",
           "call_attributes", "SENSITIVE_AT_FULL", "NS",
           "A_AGENT", "A_TIER", "A_SCOPE", "A_DECISION", "A_REASON",
           "A_STREAM", "A_POSTURE", "A_SERVER_CLASS", "A_LIMIT", "A_MANDATE",
           "A_VERIFIED_BY", "A_PEER", "A_VERSION", "A_CRYPTO_FAST", "A_DETAIL"]
