"""
trustfirewall.stateless — per-request identity for a stateless MCP.

WHY THIS EXISTS
---------------
The MCP 2026-07-28 specification removed protocol sessions. The `initialize`
handshake and the `Mcp-Session-Id` header are gone; every request is
self-describing, so any request can land on any server instance behind a plain
load balancer, including serverless and edge deployments.

That is a direct challenge to how XCP originally worked. XCP bound identity to a
*session* — `keccak256(DER(cert))` resolved once when a connection opened, then
reused for the life of that connection. In a world with no sessions, no sticky
routing and TLS often terminated at an edge, "verify once, reuse" has nowhere to
live.

The resolution is not to fight statelessness but to adopt it: replace session
state with a **credential that is itself the state**, minted per request and
cryptographically bound to the specific call being made.

    session id  →  a pointer to server-side state   (needs stickiness)
    credential  →  the state, signed and self-verifying (needs nothing)

This is strictly stronger than the session model it replaces. A stolen session
id was a bearer token for *everything* that session could do. A stolen request
credential is useless: it is bound to one method, one tool, one argument digest,
one short expiry window and one certificate footprint. Replay it against a
different tool and the binding check fails.

WHAT THE SPEC GAVE US
---------------------
MCP 2026-07-28 also made two headers mandatory on Streamable HTTP so gateways can
route and meter without opening the body:

    Mcp-Method: tools/call
    Mcp-Name:   search

Those map one-to-one onto XCP's existing scope grammar (`mcp:tools/<tool>`),
which means authorization can be decided from headers alone, at the speed a WAF
or rate limiter already works. That is what makes a "trust firewall" practical
rather than aspirational.

Status: XCP and ERC-8004x are draft proposals. MCP is a real, independent
specification by Anthropic and the MCP working group; this module targets the
2026-07-28 revision.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Mapping, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
    from eth_utils import keccak as _keccak
    _ETH = True
except ImportError:                                   # pragma: no cover
    _ETH = False

MCP_SPEC_TARGET = "2026-07-28"
CREDENTIAL_VERSION = 1

# Mandatory MCP 2026-07-28 routing headers.
H_MCP_METHOD = "mcp-method"
H_MCP_NAME = "mcp-name"
# XCP's own header, carrying the per-request credential.
H_XCP_CREDENTIAL = "xcp-request-credential"

# Removed by MCP 2026-07-28 — their presence signals a stale client.
LEGACY_HEADERS = ("mcp-session-id",)

# Deprecated in 2026-07-28 with a 12-month removal window.
DEPRECATED_METHODS = {
    "roots/list", "sampling/createMessage", "logging/setLevel",
    "notifications/message",
}


def digest(data: bytes) -> str:
    if _ETH:
        return "0x" + _keccak(data).hex()
    return "0x" + hashlib.sha3_256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


class CredentialError(Exception):
    pass


# ── scope derivation: MCP headers → XCP scope grammar ──────────────────────

def scope_for(mcp_method: str, mcp_name: str = "") -> str:
    """
    Translate the mandatory MCP 2026-07-28 headers into an XCP scope, with no
    reference to the request body.

        tools/call      + search   → mcp:tools/search
        tools/list                 → mcp:tools/list
        resources/read  + file://x → mcp:resources/read
        prompts/get     + greet    → mcp:prompts/greet

    The mapping is intentionally total: an unrecognised method still yields a
    scope string, so an unknown call is *denied by default* rather than
    silently allowed because no rule matched it.
    """
    method = (mcp_method or "").strip()
    name = (mcp_name or "").strip()
    if not method:
        return "mcp:unknown/"
    family, _, verb = method.partition("/")
    if method == "tools/call" and name:
        return f"mcp:tools/{name}"
    if method == "prompts/get" and name:
        return f"mcp:prompts/{name}"
    if family in ("tools", "resources", "prompts", "completion", "tasks"):
        return f"mcp:{family}/{verb or 'unknown'}"
    return f"mcp:{family or 'unknown'}/{verb or 'unknown'}"


def bind_digest(mcp_method: str, mcp_name: str, body: bytes = b"") -> str:
    """
    The replay binding: ties a credential to one exact call. Includes the body
    digest so the same credential cannot be reused with different arguments.
    """
    return digest(canonical({
        "m": (mcp_method or "").strip(),
        "n": (mcp_name or "").strip(),
        "b": digest(body or b""),
    }))


# ── the credential ─────────────────────────────────────────────────────────

@dataclass
class RequestCredential:
    """
    A signed, single-call, short-lived assertion of identity and authority.
    This is what replaces the session.
    """
    agent_id: int
    chain_id: int
    footprint: str                  # keccak256(DER(cert)) seen at the TLS edge
    tier: str                       # trust-lattice cell, e.g. "A2xH2"
    scope: str                      # the scope THIS request needs
    bind: str                       # bind_digest(method, name, body)
    exp: int                        # unix seconds — short (seconds, not days)
    nonce: str = field(default_factory=lambda: secrets.token_hex(8))
    flow: str = ""                  # links MRTR round trips into one logical call
    mandate_root: str = ""          # on-chain root the mandate proves against
    spend_cap_minor: int = 0
    version: int = CREDENTIAL_VERSION
    mcp_spec: str = MCP_SPEC_TARGET
    signer: str = ""
    sig: str = ""

    # ---- serialisation ----
    def payload(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("sig", None)
        d.pop("signer", None)
        return d

    def to_header(self) -> str:
        raw = canonical({**asdict(self)})
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @staticmethod
    def from_header(value: str) -> "RequestCredential":
        try:
            pad = "=" * (-len(value) % 4)
            raw = base64.urlsafe_b64decode(value + pad)
            return RequestCredential(**json.loads(raw))
        except Exception as e:
            raise CredentialError(f"malformed credential: {e}")

    def expired(self, now: Optional[int] = None) -> bool:
        return (now or int(time.time())) > self.exp


def mint(private_key: str, *, agent_id: int, chain_id: int, footprint: str,
         tier: str, mcp_method: str, mcp_name: str = "", body: bytes = b"",
         ttl_seconds: int = 60, flow: str = "", mandate_root: str = "",
         spend_cap_minor: int = 0, now: Optional[int] = None) -> RequestCredential:
    """
    Mint a credential for one call. TTL defaults to 60s: long enough for a
    retry, short enough that a captured credential is near-worthless even
    before the call binding is considered.
    """
    if not _ETH:
        raise CredentialError("eth-account required to mint credentials")
    now = now or int(time.time())
    cred = RequestCredential(
        agent_id=agent_id, chain_id=chain_id, footprint=footprint, tier=tier,
        scope=scope_for(mcp_method, mcp_name),
        bind=bind_digest(mcp_method, mcp_name, body),
        exp=now + max(1, ttl_seconds), flow=flow,
        mandate_root=mandate_root, spend_cap_minor=spend_cap_minor)
    acct = Account.from_key(private_key)
    msg = encode_defunct(text=digest(canonical(cred.payload())))
    sig = Account.sign_message(msg, private_key=private_key).signature.hex()
    cred.signer = acct.address
    cred.sig = sig if sig.startswith("0x") else "0x" + sig
    return cred


def verify(cred: RequestCredential, *, mcp_method: str, mcp_name: str = "",
           body: bytes = b"", expected_signer: str = "",
           now: Optional[int] = None, max_ttl: int = 300) -> list[str]:
    """
    Stateless verification. Needs no shared state and no prior request — which
    is exactly what lets it run on any instance, in any region, behind any load
    balancer, including a cold serverless invocation.

    Returns a list of problems; empty means the credential is valid for THIS
    call.
    """
    problems: list[str] = []
    now = now or int(time.time())

    if cred.version != CREDENTIAL_VERSION:
        problems.append(f"unsupported credential version {cred.version}")
    if cred.expired(now):
        problems.append("credential expired")
    if cred.exp - now > max_ttl:
        problems.append(f"credential ttl exceeds the {max_ttl}s ceiling")

    expected_scope = scope_for(mcp_method, mcp_name)
    if cred.scope != expected_scope:
        problems.append(
            f"scope mismatch: credential is for {cred.scope}, request is {expected_scope}")

    expected_bind = bind_digest(mcp_method, mcp_name, body)
    if cred.bind != expected_bind:
        problems.append("call binding mismatch — credential is not for this call "
                        "(replay or altered arguments)")

    if not cred.footprint.startswith("0x") or len(cred.footprint) < 34:
        problems.append("missing or malformed certificate footprint")

    if not cred.sig:
        problems.append("credential is unsigned")
    elif _ETH:
        try:
            msg = encode_defunct(text=digest(canonical(cred.payload())))
            rec = Account.recover_message(msg, signature=cred.sig)
            if cred.signer and rec.lower() != cred.signer.lower():
                problems.append("signature does not match the declared signer")
            if expected_signer and rec.lower() != expected_signer.lower():
                problems.append("signer is not the expected agent key")
        except Exception as e:
            problems.append(f"signature failed to recover: {e}")

    return problems


# ── request shape helpers ──────────────────────────────────────────────────

@dataclass
class McpRequest:
    """A stateless MCP request as the firewall sees it, headers-first."""
    method: str
    name: str = ""
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)

    @staticmethod
    def from_headers(headers: Mapping[str, str], body: bytes = b"") -> "McpRequest":
        h = {k.lower(): v for k, v in headers.items()}
        return McpRequest(method=h.get(H_MCP_METHOD, ""),
                          name=h.get(H_MCP_NAME, ""),
                          body=body, headers=h)

    @property
    def scope(self) -> str:
        return scope_for(self.method, self.name)

    def credential(self) -> Optional[RequestCredential]:
        raw = self.headers.get(H_XCP_CREDENTIAL, "")
        return RequestCredential.from_header(raw) if raw else None

    def legacy_signals(self) -> list[str]:
        """Detect clients still speaking the pre-2026-07-28 protocol."""
        out = []
        for h in LEGACY_HEADERS:
            if h in self.headers:
                out.append(f"{h} present — client predates MCP {MCP_SPEC_TARGET}")
        if self.method in DEPRECATED_METHODS:
            out.append(f"{self.method} is deprecated in MCP {MCP_SPEC_TARGET} "
                       "(12-month removal window)")
        return out


# ── MRTR: multi round-trip requests ────────────────────────────────────────

def new_flow() -> str:
    """
    MCP 2026-07-28 replaced server-pushed elicitation with Multi Round-Trip
    Requests: the server returns `input_required` with opaque state, the client
    answers and retries. That means one *logical* call can span several HTTP
    requests, each needing its own credential.

    A flow id links them, so audit and receipts record one logical call with N
    round trips rather than N unrelated calls.
    """
    return "flow-" + secrets.token_hex(6)


__all__ = [
    "RequestCredential", "McpRequest", "mint", "verify", "scope_for",
    "bind_digest", "new_flow", "digest", "canonical", "CredentialError",
    "H_MCP_METHOD", "H_MCP_NAME", "H_XCP_CREDENTIAL",
    "MCP_SPEC_TARGET", "CREDENTIAL_VERSION", "DEPRECATED_METHODS",
]
