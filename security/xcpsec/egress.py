"""
security.xcpsec.egress — refuse to fetch what an attacker chose.

FOUND IN AUDIT (XCP-A-03)
-------------------------
`/v1/federation/peer` accepted a `gatewayUrl` from an unauthenticated caller and
fetched it. That is server-side request forgery in its textbook form: the gateway
sits inside a trusted network, so an attacker who cannot reach a cloud metadata
service, an internal admin panel, or a database can ask the gateway to reach it
for them. The endpoint also returned the fetch error verbatim, which turns a
blind SSRF into an oracle that leaks response detail.

The fix is not a blocklist of strings. `http://169.254.169.254` is easy to catch
and useless as a defence: an attacker can use a decimal-encoded address, a
redirect from a benign host, or a DNS name that resolves to a private range.
Filtering has to happen on the RESOLVED ADDRESS, and it has to happen again on
every redirect hop.

WHAT THIS ENFORCES
------------------
  · scheme is https, unless the operator explicitly allows plain HTTP for dev
  · the hostname resolves only to public, routable addresses
  · every redirect target is re-checked, not just the first URL
  · responses are size-capped, so a fetch cannot exhaust memory
  · errors are generic, so failures do not become an information oracle

Status: XCP is a draft proposal.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

#: Extra ranges that are routable but should never be a federation peer.
_EXTRA_DENY = (
    ipaddress.ip_network("169.254.0.0/16"),    # link-local: cloud metadata
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100.64.0.0/10"),     # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped IPv6
)

MAX_FETCH_BYTES = 256 * 1024
MAX_REDIRECTS = 3


class EgressDenied(Exception):
    """Raised when a URL must not be fetched. The message is deliberately
    coarse: a precise reason tells an attacker what the network looks like."""


@dataclass(frozen=True)
class EgressPolicy:
    allow_http: bool = False          # plain HTTP, for local development only
    allow_private: bool = False       # private ranges, for local development only
    max_bytes: int = MAX_FETCH_BYTES
    max_redirects: int = MAX_REDIRECTS

    @staticmethod
    def from_env() -> "EgressPolicy":
        dev = os.getenv("XCP_ALLOW_INSECURE_PEERS", "0") == "1"
        return EgressPolicy(allow_http=dev, allow_private=dev)


def _address_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
        return False
    return not any(addr in net for net in _EXTRA_DENY)


def resolved_addresses(host: str) -> list[str]:
    """Every address a hostname resolves to. All of them must pass."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise EgressDenied("host could not be resolved")
    return sorted({i[4][0] for i in infos})


def check_url(url: str, policy: Optional[EgressPolicy] = None) -> str:
    """
    Validate a URL before fetching it. Returns the normalised URL or raises.

    Note the resolution step: checking the hostname string is not sufficient,
    because a name an attacker controls can resolve wherever they like.
    """
    p = policy or EgressPolicy.from_env()
    try:
        u = urlparse(url)
    except Exception:
        raise EgressDenied("malformed URL")

    if u.scheme not in ("https", "http"):
        raise EgressDenied("unsupported scheme")
    if u.scheme == "http" and not p.allow_http:
        raise EgressDenied(
            "plain HTTP is refused; set XCP_ALLOW_INSECURE_PEERS=1 for local "
            "development only")
    if not u.hostname:
        raise EgressDenied("no host in URL")
    if u.username or u.password:
        raise EgressDenied("credentials in URL are refused")
    # No port allowlist. It blocked peers on legitimate non-standard ports
    # while adding almost nothing — an SSRF target on an odd port is still
    # stopped by the address check below, which is where the defence lives.
    if u.port is not None and not (0 < u.port < 65536):
        raise EgressDenied("invalid port")

    if not p.allow_private:
        for ip in resolved_addresses(u.hostname):
            if not _address_is_public(ip):
                # Deliberately does not say WHICH address or why.
                raise EgressDenied("host does not resolve to a public address")
    return url


def guard_redirect(location: str, policy: Optional[EgressPolicy] = None) -> str:
    """
    Re-check a redirect target. A first-hop check alone is bypassed by any
    open redirector, so this must run on every hop.
    """
    return check_url(location, policy)


__all__ = ["check_url", "guard_redirect", "resolved_addresses", "EgressPolicy",
           "EgressDenied", "MAX_FETCH_BYTES", "MAX_REDIRECTS"]
