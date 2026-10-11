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
  · the hostname resolves only to permitted addresses — public ones, plus any
    private range the operator has DECLARED for a private federation
  · every redirect target is re-checked, not just the first URL
  · responses are size-capped, so a fetch cannot exhaust memory
  · errors are generic, so failures do not become an information oracle

PRIVATE FEDERATION
------------------
The guard above was written for the public federation, where peers are mutually
suspicious strangers on routable addresses. It made a private federation --
several datacentres inside one organisation -- impossible to run safely, because
reaching a peer on 10.40.0.0/16 required XCP_ALLOW_INSECURE_PEERS=1, and that one
flag ALSO accepted plain-HTTP peering and is refused outright by the production
profile. An operator had to choose between a profile they could not claim and a
guard they had to disable wholesale.

The flag is now two decisions:

    XCP_ALLOW_INSECURE_PEERS=1        blanket: any private address AND plain
                                      HTTP. Local development only; the
                                      production profile refuses to start.

    XCP_PRIVATE_PEER_CIDRS=10.40.0.0/16,fd00:dc1::/48
                                      declared: these ranges only, TLS still
                                      required. Safe in production.

Declaring a range is narrower than disabling the guard, in two ways that matter.
A hostname an attacker controls still cannot resolve into a range nobody
declared, so the SSRF defence survives. And `_never_permitted` below is checked
FIRST, so declaring 10.0.0.0/8 does not re-admit the cloud metadata service and
no declaration can reach loopback -- an address range cannot be used to aim the
gateway at its own admin surface.

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

#: The broadest declaration that can be legitimate. 10.0.0.0/8 is the largest
#: real private IPv4 block and fc00::/7 the IPv6 unique-local block, so these
#: floors admit every genuine private range while refusing 0.0.0.0/0 -- which
#: would be XCP_ALLOW_INSECURE_PEERS under a name the production profile does
#: not check for.
MIN_PRIVATE_PREFIX_V4 = 8
MIN_PRIVATE_PREFIX_V6 = 7

MAX_FETCH_BYTES = 256 * 1024
MAX_REDIRECTS = 3

PRIVATE_CIDR_ENV = "XCP_PRIVATE_PEER_CIDRS"


class EgressDenied(Exception):
    """Raised when a URL must not be fetched. The message is deliberately
    coarse: a precise reason tells an attacker what the network looks like."""


class EgressConfigError(Exception):
    """
    Raised when the operator's egress configuration cannot be honoured. Distinct
    from EgressDenied on purpose: a denial is a correct answer about one URL, a
    config error means the guard is not the shape the operator asked for. The
    gateway validates this at startup and refuses to run, rather than discovering
    it on the first peering attempt and reporting it as a refused peer.
    """


def parse_private_networks(spec: str) -> tuple:
    """
    Parse a comma-separated CIDR list into networks, refusing what cannot be a
    legitimate declaration.

    A public CIDR is accepted and has no effect -- public addresses already
    pass -- so an operator who over-declares is not punished for it.
    """
    nets: list = []
    for raw in spec.replace(";", ",").split(","):
        item = raw.strip()
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise EgressConfigError(
                f"{PRIVATE_CIDR_ENV} entry {item!r} is not a CIDR block")
        floor = (MIN_PRIVATE_PREFIX_V6 if net.version == 6
                 else MIN_PRIVATE_PREFIX_V4)
        if net.prefixlen < floor:
            raise EgressConfigError(
                f"{PRIVATE_CIDR_ENV} entry {item!r} is broader than /{floor}. "
                f"A declaration that wide disables the egress guard without "
                f"saying so; use XCP_ALLOW_INSECURE_PEERS=1 if that is what you "
                f"mean, and know that the production profile refuses it.")
        nets.append(net)
    return tuple(nets)


_CIDR_CACHE: tuple[str, tuple] = ("", ())


def private_networks_from_env() -> tuple:
    """Declared ranges, parsed once per distinct value of the variable."""
    global _CIDR_CACHE
    spec = os.getenv(PRIVATE_CIDR_ENV, "")
    if spec != _CIDR_CACHE[0]:
        _CIDR_CACHE = (spec, parse_private_networks(spec))
    return _CIDR_CACHE[1]


@dataclass(frozen=True)
class EgressPolicy:
    allow_http: bool = False          # plain HTTP, for local development only
    allow_private: bool = False       # ANY private range: development only
    #: Declared private ranges. Narrower than allow_private and safe in
    #: production, because an undeclared range is still refused.
    private_networks: tuple = ()
    max_bytes: int = MAX_FETCH_BYTES
    max_redirects: int = MAX_REDIRECTS

    @staticmethod
    def from_env() -> "EgressPolicy":
        dev = os.getenv("XCP_ALLOW_INSECURE_PEERS", "0") == "1"
        return EgressPolicy(allow_http=dev, allow_private=dev,
                            private_networks=private_networks_from_env())

    @property
    def permits_private(self) -> bool:
        return self.allow_private or bool(self.private_networks)


def _never_permitted(addr) -> bool:
    """
    True for addresses no declaration can re-admit.

    Checked before the declared ranges, which is the whole reason declaring a
    range is safer than disabling the guard. 169.254.169.254 sits inside several
    plausible declarations and must never be reachable through one.
    """
    if (addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_reserved or addr.is_unspecified):
        return True
    return any(addr in net for net in _EXTRA_DENY)


def _address_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or _never_permitted(addr):
        return False
    return True


def address_permitted(ip: str, policy: Optional["EgressPolicy"] = None) -> bool:
    """Whether one resolved address may be fetched under this policy."""
    p = policy or EgressPolicy.from_env()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if _never_permitted(addr):
        return False
    if not addr.is_private:
        return True
    if p.allow_private:
        return True
    return any(addr in net for net in p.private_networks)


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
        # A private federation does NOT relax this. Declaring a CIDR says where
        # peers live, not that the network between them is trusted -- an
        # internal network is exactly where an attacker who got a foothold is
        # already positioned to read and rewrite traffic.
        raise EgressDenied(
            "plain HTTP is refused; a private federation still requires TLS. "
            "Set XCP_ALLOW_INSECURE_PEERS=1 for local development only")
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
            if not address_permitted(ip, p):
                # Deliberately does not say WHICH address, why, or which ranges
                # are declared. The caller learns that this host is not a
                # permitted peer and nothing about the shape of the network.
                raise EgressDenied("host does not resolve to a permitted address")
    return url


def guard_redirect(location: str, policy: Optional[EgressPolicy] = None) -> str:
    """
    Re-check a redirect target. A first-hop check alone is bypassed by any
    open redirector, so this must run on every hop.
    """
    return check_url(location, policy)


__all__ = ["check_url", "guard_redirect", "resolved_addresses", "EgressPolicy",
           "EgressDenied", "EgressConfigError", "MAX_FETCH_BYTES",
           "MAX_REDIRECTS", "address_permitted", "parse_private_networks",
           "private_networks_from_env", "PRIVATE_CIDR_ENV",
           "MIN_PRIVATE_PREFIX_V4", "MIN_PRIVATE_PREFIX_V6"]
