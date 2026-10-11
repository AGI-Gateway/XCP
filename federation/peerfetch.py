"""
federation.peerfetch — the one place that knows how to reach a peer.

WHY THIS MODULE EXISTS
----------------------
A node's identity is bound to the TLS certificate its domain serves:
`verify_node_record()` compares the record's declared footprint against
`keccak256(DER(cert))` taken from the live connection. That binding is a pinning
construction, so it is indifferent to WHO signed the certificate -- which ought
to make an internal certificate authority a non-event.

It was not. Both halves of peering used the ambient system trust store: the
record fetch (httpx, default `verify`) and the certificate retrieval
(`ssl.create_default_context()`). An internal chain fails verification in both
places, and it fails BEFORE pinning is reached, so a private federation whose
certificates are signed by the organisation's own CA could not peer at all.

This module carries the trust decision for federation traffic only. Upstream
tool calls keep the public trust store, which is correct: a peer is an internal
party whose signer the operator declares, an upstream API is a public party
whose signer they do not.

THE BUNDLE REPLACES THE SYSTEM STORE
------------------------------------
When XCP_PEER_CA_BUNDLE is set it is the ONLY trust anchor for peer
verification. Augmenting the system roots would have been the softer default and
is the wrong one: setting the variable is a statement about who signs your
peers, and leaving 150-odd public roots trusted contradicts it. Any public CA
mis-issuance for an internal name would be accepted on a first peering, which is
precisely the moment pinning cannot help, because there is no prior footprint to
compare against.

A deployment with some public-CA peers and some internal ones concatenates the
roots it needs into one bundle file. That keeps the trust decision legible in a
file an auditor can read, rather than implicit in code.

IF THE BUNDLE IS UNREADABLE THE NODE DOES NOT START
---------------------------------------------------
Falling back to the system store would leave the operator believing peers are
verified against their internal CA while every public root is in fact trusted.
That is the failure mode this codebase refuses elsewhere -- a control you asked
for and silently did not get -- so `validate_config()` runs at startup.

Status: XCP is a draft proposal.
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

CA_BUNDLE_ENV = "XCP_PEER_CA_BUNDLE"

#: Mirrors security.xcpsec.egress.MAX_FETCH_BYTES. Duplicated rather than
#: imported so this module does not drag the whole security package in; the
#: test suite asserts they agree.
MAX_RECORD_BYTES = 256 * 1024

DEFAULT_TIMEOUT = 10.0
DEFAULT_TLS_TIMEOUT = 8.0


class PeerFetchError(Exception):
    """A peer could not be reached or did not answer usefully."""


class PeerTrustConfigError(Exception):
    """The declared peer trust anchor cannot be used. Fatal at startup."""


def peer_ca_bundle() -> str:
    """The configured bundle path, or "" for the system trust store."""
    return os.getenv(CA_BUNDLE_ENV, "").strip()


def validate_config() -> None:
    """
    Check the trust anchor is usable. Call once at startup.

    Raises PeerTrustConfigError rather than warning, because the alternative is
    a node that reports healthy while trusting the wrong roots.
    """
    bundle = peer_ca_bundle()
    if not bundle:
        return
    if not os.path.isfile(bundle):
        raise PeerTrustConfigError(
            f"{CA_BUNDLE_ENV}={bundle!r} is not a readable file. Refusing to "
            f"start: continuing would verify peers against the public trust "
            f"store while you believe they are verified against your own CA.")
    try:
        ctx = ssl.create_default_context(cafile=bundle)
    except (ssl.SSLError, OSError) as e:
        raise PeerTrustConfigError(
            f"{CA_BUNDLE_ENV}={bundle!r} could not be loaded as PEM "
            f"certificates: {e}")
    if not ctx.get_ca_certs():
        raise PeerTrustConfigError(
            f"{CA_BUNDLE_ENV}={bundle!r} loaded but contains no certificate "
            f"authorities, so no peer could ever verify.")


def peer_ssl_context(*, bundle: Optional[str] = None) -> ssl.SSLContext:
    """
    An SSL context for peer verification.

    `cafile` REPLACES the default root set -- see the module docstring. Hostname
    checking and certificate verification both stay on; the certificate
    footprint binding in `verify_node_record()` is an additional check on top of
    chain validation, never a substitute for it.
    """
    ca = bundle if bundle is not None else peer_ca_bundle()
    if ca:
        return ssl.create_default_context(cafile=ca)
    return ssl.create_default_context()


def peer_verify(*, bundle: Optional[str] = None) -> Any:
    """
    The value to hand an HTTP client's `verify=` parameter.

    Returns an SSLContext in both cases rather than a bool or a path, so the
    client cannot be constructed with verification accidentally off.
    """
    return peer_ssl_context(bundle=bundle)


@dataclass(frozen=True)
class FetchedRecord:
    status: int
    body: bytes
    #: True when the record was served over TLS whose chain verified against
    #: the configured anchor. A record without this cannot reach VERIFIED.
    tls: bool

    @property
    def ok(self) -> bool:
        return self.status == 200


def _record_url(gateway_url: str, path: str = "/.well-known/xcp-node.json") -> str:
    return gateway_url.rstrip("/") + path


async def fetch_node_record(gateway_url: str, *,
                            timeout: float = DEFAULT_TIMEOUT,
                            bundle: Optional[str] = None) -> FetchedRecord:
    """
    Fetch a peer's node record.

    Redirects are refused rather than followed: the caller has already checked
    this URL against the egress guard, and an open redirector on a permitted
    host would otherwise reach somewhere that was never checked.
    """
    import httpx
    url = _record_url(gateway_url)
    # Always an SSLContext, never `verify=False`. A plain-HTTP peer URL has
    # already been refused by the egress guard unless the operator set the
    # development flag, and `verify=False` in federation code is the line an
    # auditor greps for -- it should not appear even where it is inert.
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                     verify=peer_verify(bundle=bundle)) as hc:
            r = await hc.get(url)
    except Exception as e:                       # noqa: BLE001 - reported coarsely
        raise PeerFetchError(f"{type(e).__name__}") from e
    body = r.content or b""
    if len(body) > MAX_RECORD_BYTES:
        raise PeerFetchError("record is too large")
    return FetchedRecord(status=r.status_code, body=body,
                         tls=url.startswith("https://"))


def _certificate_der_blocking(host: str, port: int, *,
                              timeout: float,
                              bundle: Optional[str]) -> bytes:
    ctx = peer_ssl_context(bundle=bundle)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    if not der:
        raise PeerFetchError("no certificate presented")
    return der


async def peer_certificate_der(gateway_url: str, *,
                               timeout: float = DEFAULT_TLS_TIMEOUT,
                               bundle: Optional[str] = None) -> bytes:
    """
    The DER certificate a peer's endpoint actually presents, for footprint
    binding.

    Runs the blocking handshake off the event loop. Inline, a peer that accepts
    a connection and then stalls held the whole gateway for the timeout --
    cheap for an attacker and, on a private federation where peering traffic is
    ordinary rather than rare, easy to hit by accident.
    """
    u = urlparse(gateway_url)
    if u.scheme != "https" or not u.hostname:
        raise PeerFetchError("certificate binding requires an https URL")
    return await asyncio.to_thread(
        _certificate_der_blocking, u.hostname, u.port or 443,
        timeout=timeout, bundle=bundle)


def trust_summary() -> dict[str, Any]:
    """What this node will accept as a peer signer. For /health and triage."""
    bundle = peer_ca_bundle()
    if not bundle:
        return {"anchor": "system", "bundle": "", "authorities": 0}
    try:
        n = len(peer_ssl_context().get_ca_certs())
    except Exception:
        n = 0
    return {"anchor": "declared", "bundle": bundle, "authorities": n}


__all__ = ["CA_BUNDLE_ENV", "MAX_RECORD_BYTES", "PeerFetchError",
           "PeerTrustConfigError", "FetchedRecord", "peer_ca_bundle",
           "validate_config", "peer_ssl_context", "peer_verify",
           "fetch_node_record", "peer_certificate_der", "trust_summary"]
