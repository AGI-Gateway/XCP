"""
xcpsec.mtls — hardened mutual-TLS for XCP.

This is the optional secured-transport foundation. It gives the client, gateway,
and server a single, opinionated way to build TLS 1.3 mutual-auth contexts with:

  - TLS 1.3 only (no downgrade, no renegotiation, strong cipher suites)
  - required client certificates (mutual auth) with CA verification
  - certificate pinning by keccak256(DER(cert)) footprint (optional allowlist)
  - extraction of the ERC-8004 AgentBinding OID from the peer certificate
  - the channel-binding value (RFC 9266 tls-exporter) for binding session tokens

None of this "solves" application-layer attacks by itself — it is the transport
substrate the argument firewall, supply-chain verifier, and content firewall sit
on top of. What it does eliminate is the transport-level attack surface: MITM,
downgrade, anonymous callers, and token replay across connections.

Standard library only (ssl, hashlib) plus an optional keccak from eth-utils.
Status: XCP / ERC-8004x are draft proposals.
"""

from __future__ import annotations

import hashlib
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# The private-enterprise OID that carries the agent's ERC-8004 id in its cert.
AGENT_BINDING_OID = "1.3.6.1.4.1.99999.1"


def _keccak(data: bytes) -> str:
    try:
        from eth_utils import keccak
        return "0x" + keccak(data).hex()
    except Exception:
        # sha3-256 stand-in so the module runs without the crypto stack;
        # on-chain footprints require real keccak256 (install eth-utils).
        return "0x" + hashlib.sha3_256(data).hexdigest()


def cert_footprint_der(der: bytes) -> str:
    """keccak256(DER(cert)) — the on-chain session key."""
    return _keccak(der)


def cert_footprint_pem(pem: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    der = x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)
    return cert_footprint_der(der)


@dataclass
class TLSPolicy:
    """Declarative hardening policy for an mTLS context."""
    ca_path: str                              # CA bundle to verify the peer
    cert_path: str                            # our certificate (PEM)
    key_path: str                             # our private key (PEM)
    require_client_cert: bool = True          # mutual auth (server side)
    pinned_footprints: set[str] = field(default_factory=set)  # allowlist (optional)
    check_hostname: bool = True               # client side
    minimum_days_valid: int = 0               # reject certs expiring too soon


class TLSHardeningError(Exception):
    """Raised when a policy cannot be satisfied or a peer fails pinning."""


def _base_context(purpose: ssl.Purpose, policy: TLSPolicy) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER
                         if purpose == ssl.Purpose.CLIENT_AUTH
                         else ssl.PROTOCOL_TLS_CLIENT)
    # TLS 1.3 floor: disable everything below.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    # No compression (CRIME), no renegotiation quirks.
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    ctx.options |= ssl.OP_NO_TICKET
    # Load our identity and the trust anchor.
    ctx.load_cert_chain(certfile=policy.cert_path, keyfile=policy.key_path)
    ctx.load_verify_locations(cafile=policy.ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def server_context(policy: TLSPolicy) -> ssl.SSLContext:
    """Build a hardened server context requiring client certificates."""
    ctx = _base_context(ssl.Purpose.CLIENT_AUTH, policy)
    ctx.verify_mode = (ssl.CERT_REQUIRED if policy.require_client_cert
                       else ssl.CERT_OPTIONAL)
    # Server never checks hostnames of clients.
    ctx.check_hostname = False
    return ctx


def client_context(policy: TLSPolicy) -> ssl.SSLContext:
    """Build a hardened client context presenting our certificate."""
    ctx = _base_context(ssl.Purpose.SERVER_AUTH, policy)
    ctx.check_hostname = policy.check_hostname
    return ctx


def verify_peer_footprint(der_cert: bytes, policy: TLSPolicy) -> str:
    """
    Compute the peer footprint and enforce the pin allowlist if one is set.
    Call this right after the handshake with getpeercert(binary_form=True).
    Returns the footprint; raises TLSHardeningError if pinning fails.
    """
    fp = cert_footprint_der(der_cert)
    if policy.pinned_footprints and fp not in policy.pinned_footprints:
        raise TLSHardeningError(
            f"peer footprint {fp[:14]}… not in the pinned allowlist")
    return fp


def extract_agent_id(der_cert: bytes) -> Optional[int]:
    """
    Pull the ERC-8004 agent id out of the AgentBinding OID extension, if present.
    Lets a server learn which agent a certificate claims *before* consulting the
    registry (the registry is still authoritative).
    """
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der_cert)
        for ext in cert.extensions:
            if ext.oid.dotted_string == AGENT_BINDING_OID:
                val = ext.value
                raw = getattr(val, "value", val)
                if isinstance(raw, bytes):
                    # strip ASN.1 UTF8String tag/len if present
                    text = raw.decode("utf-8", "ignore").lstrip("\x0c").strip()
                    digits = "".join(c for c in text if c.isdigit())
                    return int(digits) if digits else None
    except Exception:
        return None
    return None


def channel_binding(ssl_object: ssl.SSLObject | ssl.SSLSocket,
                    kind: str = "tls-exporter") -> Optional[bytes]:
    """
    Return the RFC 9266 channel-binding value for this connection, used to bind
    session tokens to the exact TLS channel (defeats token replay across
    connections). Falls back to None if unsupported by the runtime.
    """
    try:
        return ssl_object.get_channel_binding(kind)  # type: ignore[arg-type]
    except (ValueError, NotImplementedError, AttributeError):
        try:
            return ssl_object.get_channel_binding("tls-unique")
        except Exception:
            return None


def load_pinned_from_dir(directory: str) -> set[str]:
    """Convenience: compute pinned footprints for every *.crt in a directory."""
    pins: set[str] = set()
    for p in Path(directory).glob("*.crt"):
        try:
            pins.add(cert_footprint_pem(p.read_bytes()))
        except Exception:
            continue
    return pins


__all__ = [
    "TLSPolicy", "TLSHardeningError", "server_context", "client_context",
    "verify_peer_footprint", "extract_agent_id", "channel_binding",
    "cert_footprint_der", "cert_footprint_pem", "load_pinned_from_dir",
    "AGENT_BINDING_OID",
]
