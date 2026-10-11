"""
protocol.hashing — one hash function, and a loud failure when it is unavailable.

THE DEFECT THIS REPLACES
------------------------
Eleven modules in this repository each carried their own copy of:

    def digest(data: bytes) -> str:
        if _ETH:
            return "0x" + _keccak(data).hex()
        return "0x" + hashlib.sha3_256(data).hexdigest()

keccak256 and SHA3-256 are not the same function. They differ in padding, so
they return different output for the same input. That `if` therefore means the
binding digest a node computes depends on whether `eth_utils` happened to be
importable in the environment it booted in.

The failure that produces is as bad as it sounds and worse than it looks. Two
operators install the same version of this package. One installs `xcp[client]`,
which pulls `eth-utils`; the other installs the base distribution, which by
design pulls nothing. Both nodes come up healthy. Every stateless credential
minted by one is rejected by the other, because they are signing over different
digests of identical bytes. Nothing in either log says "different hash
function", because neither node knows there is more than one.

It survived because it is invisible to testing. A suite run without `eth_utils`
exercises the fallback consistently and passes: it proves the implementation
agrees with itself, which is the one property that was never in doubt. This
project's own differential harness exists because self-consistency is not
agreement -- and the fallback was in the code that harness was written to guard.

WHY FAIL RATHER THAN POLYFILL
-----------------------------
Three options existed. Hard-require `eth-utils` everywhere, which would end the
zero-dependency base install the CLI and lattice legitimately provide. Ship a
pure-Python keccak, which adds a cryptographic primitive this project would then
own and have to keep correct. Or refuse to produce a digest at all when the real
function is unavailable.

The third is right because of what a digest is for here. It is not a checksum
with a local consumer; it is the value two independent implementations must
agree on, so a digest nobody can verify is worse than no digest. Refusing is
also what the rest of this codebase already does with a setting it cannot
honour: the gateway will not start when `XCP_PRIVATE_PEER_CIDRS` is set and the
egress guard is missing, for the same reason -- an operator who believes a
control is active and is wrong is in a worse position than one who got an error.

The zero-dependency surface is unaffected because none of it needs a digest.
The trust lattice is arithmetic over nine cells, `xcp config` reads a registry,
`xcp compliance` reads a table. Signing, binding and membership need the real
hash, and those surfaces already declare `eth-utils` in their extras.
"""

from __future__ import annotations

from typing import Optional

#: Resolved once at import. A per-call import would make the first caller's
#: environment decide for every later one, which is a quieter version of the
#: bug this module exists to remove.
_keccak = None
_IMPORT_ERROR: Optional[str] = None

try:
    from eth_utils import keccak as _keccak  # type: ignore[no-redef]
except Exception as e:                        # pragma: no cover - env dependent
    _IMPORT_ERROR = f"{type(e).__name__}: {e}"


AVAILABLE = _keccak is not None

_MESSAGE = (
    "XCP needs keccak256 and it is not available, so no digest can be "
    "computed. This is refused rather than substituted: SHA3-256 is a "
    "different function, and a node that silently used it would compute "
    "binding digests no other node agrees with, rejecting every credential "
    "minted elsewhere with no indication why.\n"
    "Install a distribution that provides it:\n"
    "    pip install 'xcp[client]'     # to call a gateway\n"
    "    pip install 'xcp[gateway]'    # to run a node\n"
    "The base distribution has no dependencies on purpose; the trust lattice, "
    "`xcp config` and `xcp compliance` need no hash and keep working without "
    "one."
)


class HashUnavailable(RuntimeError):
    """
    Raised when keccak256 is needed and absent.

    A distinct type so a caller that genuinely has a local-only use for a hash
    can catch it deliberately, rather than every caller inheriting a silent
    substitution none of them asked for.
    """


def keccak256(data: bytes) -> bytes:
    """keccak256 as raw bytes. Raises HashUnavailable rather than substituting."""
    if _keccak is None:
        raise HashUnavailable(
            _MESSAGE + (f"\nImport failed with {_IMPORT_ERROR}."
                        if _IMPORT_ERROR else ""))
    return _keccak(data)


def digest(data: bytes) -> str:
    """
    keccak256 as an 0x-prefixed lowercase hex string.

    This is the project's canonical digest. Every module that previously
    defined its own now delegates here, so there is one answer to "what hash
    does XCP use" and it cannot vary by environment.
    """
    return "0x" + keccak256(data).hex()


def require(context: str = "") -> None:
    """
    Assert availability early, with a message naming what will not work.

    Called at node startup so a missing hash is a refusal to boot rather than a
    failure on the first credential, which is the difference between an error an
    operator can act on and an incident they have to diagnose.
    """
    if _keccak is None:
        where = f" Needed for: {context}." if context else ""
        raise HashUnavailable(_MESSAGE + where)


__all__ = ["keccak256", "digest", "require", "HashUnavailable", "AVAILABLE"]
