"""
protocol.identity — the one parser for the XCP-Agent-Identity header.

WHY THIS MODULE EXISTS
----------------------
This header is the first thing every implementation reads and the last thing
anyone thinks about. Its parse was written three times in this repository --
inline in the Python gateway's `parse_ctx`, again in `core/gateway-ts`, and a
third time in the Python client, which only formats it. Five SDKs would have
made that eight.

That matters more here than it would for most headers, because the footprint in
field three is compared byte-for-byte against a registered binding. Two parsers
that disagree about which bytes are "the footprint" do not fail loudly; one
verifies a session the other rejects, and the disagreement surfaces as an
intermittent 401 nobody can reproduce. That exact bug has already happened in
this project, between the Python and Node gateways, and was found by
differential analysis rather than by either test suite.

So the parse lives here, once, and the SDK conformance vectors are generated
from it. An SDK that reproduces the vectors agrees with the gateway by
construction rather than by inspection.

THE RULES, AND WHY EACH ONE
---------------------------
  1. Strip surrounding OWS, where OWS is EXACTLY space and horizontal tab
     ([RFC9110] 5.5: `OWS = *( SP / HTAB )`). Nothing else is stripped.

     Stripping at all is not leniency: Node's HTTP server strips OWS before the
     application sees it, as RFC 9110 says a recipient should, while uvicorn
     passes it through. Refusing OWS is therefore unimplementable on one of the
     two servers -- a parser that never receives the bytes cannot refuse them --
     so the two could never have converged on refusal.

     Stripping *exactly* OWS, rather than whatever the host language calls
     whitespace, is the part that was wrong before this module existed. The
     gateway used Python's `str.strip()`, which also removes LF, CR, VT, FF,
     NEL, NBSP (U+00A0), OGHAM SPACE MARK, EN QUAD, NARROW NBSP and IDEOGRAPHIC
     SPACE -- ten codepoint classes beyond OWS. The consequence is the original
     trailing-space differential with new characters: "<footprint> " was
     stripped here and matched a registered binding, while a parser that
     implements RFC 9110 as written keeps the NBSP, finds no binding, and
     answers 401. Same bytes, two verdicts, no way to reproduce it on purpose.

     Five SDKs make this certain rather than likely, because no two languages
     agree on trim(): JavaScript strips Unicode whitespace plus the BOM, Go's
     TrimSpace strips Unicode space, Java's trim() strips only U+0000-U+0020
     while its strip() strips Unicode, and C#'s Trim() strips Unicode. Writing
     "trim the value" in a spec and letting each port reach for its standard
     library would produce four different parsers and call them one protocol.

     So OWS is defined here as a two-character set and implemented by hand. The
     narrowing can only turn a previously-accepted exotic-whitespace header into
     a refusal; no legitimate client emits one, and an HTTP server will not
     deliver a raw CR or LF inside a field value in the first place.

  2. Exactly three semicolon-separated fields. Not "at least three": a fourth
     field is a header some other implementation understands and this one does
     not, which is the point at which to stop rather than guess.

  3. The first two fields must be canonical decimal integers, tested with
     `str.isdigit()` rather than parsed with `int()`. `int()` accepts
     "+42001", " 42001" and "42_001", all of which differ from what another
     parser in the chain reads from the same bytes. Found by differential
     analysis against the Node implementation, which refused what this one
     silently normalised.

  4. The footprint is taken verbatim. It is NOT lowercased, NOT stripped of a
     "0X" prefix, NOT length-checked here. Normalising it would make two
     distinct headers produce the same binding lookup, which is the parser
     differential this module exists to prevent. Whether a given footprint is
     registered is a question for the session registry, not for the parser.

This module has no dependencies and performs no I/O, so every SDK can port it
and every port can be checked offline against the vectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

#: The header this module parses. Lower-case because HTTP field names are
#: case-insensitive and every server in this project normalises them that way.
HEADER = "xcp-agent-identity"

#: Field separator. A semicolon rather than a comma so the value survives
#: intermediaries that recombine repeated comma-separated headers.
SEP = ";"

FIELDS = 3

#: RFC 9110 5.5: `OWS = *( SP / HTAB )`. Spelled out as a two-character set
#: rather than delegated to the host language's notion of whitespace, because
#: no two languages agree on that and all five SDKs must agree here. See rule 1
#: in the module docstring for the divergence this prevents.
OWS = " \t"


def strip_ows(value: str) -> str:
    """
    Remove leading and trailing OWS -- space and horizontal tab only.

    Deliberately not `str.strip()`. Every SDK implements this function by hand
    for the same reason, and the conformance vectors include the ten codepoint
    classes that `str.strip()` would have removed.
    """
    start, end = 0, len(value)
    while start < end and value[start] in OWS:
        start += 1
    while end > start and value[end - 1] in OWS:
        end -= 1
    return value[start:end]


class IdentityError(ValueError):
    """A header that cannot be parsed. Carries the reason a caller may be told."""


@dataclass(frozen=True)
class AgentIdentityHeader:
    """The three fields, after parsing. No session state, no verification."""
    agent_id: int
    chain_id: int
    footprint: str

    def format(self) -> str:
        """Render the canonical form. `parse(format(x)) == x` for every x."""
        return f"{self.agent_id}{SEP}{self.chain_id}{SEP}{self.footprint}"


# Reasons are constants rather than f-strings so an SDK can match on them and
# the conformance vectors can assert the exact text. A reason that drifts
# between implementations is a reason nobody can test against.
REASON_MALFORMED = "missing or malformed XCP-Agent-Identity"
REASON_NON_CANONICAL = "identity fields must be canonical decimal integers"


def parse(header: Optional[str]) -> AgentIdentityHeader:
    """
    Parse the header, or raise IdentityError with the reason.

    See the module docstring for why each rule is what it is. The short version:
    strip OWS because RFC 9110 says a recipient does, refuse everything else
    because a second parser downstream will not make the same guess.
    """
    # Rule 1: OWS around the value is not part of the value. A None header and
    # an empty one are the same case -- neither carries an identity.
    parts = strip_ows(header or "").split(SEP)

    # Rule 2: exactly three fields.
    if len(parts) != FIELDS:
        raise IdentityError(REASON_MALFORMED)

    # Rule 3: canonical decimal, not merely int()-parseable.
    if not (parts[0].isdigit() and parts[1].isdigit()):
        raise IdentityError(REASON_NON_CANONICAL)

    # Rule 4: footprint verbatim.
    return AgentIdentityHeader(agent_id=int(parts[0]), chain_id=int(parts[1]),
                               footprint=parts[2])


def try_parse(header: Optional[str]) -> tuple[Optional[AgentIdentityHeader], str]:
    """
    Non-raising form: returns (identity, "") or (None, reason).

    The gateway wants the reason as a value rather than as an exception,
    because it records every refusal with its reason. Both forms exist so
    neither caller has to wrap the other.
    """
    try:
        return parse(header), ""
    except IdentityError as e:
        return None, str(e)


def format_identity(agent_id: int, chain_id: int, footprint: str) -> str:
    """
    Build the header. Refuses to emit what this module would refuse to read,
    so a client cannot construct a header the gateway will reject.

    A formatter that happily emits "+42001" is a formatter that ships a bug to
    whoever runs it against a stricter peer.
    """
    if agent_id < 0 or chain_id < 0:
        raise IdentityError(REASON_NON_CANONICAL)
    # Deliberately broader than strip_ows: the parser removes only OWS because
    # RFC 9110 obliges it to, but nothing obliges a formatter to EMIT a
    # footprint padded with an ideographic space. Be liberal only where the
    # specification requires it, and strict in what you send.
    if SEP in footprint or footprint.strip() != footprint:
        raise IdentityError(
            "footprint may not contain the field separator or surrounding "
            "whitespace; it is compared byte-for-byte against a binding")
    h = AgentIdentityHeader(agent_id, chain_id, footprint).format()
    parse(h)                      # the formatter is held to the parser's rules
    return h


__all__ = ["HEADER", "SEP", "FIELDS", "AgentIdentityHeader", "IdentityError",
           "REASON_MALFORMED", "REASON_NON_CANONICAL",
           "parse", "try_parse", "format_identity"]
