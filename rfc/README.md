# Internet-Draft

`draft-xcp-trust-envelope-00.txt` — XCP specified as a trust encapsulation
layer over TLS.

## The architectural claim, and its limit

OSI layers are defined by **encapsulation**: each wraps the PDU above. A
protocol that annotates rather than wraps is not a layer, however useful it is.

XCP earns the layering claim because `XCP-Request-Credential` commits to the
payload it carries through a binding digest over method, target and body. The
authorization cannot be detached from the request it authorizes. That is a real
encapsulation relationship, and it is the **only** basis on which the draft
makes the claim.

Position is directly analogous to TLS:

| | secures |
|---|---|
| TLS | the authenticity of the **channel** |
| XCP | the authority of the **action** taken over it |

## On "Layer 8"

The draft does **not** propose adding one. Layer 8 — the human — already exists
and is where authority originates. What was missing is any means of *addressing*
it: no protocol field has ever named the person on whose behalf a packet was
sent.

XCP's contribution is narrower and more defensible than "a new layer": it makes
the existing Layer 8 machine-legible. The Principal becomes a named, bounded,
revocable participant rather than an assumption behind the stack.

A reviewer would reject the stronger claim, and correctly.

## Status

Not submitted. No IETF consensus, no working group, no review. The draft is
written to IETF conventions so it can be read by people who expect them, not to
imply standing it does not have.

Appendix A states the one piece of real evidence: a second implementation, in
Node, written against this document rather than ported, passes the conformance
suite. That is the only available test of whether the specification is
implementable from the text.

## Appendix B — resolutions

| | disposition |
|---|---|
| **Credential lifetime** | resolved against [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) (DPoP), which solves a closely related problem and declines to fix a figure. Deployed DPoP has converged on a 60s window with ~30s skew; the draft adopts that rather than asserting its own. 300s becomes a ceiling, not the default. |
| **Classification mechanism** | resolved by deferral, with [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334) (RATS) as precedent — architecture and appraisal policy belong in separate documents. The draft adopts RATS vocabulary so a future document can be written against established terms. |
| **Independent security analysis** | **not resolved, and not resolvable by citation.** Kept rather than deleted, with the four most likely locations of an error named so review is tractable. |

The third is the one that matters. No amount of referencing other people's work
substitutes for someone competent attacking this one.
