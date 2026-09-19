# Independent security analysis

Addresses draft Appendix B.3. **Not a substitute for human review** — see
*What this is not* below.

## Method

AI models reviewing AI-written code is weak evidence: models share training
data and failure modes, so a second model agreeing is correlated rather than
independent. These methods were chosen because **none depends on anyone's
judgment**:

| method | independence comes from |
|---|---|
| `fuzz_binding.py` | falsifiability — a digest collision is a concrete object, found or not |
| `differential.py` | two implementations written separately; disagreement means at least one is wrong |
| `bandit` | different methodology, applied mechanically |

## Findings

### SA-01 (high) — parser differential in the binding digest

`bind_digest` called `.strip()`, so `"search"` and `"search "` produced the
**same** digest. The gateway strips; an upstream may not. A credential verified
for one tool could be forwarded carrying another — request smuggling in its
classic shape, and a direct contradiction of draft §4.2's claim to bind "one
exact call."

Fixed by **refusing** non-canonical input rather than normalising it.
Normalising closes the instance and leaves the class open, because it assumes
every downstream parser normalises identically.

### SA-02 (high) — mandate with no expiry was accepted

`int(proof.get("notAfter", 0)) and ...` short-circuits when the field is absent,
so the expiry check was skipped entirely. A mandate without `notAfter` never
expired. **An absent expiry is not an infinite one**; a delegation that cannot
lapse is not a delegation.

Found by differential: Node refused it, Python forwarded it upstream.

### SA-03 (high) — malformed scope was accepted

`mandateScope: null` reached the coverage check and passed vacuously. Malformed
authorization is **absent** authorization, not universal authorization.

### SA-04 (medium) — coercive identity parsing

Python's `int()` accepts `"+42001"` and `" 42001"`; Node's regex did not. Both
now refuse.

### SA-05 (specification) — OWS handling is not interoperable

The last divergence was not in XCP code. [RFC 9110] treats optional whitespace
around a field value as not part of the value; Node's HTTP parser strips it,
uvicorn does not. Both arguably conform, and they disagreed about whether the
same bytes named the same tool.

This cannot be fixed in an implementation — it is fixed in the **specification**,
by requiring canonical form and refusing anything else. Draft §4.2 now says so.

## Results

- Binding digest: exhaustive over 216 triples, 4000 randomised triples, 13
  adversarial pairs. No collision.
- Differential: 21 adversarial inputs, **20/21 agree**; the one divergence is
  SA-05, an HTTP-layer artifact now specified away.
- Bandit: no medium or high findings.

## A correction

The first fuzzer run reported a collision that was not one — the test data
contained `"se\u0061rch"` and `"search"`, which are the same string. **Test data
is as capable of being wrong as the code under test**, and an analysis that
does not check its own findings produces false confidence rather than assurance.

## What this is not

Four things remain true and are not addressed by anything here:

1. **No human security review.** These methods find what they are pointed at.
   Nothing here would find a flaw in the threat model, because the threat model
   is what told them where to look.
2. **The code and the analysis share an author.** A blind spot in one is likely
   a blind spot in the other.
3. **Agreement between implementations is weak evidence.** Two implementations
   can share a misunderstanding of an ambiguous specification; SA-05 is exactly
   that case, caught only because the HTTP stacks differed.
4. **Absence of a collision is not proof of absence.** The search is bounded.

Appendix B.3 stays open.
