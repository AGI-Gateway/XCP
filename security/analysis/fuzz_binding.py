"""
Adversarial analysis of the binding digest (draft §4.2, Appendix B.3 item 1).

WHY THIS ONE FIRST
------------------
Appendix B.3 names the binding digest separator scheme as the most likely
location of an error, because if field-boundary ambiguity is possible then the
encapsulation claim fails and with it the architectural argument for layering.

That claim is FALSIFIABLE, which makes it the one part of the draft that does
not need a human reviewer to attack. A collision between two distinct
(method, target, payload) triples is a concrete object. Either the search finds
one or it does not.

This is not a proof of absence. It is a bounded search that has not found one,
which is a weaker and more honest statement.
"""
from __future__ import annotations
import itertools, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from trustfirewall.stateless import bind_digest, NonCanonicalHeader


def safe_digest(m, t, p):
    """Refusal is a correct outcome, not a collision. Distinct sentinels so two
    refusals never compare equal to each other."""
    try:
        return bind_digest(m, t, p)
    except NonCanonicalHeader:
        return f"<refused:{m!r}:{t!r}:{p!r}>"


def adversarial_pairs():
    """
    Inputs chosen to break a naive concatenation. A scheme that joined fields
    without separators would collide on several of these.
    """
    return [
        # classic boundary-shift: content moved across the field boundary
        (("tools/call", "search", b""), ("tools", "/callsearch", b"")),
        (("tools/call", "a", b"b"), ("tools/call", "ab", b"")),
        (("a", "bc", b""), ("ab", "c", b"")),
        (("", "abc", b""), ("abc", "", b"")),
        # separator injection: the attacker supplies the delimiter
        (("tools/call\x00search", "", b""), ("tools/call", "search", b"")),
        (("a\x00b", "c", b""), ("a", "b\x00c", b"")),
        (("a", "b", b"\x00c"), ("a", "b\x00c", b"")),
        # length-extension shapes
        (("tools/call", "search", b"x"), ("tools/call", "searchx", b"")),
        (("t", "", b"ools/call"), ("tools/call", "", b"")),
        # unicode normalisation and case
        (("tools/call", "search", b""), ("tools/call", "Search", b"")),
        # NOTE: an earlier version of this list contained
        # ("se\u0061rch", "search"), which are the SAME string. The harness
        # reported it as a collision and it was not one. Test data is as
        # capable of being wrong as the code under test.
        (("tools/call", "\u00e9", b""), ("tools/call", "e\u0301", b"")),
        # empty-vs-absent
        (("", "", b""), ("", "", b"\x00")),
    ]


def test_adversarial_pairs_do_not_collide():
    bad = []
    for (a, b) in adversarial_pairs():
        if safe_digest(*a) == safe_digest(*b):
            bad.append((a, b))
    assert not bad, f"binding digest collision: {bad}"


def test_exhaustive_small_alphabet():
    """
    Every distinct triple over a tiny alphabet must produce a distinct digest.
    Small enough to be exhaustive, which is stronger than sampling: over this
    domain the absence of collisions is established rather than estimated.
    """
    alphabet = ["", "a", "b", "/", "\x00", "ab"]
    seen: dict[str, tuple] = {}
    n = 0
    for m, t, p in itertools.product(alphabet, alphabet, alphabet):
        triple = (m, t, p.encode())
        d = safe_digest(*triple)
        n += 1
        if d in seen and seen[d] != triple:
            raise AssertionError(f"collision: {seen[d]} and {triple}")
        seen[d] = triple
    print(f"    exhaustive over {n} triples, {len(seen)} distinct digests")
    assert len(seen) == n


def test_property_based_search():
    """Randomised search with a shrinker, over adversarial byte alphabets."""
    try:
        from hypothesis import given, settings, strategies as st, HealthCheck
    except ImportError:
        print("    hypothesis unavailable; skipped")
        return
    tricky = st.text(alphabet=st.sampled_from(list("ab/\x00\x01 ") + ["\u00e9"]),
                     min_size=0, max_size=8)
    payload = st.binary(min_size=0, max_size=8)

    seen: dict[str, tuple] = {}

    @given(m1=tricky, t1=tricky, p1=payload, m2=tricky, t2=tricky, p2=payload)
    @settings(max_examples=4000, deadline=None,
              suppress_health_check=[HealthCheck.function_scoped_fixture])
    def check(m1, t1, p1, m2, t2, p2):
        a, b = (m1, t1, p1), (m2, t2, p2)
        if a == b:
            return
        assert safe_digest(*a) != safe_digest(*b), f"collision: {a} vs {b}"

    check()
    print("    4000 randomised triples, no collision")


def test_digest_changes_with_every_field():
    """A field that does not affect the digest is a field not actually bound."""
    d = bind_digest("tools/call", "search", b"body")
    assert bind_digest("tools/list", "search", b"body") != d, "method not bound"
    assert bind_digest("tools/call", "other", b"body") != d, "target not bound"
    assert bind_digest("tools/call", "search", b"other") != d, "payload not bound"


def test_non_canonical_input_is_refused_not_normalised():
    """
    THE FINDING. bind_digest used to .strip(), so "search" and "search "
    produced the same digest: a gateway that strips and an upstream that does
    not can be made to disagree about which tool was authorised.
    """
    for m, n in [("tools/call", "search "), ("tools/call", " search"),
                 ("tools/call ", "search"), ("tools/call", "sea\x00rch"),
                 ("tools/call", " ")]:
        try:
            bind_digest(m, n, b"")
            raise AssertionError(f"non-canonical input accepted: {(m, n)!r}")
        except NonCanonicalHeader:
            pass


def test_digest_is_deterministic():
    a = bind_digest("tools/call", "search", b"x")
    b = bind_digest("tools/call", "search", b"x")
    assert a == b and len(a) >= 64


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    p = f_ = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); p += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:200]}"); f_ += 1
    print(f"\n{p} passed, {f_} failed")
    sys.exit(1 if f_ else 0)
