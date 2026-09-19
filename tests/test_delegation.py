"""
test_delegation.py — passing a sealed credential onward without losing control.

Sealing is single-hop. A multi-hop workflow forced the caller to hold a key per
hop, and in practice that means callers stop sealing and hand over a bearer
credential instead — losing the property the mechanism exists for.

    python tests/test_delegation.py
"""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vault.sealed import (generate_recipient_key, seal_chained, open_chained,
                          delegate, acceptable, ChainedCredential, SealError)


def _hop():
    return generate_recipient_key()


def test_a_chained_credential_opens_at_each_hop():
    kg, Kg = _hop(); kw, Kw = _hop()
    c = seal_chained("sk_live_SECRET", Kg, origin="agent", max_hops=2)
    assert "sk_live" not in c.blob
    c2 = delegate(c, kg, Kg, Kw, from_node="gateway", to_node="wrapper-a")
    assert open_chained(c2, kw, Kw) == "sk_live_SECRET"


def test_the_originators_budget_cannot_be_exceeded():
    kg, Kg = _hop(); kw, Kw = _hop(); kx, Kx = _hop()
    c = seal_chained("s", Kg, origin="agent", max_hops=1)
    c2 = delegate(c, kg, Kg, Kw, from_node="gateway", to_node="wrapper-a")
    try:
        delegate(c2, kw, Kw, Kx, from_node="wrapper-a", to_node="wrapper-b")
        assert False, "a hop must not grant itself authority the originator withheld"
    except SealError as e:
        assert "budget exhausted" in str(e)


def test_budget_is_checked_before_decryption():
    """A chain out of hops must not cause a decryption that was not permitted."""
    src = (ROOT / "vault" / "sealed.py").read_text()
    body = src[src.index("def delegate("):]
    assert body.index("budget exhausted") < body.index("open_chained(")


def test_a_node_cannot_appear_twice_in_a_chain():
    kg, Kg = _hop(); kw, Kw = _hop()
    c = seal_chained("s", Kg, origin="agent", max_hops=5)
    c2 = delegate(c, kg, Kg, Kw, from_node="gateway", to_node="wrapper-a")
    for target in ("gateway", "agent", "wrapper-a"):
        try:
            delegate(c2, kw, Kw, Kg, from_node="wrapper-a", to_node=target)
            assert False, f"a loop back to {target} must be refused"
        except SealError:
            pass


def test_a_hop_cannot_rewrite_the_recorded_path():
    """The chain is bound into the AAD, so history cannot be edited silently."""
    kg, Kg = _hop(); kw, Kw = _hop(); kx, Kx = _hop()
    c = seal_chained("s", Kg, origin="agent", max_hops=3)
    c2 = delegate(c, kg, Kg, Kw, from_node="gateway", to_node="wrapper-a")
    c3 = delegate(c2, kw, Kw, Kx, from_node="wrapper-a", to_node="wrapper-b")
    forged = ChainedCredential(blob=c3.blob, origin=c3.origin,
                               max_hops=c3.max_hops, hops=c3.hops[:1])
    try:
        open_chained(forged, kx, Kx)
        assert False, "a rewritten path must not open"
    except SealError:
        pass


def test_a_recipient_applies_its_own_policy_to_the_path():
    """A budget says how far; it says nothing about through whom."""
    kg, Kg = _hop(); kw, Kw = _hop(); kx, Kx = _hop()
    c = seal_chained("s", Kg, origin="agent", max_hops=3)
    c2 = delegate(c, kg, Kg, Kw, from_node="gateway", to_node="wrapper-a")
    c3 = delegate(c2, kw, Kw, Kx, from_node="wrapper-a", to_node="wrapper-b")
    assert acceptable(c3, allowed_hops={"wrapper-a", "wrapper-b"}) == []
    assert acceptable(c3, allowed_hops={"wrapper-a"}), "unlisted hop must be flagged"
    assert acceptable(c3, max_depth=1), "a too-deep chain must be flagged"


def test_the_limit_is_documented_rather_than_overclaimed():
    """Re-sealing needs plaintext at the hop; the chain adds accountability,
    not secrecy from intermediaries. Claiming otherwise would be false."""
    src = (ROOT / "vault" / "sealed.py").read_text().lower()
    assert "momentarily" in src and "accountability" in src
    assert "seal directly to" in src


def test_round_trips_over_the_wire():
    import json
    kg, Kg = _hop(); kw, Kw = _hop()
    c = seal_chained("s", Kg, origin="agent", max_hops=2)
    c2 = delegate(c, kg, Kg, Kw, from_node="gateway", to_node="wrapper-a")
    revived = ChainedCredential.from_dict(json.loads(json.dumps(c2.to_dict())))
    assert open_chained(revived, kw, Kw) == "s"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    p = f_ = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); p += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:120]}"); f_ += 1
    print(f"\n{p} passed, {f_} failed")
    sys.exit(1 if f_ else 0)
