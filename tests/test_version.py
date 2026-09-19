"""
test_version.py — two implementations must be able to discover what they share.

This project has already shipped breaking wire changes with no compatibility
path. In one repository that is untidy; in a federation it is fatal, because two
nodes on different versions fail in ways neither can diagnose.

    python tests/test_version.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from protocol import (SUPPORTED, CURRENT, MINIMUM, Feature, IMPLEMENTED,
                      negotiate, VersionError, parse_accept, request_headers,
                      response_headers, DEPRECATIONS, read_compat,
                      deprecation_warnings, advertisement, compatible_with)


# ── the source of truth ────────────────────────────────────────────────────

def test_current_and_minimum_are_supported():
    assert CURRENT in SUPPORTED and MINIMUM in SUPPORTED
    assert SUPPORTED[-1] == CURRENT, "SUPPORTED should be ordered oldest first"


def test_implemented_features_are_real():
    """Advertising a capability you lack is worse than advertising none: a peer
    will rely on it."""
    for f in IMPLEMENTED:
        assert isinstance(f, Feature)
    # CHAIN is optional everywhere and must not be claimed by default
    assert Feature.CHAIN not in IMPLEMENTED


def test_module_versions_do_not_contradict_the_source_of_truth():
    """
    Eight scattered constants was the original problem. Any module still
    declaring its own wire version must not claim something SUPPORTED denies.
    """
    import re
    for mod in ("federation/node.py", "federation/transport.py",
                "receipts/receipt.py", "federation/identity.py"):
        src = (ROOT / mod).read_text()
        for m in re.findall(r'SPEC_VERSION\s*=\s*"([^"]+)"', src):
            base = m.split("-")[0]
            assert base in SUPPORTED, f"{mod} declares {m}, not in SUPPORTED"


# ── negotiation ────────────────────────────────────────────────────────────

def test_picks_the_highest_common_version():
    assert negotiate(["0.1", "0.2"]).version == "0.2"
    assert negotiate(["0.2"]).version == "0.2"


def test_downgrades_for_a_legacy_peer_and_says_so():
    n = negotiate(["0.1"])
    assert n.version == "0.1" and n.downgraded
    assert "prefers" in n.note


def test_no_overlap_is_refused_not_guessed():
    """Treating an unknown version as the current one is how a peer silently
    misreads a field that changed meaning."""
    try:
        negotiate(["9.9"])
        assert False, "must refuse rather than guess"
    except VersionError as e:
        assert "no common protocol version" in str(e)
        assert "9.9" in str(e), "the error should show what was asked for"


def test_a_silent_caller_gets_the_oldest_not_the_newest():
    """Assuming a silent peer is current is optimistic in the direction that
    breaks things."""
    assert negotiate([]).version == MINIMUM


def test_features_are_intersected_not_assumed():
    n = negotiate(["0.2"], client_features=["session", "mandate"])
    assert n.features == frozenset({Feature.SESSION, Feature.MANDATE})


def test_unknown_feature_names_are_ignored_not_fatal():
    n = negotiate(["0.2"], client_features=["session", "telepathy"])
    assert Feature.SESSION in n.features
    assert len(n.features) == 1


def test_a_peer_cannot_negotiate_a_feature_we_lack():
    n = negotiate(["0.2"], client_features=["chain"])
    assert Feature.CHAIN not in n.features


def test_headers_round_trip():
    req = request_headers()
    assert parse_accept(req["XCP-Accept-Versions"]) == list(SUPPORTED)
    res = response_headers(negotiate(parse_accept(req["XCP-Accept-Versions"])))
    assert res["XCP-Version"] == CURRENT


def test_malformed_version_is_rejected():
    try:
        negotiate(["not-a-version"])
        assert False
    except VersionError:
        pass


# ── deprecation on a clock ─────────────────────────────────────────────────

def test_every_deprecation_has_a_replacement_and_a_date():
    """A breaking change with no removal date is either never removed or removed
    by surprise."""
    assert DEPRECATIONS, "renames already shipped; they must be recorded"
    import re
    for d in DEPRECATIONS:
        assert d.since in SUPPORTED, f"{d.old} since {d.since}"
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", d.remove_after), d.old
        assert d.note, f"{d.old} needs an explanation"


def test_the_renames_this_project_actually_shipped_are_recorded():
    olds = {d.old for d in DEPRECATIONS}
    assert "slyTrustTier" in olds and "_sly" in olds
    assert "Mcp-Session-Id" in olds


def test_reader_accepts_the_deprecated_spelling_and_warns():
    value, warning = read_compat({"slyTrustTier": "A2xH2"}, "xcpTrustTier")
    assert value == "A2xH2"
    assert warning and "deprecated" in warning and "xcpTrustTier" in warning


def test_reader_prefers_the_current_spelling():
    value, warning = read_compat({"xcpTrustTier": "A1xH1",
                                  "slyTrustTier": "A2xH2"}, "xcpTrustTier")
    assert value == "A1xH1" and warning is None


def test_reader_returns_the_default_when_neither_is_present():
    value, warning = read_compat({}, "xcpTrustTier", default="none")
    assert value == "none" and warning is None


def test_deprecated_keys_are_surfaced():
    warns = deprecation_warnings({"slyTrustTier": "x", "other": 1})
    assert len(warns) == 1 and "slyTrustTier" in warns[0]


# ── advertisement and peering ──────────────────────────────────────────────

def test_advertisement_is_complete_and_serialisable():
    import json
    a = advertisement()
    json.dumps(a)
    assert a["protocolCurrent"] == CURRENT
    assert set(a) >= {"protocolVersions", "protocolCurrent", "features",
                      "deprecations"}


def test_peer_compatibility_is_checked_before_peering():
    ok, _ = compatible_with({"protocolVersions": ["0.2"]})
    assert ok
    bad, msg = compatible_with({"protocolVersions": ["3.0"]})
    assert not bad and "no common" in msg


def test_a_peer_advertising_nothing_is_refused():
    ok, msg = compatible_with({})
    assert not ok and "no protocol version" in msg


def test_federation_refuses_an_incompatible_node_record():
    from federation import NodeRecord, verify_node_record, digest
    der = b"--cert--"
    rec = NodeRecord(domain="b.example", node_id=digest(der),
                     gateway_url="https://b.example", protocol_versions=["3.0"])
    problems = verify_node_record(rec, der, "b.example")
    assert any("cannot federate" in p for p in problems)


def test_a_legacy_record_without_versions_still_peers():
    """Records predating negotiation must not be locked out."""
    from federation import NodeRecord, verify_node_record, digest
    der = b"--cert--"
    rec = NodeRecord(domain="a.example", node_id=digest(der),
                     gateway_url="https://a.example")
    assert verify_node_record(rec, der, "a.example") == []


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
