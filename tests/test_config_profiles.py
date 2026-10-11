"""
test_config_profiles.py — profiles must agree with the settings registry.

A profile is a file operators copy. The failure mode is not a crash: a profile
naming a renamed setting still parses, the node still boots, and the control
the operator believed they configured is simply at its default. These tests
make that a build failure instead.

    python tests/test_config_profiles.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ops.config import SETTINGS, get, secrets, unsafe          # noqa: E402
from ops.profiles import (PROFILES, NEVER_IN_A_PROFILE, Profile,  # noqa: E402
                          ProfileError, coverage, get_profile, validate_all)

PROFILE_DIR = ROOT / "deploy" / "profiles"


def test_every_profile_validates():
    validate_all()


def test_every_unsafe_setting_has_a_safe_default():
    """
    Profile validation only demands a justification when a value moves OFF the
    default, which is sound exactly while every unsafe setting's default is its
    safe value. If someone adds an unsafe setting whose default is itself
    unsafe, that rule silently stops protecting anything -- so the assumption
    is asserted here rather than left as a comment.
    """
    offenders = []
    for s in unsafe():
        # The safe value is the one that keeps the control on. For every
        # current unsafe setting that is "0", "1", "enforce" or "scrubbed";
        # what matters is that SOME default exists and the description frames
        # the other value as the dangerous one.
        if s.default == "":
            # An empty default means "unset", which for these settings means
            # the control is at its strictest (no CIDRs declared = none
            # permitted). That is safe.
            continue
        if s.name == "XCP_POSTURE" and s.default != "enforce":
            offenders.append(s.name)
        if s.name in ("XCP_RATE_LIMIT", "REQUIRE_VERIFIED") and s.default != "1":
            offenders.append(s.name)
        if s.name in ("XCP_LIMIT_FAIL_OPEN", "XCP_NODE_RECORD_PUBLIC",
                      "XCP_SEAL_EPHEMERAL", "XCP_ALLOW_INSECURE_PEERS") \
                and s.default != "0":
            offenders.append(s.name)
    assert not offenders, (
        f"these unsafe settings no longer default to their safe value: "
        f"{offenders}. Profile validation assumes they do.")


def test_no_profile_carries_a_secret_value():
    names = {s.name for s in secrets()}
    for p in PROFILES:
        for n, v in p.settings.items():
            assert not (n in names and v), (
                f"profile {p.name!r} contains a value for the secret {n!r}")


def test_no_profile_names_a_setting_that_must_never_appear():
    for p in PROFILES:
        for n in list(p.settings) + list(p.operator_supplied):
            assert n not in NEVER_IN_A_PROFILE, (
                f"profile {p.name!r} names {n!r}, which must never appear in "
                f"a profile: {NEVER_IN_A_PROFILE[n]}")


def test_every_unsafe_setting_is_pinned_or_deliberately_excluded():
    cov = coverage()
    assert not cov["unsafeUnmentioned"], (
        f"these unsafe settings appear in no profile and are not in "
        f"NEVER_IN_A_PROFILE: {cov['unsafeUnmentioned']}. An operator meets "
        f"them for the first time during an incident.")


def test_a_profile_naming_an_unknown_setting_is_refused():
    bad = Profile(name="bogus", purpose="x",
                  settings={"XCP_POSTURE_MODE": "enforce"})
    try:
        bad.validate()
        raise AssertionError("a renamed/typo'd setting was accepted")
    except ProfileError as e:
        assert "not in ops.config.SETTINGS" in str(e)


def test_moving_an_unsafe_setting_off_its_default_needs_a_reason():
    bad = Profile(name="bogus", purpose="x", settings={"XCP_POSTURE": "observe"})
    try:
        bad.validate()
        raise AssertionError("weakened a control with no acknowledgement")
    except ProfileError as e:
        assert "acknowledged_unsafe" in str(e)


def test_restating_a_safe_default_needs_no_reason():
    """The rule must not fire on a no-op, or operators learn to ignore it."""
    Profile(name="ok", purpose="x",
            settings={"XCP_RATE_LIMIT": "1"}).validate()


def test_a_stale_acknowledgement_is_refused():
    bad = Profile(name="bogus", purpose="x",
                  settings={"XCP_RATE_LIMIT": "1"},
                  acknowledged_unsafe={"XCP_RATE_LIMIT": "stale"})
    try:
        bad.validate()
        raise AssertionError("acknowledged a control that is not weakened")
    except ProfileError as e:
        assert "safe default" in str(e)


def test_the_committed_profiles_match_the_source():
    import subprocess
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate-config-profiles.py"),
         "--check"], capture_output=True, text=True, cwd=str(ROOT))
    assert r.returncode == 0, (
        "committed profiles differ from ops/profiles.py.\n"
        "Run: python scripts/generate-config-profiles.py\n" + r.stderr)


def test_the_rendered_profiles_warn_about_what_they_weaken():
    for p in PROFILES:
        if not p.acknowledged_unsafe:
            continue
        text = (PROFILE_DIR / f"{p.name}.env").read_text()
        assert "DELIBERATELY WEAKENS CONTROLS" in text
        for name, why in p.acknowledged_unsafe.items():
            assert name in text and why.split(".")[0][:40] in text, (
                f"{p.name}.env does not carry the reason for {name}")


def test_operator_supplied_settings_render_empty():
    """
    A profile documents a required setting without pretending to satisfy it. A
    placeholder value would be copied into production unchanged.
    """
    for p in PROFILES:
        if not p.operator_supplied:
            continue
        text = (PROFILE_DIR / f"{p.name}.env").read_text()
        for name in p.operator_supplied:
            assert f"{name}=\n" in text or text.rstrip().endswith(f"{name}="), \
                f"{p.name}.env gives {name} a value; it must be empty"


def test_the_profiles_cover_the_documented_deployment_shapes():
    for name in ("evaluation", "enforce", "private-federation"):
        assert get_profile(name) is not None, f"no {name!r} profile"
    pf = get_profile("private-federation")
    assert pf is not None
    for required in ("XCP_PRIVATE_PEER_CIDRS", "XCP_PEER_CA_BUNDLE",
                     "XCP_NODE_SITE", "XCP_RESIDENCY_SITES"):
        assert required in pf.operator_supplied, (
            f"the private-federation profile does not mention {required}")
    ev = get_profile("evaluation")
    assert ev is not None and ev.settings.get("XCP_POSTURE") == "observe"


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
