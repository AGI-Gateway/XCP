"""
test_config_drift.py — configuration cannot go undocumented again.

Two thirds of this system's environment variables were undocumented, including
several that turn security controls off. An operator cannot make a safe decision
about a setting they do not know exists.

This test reads the source for every variable the code actually consults and
fails if any is missing from the registry, so the reference stays true without
anyone remembering to update it.

    python tests/test_config_drift.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ops.config import SETTINGS, get, unsafe, secrets, Role, table

SKIP_DIRS = {".git", "__pycache__", "site", "dist", "node_modules"}
ENV_READ = re.compile(r'os\.(?:getenv|environ\.get)\(\s*["\']([A-Z][A-Z0-9_]*)["\']')


def _read_by_code() -> set[str]:
    found: set[str] = set()
    for p in ROOT.rglob("*.py"):
        if any(d in p.parts for d in SKIP_DIRS):
            continue
        if p.name.startswith("test_"):
            continue                       # tests set their own fixtures
        try:
            found |= set(ENV_READ.findall(p.read_text(encoding="utf-8")))
        except (UnicodeDecodeError, PermissionError):
            continue
    return found


def test_every_setting_the_code_reads_is_declared():
    undeclared = sorted(n for n in _read_by_code() if get(n) is None)
    assert not undeclared, (
        "these environment variables are read but undocumented, so an operator "
        f"cannot reason about them: {undeclared}")


def test_no_declared_setting_is_dead():
    """A reference listing settings nothing reads is its own kind of wrong."""
    read = _read_by_code()
    dead = [s.name for s in SETTINGS
            if not s.name.endswith("*") and s.name not in read]
    assert not dead, f"declared but never read: {dead}"


def test_settings_that_weaken_a_control_are_marked():
    """These are the ones an operator must find deliberately, not stumble onto."""
    names = {s.name for s in unsafe()}
    for expected in ("XCP_POSTURE", "XCP_RATE_LIMIT", "XCP_LIMIT_FAIL_OPEN",
                     "REQUIRE_VERIFIED", "XCP_OTEL_DETAIL"):
        assert expected in names, f"{expected} weakens a control but is not marked"


def test_secrets_are_marked_and_default_to_empty():
    for s in secrets():
        assert s.default == "", f"{s.name} ships a default secret"


def test_the_unrecoverable_setting_says_so():
    node_key = get("XCP_NODE_KEY")
    assert node_key.secret
    assert "UNRECOVERABLE" in node_key.description.upper()


def test_every_setting_explains_itself():
    for s in SETTINGS:
        assert len(s.description) > 30, f"{s.name} has no useful description"
        assert s.role in Role


def test_defaults_are_safe():
    """A fresh deployment must not start with a control already off."""
    assert get("XCP_POSTURE").default == "enforce"
    assert get("XCP_RATE_LIMIT").default == "1"
    assert get("XCP_LIMIT_FAIL_OPEN").default == "0"
    assert get("REQUIRE_VERIFIED").default == "1"
    assert get("XCP_OTEL_DETAIL").default == "scrubbed"


def test_the_runbook_documents_the_unsafe_settings():
    rb = (ROOT / "docs" / "runbook.md").read_text()
    for s in unsafe():
        assert s.name in rb, f"{s.name} weakens a control and is not in the runbook"


def test_the_runbook_has_a_day_zero_deployment_section():
    rb = (ROOT / "docs" / "runbook.md").read_text().lower()
    assert "standing up a node" in rb
    for step in ("xcp_node_key", "certificate", "xcp triage"):
        assert step in rb, f"day-zero is missing: {step}"


def test_the_runbook_inventories_the_diagnostic_tools():
    rb = (ROOT / "docs" / "runbook.md").read_text()
    for tool in ("xcp triage", "xcp doctor", "xcp conform", "xcp config",
                 "make bench", "/health", "/metrics"):
        assert tool in rb, f"diagnostic not listed in the runbook: {tool}"


def test_config_table_renders():
    assert "weakens a control" in table()
    assert "XCP_POSTURE" in table(Role.GATEWAY)


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:160]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
