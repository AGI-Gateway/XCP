"""
test_telemetry.py — observability that does not become an exfiltration path.

Instrumentation is the easiest way to undo a privacy design: spans carrying
agent identifiers, tool names and counterparty hostnames get shipped to a
third-party vendor, and nobody reads the span schema. These tests pin the
default to scrubbed and keep payloads out at every level.

    python tests/test_telemetry.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from telemetry import (Detail, detail_level, pseudonym, scrub_scope,
                       call_attributes, SENSITIVE_AT_FULL, init, enabled,
                       status, call_span, record_decision)
from telemetry.attributes import A_AGENT, A_SCOPE, A_TIER, A_DECISION, A_REASON


# ── optional, and silent when absent ───────────────────────────────────────

def test_telemetry_is_off_unless_asked_for():
    """
    Checked in a fresh interpreter: `init()` latches a module global once
    enabled, so asserting on this process would only measure test ordering.
    """
    import subprocess
    env = {k: v for k, v in os.environ.items() if k != "XCP_OTEL"}
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r);"
         "from telemetry import init, status;"
         "print(init(), status()['enabled'])" % str(ROOT)],
        capture_output=True, text=True, env=env)
    assert r.stdout.strip() == "False False", r.stdout + r.stderr


def test_every_call_is_a_noop_when_disabled():
    """A node must run identically whether or not anyone is collecting."""
    with call_span("a2t", stream="a2t", agent_id=1) as span:
        record_decision(span, decision="allow", stream="a2t")
    # no exception is the assertion


def test_init_never_raises_on_a_broken_endpoint():
    os.environ["XCP_OTEL"] = "1"
    os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://127.0.0.1:1"
    try:
        init()          # must not throw: no telemetry beats no node
    finally:
        os.environ.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)


# ── scrubbed by default ────────────────────────────────────────────────────

def test_default_detail_is_scrubbed():
    os.environ.pop("XCP_OTEL_DETAIL", None)
    assert detail_level() is Detail.SCRUBBED


def test_an_unknown_detail_value_falls_back_to_scrubbed():
    os.environ["XCP_OTEL_DETAIL"] = "verbose-please"
    try:
        assert detail_level() is Detail.SCRUBBED
    finally:
        os.environ.pop("XCP_OTEL_DETAIL", None)


def test_agent_identifiers_are_pseudonymised_by_default():
    a = call_attributes(agent_id=42001, level=Detail.SCRUBBED)
    assert a[A_AGENT] != "42001" and a[A_AGENT].startswith("a_")


def test_pseudonyms_are_stable_within_a_process():
    """Otherwise you cannot say 'these 400 denials were the same caller'."""
    assert pseudonym(42001) == pseudonym(42001)
    assert pseudonym(42001) != pseudonym(42002)


def test_scope_names_are_reduced_to_a_family():
    """A tool name can identify a workload, a customer, or a person."""
    assert scrub_scope("mcp:tools/patient_lookup", Detail.SCRUBBED) == "mcp:tools/*"
    assert scrub_scope("mcp:tools/patient_lookup", Detail.FULL) == \
        "mcp:tools/patient_lookup"


def test_hostnames_are_pseudonymised_below_hosts_detail():
    a = call_attributes(server_host="clinic.example", level=Detail.SCRUBBED)
    assert "clinic.example" not in str(a)
    b = call_attributes(server_host="clinic.example", level=Detail.HOSTS)
    assert b["server.address"] == "clinic.example"


# ── the hard line: payloads never appear ───────────────────────────────────

def test_arguments_and_results_are_never_recorded_at_any_level():
    """
    A debug flag must not be able to turn an observability pipeline into a
    personal-data pipeline.
    """
    for level in (Detail.SCRUBBED, Detail.HOSTS, Detail.FULL):
        a = call_attributes(agent_id=1, scope="mcp:tools/x", level=level)
        keys = " ".join(a.keys()).lower()
        assert "argument" not in keys and "payload" not in keys
        assert "result" not in keys and "body" not in keys


def test_the_attribute_builder_has_no_parameter_for_payloads():
    import inspect
    params = set(inspect.signature(call_attributes).parameters)
    for forbidden in ("arguments", "payload", "body", "result", "principal",
                      "email", "subject"):
        assert forbidden not in params


# ── what a span is FOR ─────────────────────────────────────────────────────

def test_a_span_records_why_a_call_was_refused():
    """A latency number says a call was slow. An operator needs the reason."""
    a = call_attributes(decision="block", reason="scope not covered by mandate",
                        tier="A2xH2", stream="a2t")
    assert a[A_DECISION] == "block"
    assert "scope not covered" in a[A_REASON]
    assert a[A_TIER] == "A2xH2", "the tier is a category, not an identifier"


def test_reason_is_truncated_so_a_span_cannot_carry_a_payload():
    a = call_attributes(reason="x" * 5000)
    assert len(a[A_REASON]) <= 200


def test_sensitive_attributes_are_published_for_collector_config():
    """So the decision can be enforced in a collector, not merely trusted."""
    assert A_AGENT in SENSITIVE_AT_FULL and A_SCOPE in SENSITIVE_AT_FULL


# ── it must be declared as processing ──────────────────────────────────────

def test_telemetry_is_a_declared_data_class():
    """
    Adding OTel without declaring it creates a whole category of personal data
    processing the Art. 30 record does not cover.
    """
    from privacy import classify
    c = classify("telemetry")
    assert c.contains_personal_data
    assert c.erasable_on_request
    assert c.retention_days <= 90
    assert "export" in c.note.lower()


def test_the_data_map_warns_about_third_party_export():
    from privacy import classify
    note = classify("telemetry").note.lower()
    assert "processor" in note and "transfer" in note


# ── triage surfaces it ─────────────────────────────────────────────────────

def test_triage_flags_full_detail_as_high_severity():
    src = (ROOT / "ops" / "triage.py").read_text()
    assert "FULL detail" in src
    assert "third-party vendor" in src


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:130]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
