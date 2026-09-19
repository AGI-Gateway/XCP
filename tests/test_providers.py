"""
test_providers.py — the extension points stay open.

The point of these tests is not that the registry works (it is a dict), but that
adding a connection or a model requires no privilege, no vendor-specific core
change, and no allowlist.

    python tests/test_providers.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from providers import (MCPConnection, ModelProvider, ToolCallStyle, Transport,
                       register_connection, register_model, connections, models,
                       get_connection, get_model, scope_for_model_call,
                       apply_to_firewall, load_builtin, export, reset,
                       RegistryError)


def setup():
    reset()


# ── MCP connections ────────────────────────────────────────────────────────

def test_anyone_can_add_a_connection():
    setup()
    c = register_connection(MCPConnection(
        id="acme-research", name="Acme Research",
        endpoint="https://mcp.acme.example/mcp"))
    assert get_connection("acme-research") is c
    assert c.maintainer == "anonymous", "attribution defaults to anonymous"
    assert c.trust_class == "unknown", "new servers start untrusted, not blocked"


def test_connection_validation_is_the_only_gate():
    setup()
    for bad in [
        MCPConnection(id="", name="x", endpoint="https://a.example/mcp"),
        MCPConnection(id="has space", name="x", endpoint="https://a.example/mcp"),
        MCPConnection(id="ok", name="x", endpoint="ftp://a.example"),
        MCPConnection(id="ok2", name="x", endpoint="https://a.example/mcp",
                      trust_class="platinum"),
    ]:
        try:
            register_connection(bad)
            assert False, f"should reject {bad.id!r}"
        except RegistryError:
            pass


def test_no_duplicate_without_explicit_replace():
    setup()
    c = MCPConnection(id="dup", name="x", endpoint="https://a.example/mcp")
    register_connection(c)
    try:
        register_connection(c)
        assert False, "silent overwrite would let one publisher hijack another"
    except RegistryError:
        pass
    register_connection(c, replace=True)          # explicit is fine


def test_deprecated_transport_warns_but_does_not_block():
    setup()
    c = MCPConnection(id="legacy", name="Legacy", endpoint="https://a.example/mcp",
                      transport=Transport.HTTP_SSE)
    assert any("deprecated" in p for p in c.validate())
    register_connection(c)                         # still registers — 12-month window
    assert get_connection("legacy") is not None


def test_connections_feed_the_trust_firewall():
    setup()
    from trustfirewall import TrustFirewall, ServerClass
    register_connection(MCPConnection(id="a", name="A",
                                      endpoint="https://probed.example/mcp",
                                      trust_class="probed"))
    register_connection(MCPConnection(id="b", name="B",
                                      endpoint="https://partner.example/mcp",
                                      trust_class="contracted"))
    fw = TrustFirewall()
    n = apply_to_firewall(fw)
    assert n == 2
    assert fw.class_of("probed.example") == ServerClass.PROBED
    assert fw.class_of("partner.example") == ServerClass.CONTRACTED
    assert fw.class_of("never-declared.example") == ServerClass.UNKNOWN


# ── inference models ───────────────────────────────────────────────────────

def test_anyone_can_add_a_model():
    setup()
    m = register_model(ModelProvider(id="acme-llm", name="Acme LLM"))
    assert get_model("acme-llm") is m
    assert m.vendor == "anonymous"


def test_every_builtin_style_normalises_to_the_same_shape():
    setup()
    cases = [
        (ToolCallStyle.NATIVE_MCP, {"name": "search", "arguments": {"q": "x"}}),
        (ToolCallStyle.OPENAI_TOOLS,
         {"function": {"name": "search", "arguments": '{"q":"x"}'}}),
        (ToolCallStyle.ANTHROPIC,
         {"type": "tool_use", "name": "search", "input": {"q": "x"}}),
        (ToolCallStyle.JSON_SCHEMA, {"tool": "search", "arguments": {"q": "x"}}),
        (ToolCallStyle.TEXT_DSL, 'search {"q":"x"}'),
    ]
    for style, raw in cases:
        m = register_model(ModelProvider(id=f"m-{style.value}", name=style.value,
                                         tool_call_style=style), replace=True)
        name, args = m.normalise(raw)
        assert name == "search", f"{style} gave {name}"
        assert args == {"q": "x"}, f"{style} gave {args}"


def test_custom_style_requires_a_normaliser():
    setup()
    try:
        register_model(ModelProvider(id="c", name="c",
                                     tool_call_style=ToolCallStyle.CUSTOM))
        assert False, "CUSTOM without a normaliser should be rejected"
    except RegistryError:
        pass
    m = register_model(ModelProvider(
        id="c", name="c", tool_call_style=ToolCallStyle.CUSTOM,
        normaliser=lambda raw: (raw.split(":")[0], {"v": raw.split(":")[1]})))
    assert m.normalise("search:x") == ("search", {"v": "x"})


def test_model_call_maps_to_an_xcp_scope():
    setup()
    register_model(ModelProvider(id="m", name="m",
                                 tool_call_style=ToolCallStyle.OPENAI_TOOLS))
    scope = scope_for_model_call(
        "m", {"function": {"name": "search", "arguments": "{}"}})
    assert scope == "mcp:tools/search", scope


def test_unknown_model_is_an_error_not_a_default():
    setup()
    try:
        scope_for_model_call("nope", {"name": "x", "arguments": {}})
        assert False, "unknown model must not silently pass through"
    except RegistryError:
        pass


def test_builtins_are_vendor_neutral():
    setup()
    load_builtin()
    assert len(models()) >= 4
    for m in models():
        assert m.vendor == "anonymous", f"{m.id} names a vendor"
        assert "reference" in m.id, f"{m.id} is not a neutral reference entry"
    # a self-hostable, open-weights path exists — no dependency on a hosted API
    assert any(m.self_hostable and m.open_weights for m in models())


def test_export_is_plain_data():
    setup()
    load_builtin()
    register_connection(MCPConnection(id="a", name="A",
                                      endpoint="https://a.example/mcp"))
    import json
    blob = json.dumps(export())          # must be serialisable for docs/catalogs
    assert "connections" in blob and "models" in blob


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
