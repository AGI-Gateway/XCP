# Providers


**This is the part of XCP you are meant to change.**

Two things any organisation can add — without permission, without a commercial
relationship, and without touching the core:

| | |
|---|---|
| **An MCP connection** | any MCP server, anywhere, at any trust class |
| **An inference model** | any foundational model that drives an agent |

There is no allowlist of blessed vendors, no key to obtain, no tier to buy, and
no approval step. Validation is the only gate.

## Add an MCP connection

```python
from providers import MCPConnection, register_connection

register_connection(MCPConnection(
    id="acme-research",
    name="Acme Research Tools",
    endpoint="https://mcp.acme.example/mcp",
    description="Filing search and summarisation",
    trust_class="unknown",        # unknown | probed | attested | contracted
    maintainer="anonymous",
))
```

New servers start at `unknown` — **reachable, not blocked**. The
[Trust Firewall](trust-firewall.md) grades them: unknown means
read-only, observed, sandboxed, output quarantined, nothing binding. Climb by
passing the safety gate (`probed`), pinning a signed manifest (`attested`), or
having a legal entity stand behind it (`contracted`).

Push every declared connection into a running firewall in one call:

```python
from providers import apply_to_firewall
apply_to_firewall(firewall)     # classifies by hostname; no per-server code
```

## Add an inference model

XCP never calls your model. What it needs to know is how the model *expresses* a
tool call, so the gateway can map it onto a scoped, mandate-gated action. That is
the entire contract — which is why adding a model changes nothing in the core.

```python
from providers import ModelProvider, ToolCallStyle, register_model

register_model(ModelProvider(
    id="acme-llm-1",
    name="Acme LLM 1",
    tool_call_style=ToolCallStyle.OPENAI_TOOLS,
    self_hostable=True,
    open_weights=True,
))
```

Built-in styles, all normalising to the same `(tool_name, arguments)` shape:

| style | shape it accepts |
|---|---|
| `NATIVE_MCP` | `{"name": …, "arguments": {…}}` |
| `OPENAI_TOOLS` | `{"function": {"name": …, "arguments": "<json>"}}` |
| `ANTHROPIC` | `{"type": "tool_use", "name": …, "input": {…}}` |
| `JSON_SCHEMA` | `{"tool": …, "arguments": {…}}` |
| `TEXT_DSL` | `search {"q":"x"}` — for models with no tool API |
| `CUSTOM` | supply your own `normaliser` callable |

If none fit, use `CUSTOM` and pass a function. You never need a core change.

```python
from providers import scope_for_model_call
scope_for_model_call("acme-llm-1",
                     {"function": {"name": "search", "arguments": "{}"}})
# → "mcp:tools/search"   ← the scope the gateway gates on
```

## Why registries, not integrations

A connection or a model is **declared**, not wired. The record says what the
thing is and how to reach it; the gateway, trust firewall and lattice then treat
it uniformly.

That is what makes tens of thousands of MCP servers tractable. They differ
enormously in quality, but they are all the same *shape* to XCP once declared,
and the firewall grades them by class rather than by who wrote the adapter.

The same holds for models. **"Multi-Model" is a commitment, not branding.** The
reference entries are deliberately vendor-neutral, and one of them is a
self-hosted, open-weights path — XCP never phones home, and nothing here depends
on a hosted API.

## Contributing one upstream

Open a PR adding your entry. Attribution defaults to `anonymous`, and you are
welcome to leave it that way. You are equally welcome to register at runtime and
never publish it at all — the registry works the same either way.
