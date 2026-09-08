"""
providers.registry — the open extension points.

XCP is infrastructure, not a marketplace. Two things must be addable by anyone,
without asking permission, without a commercial relationship, and without
touching the core:

    1. an MCP CONNECTION   — any MCP server, anywhere, at any trust class
    2. an INFERENCE MODEL  — any foundational model that drives an agent

Both are plain registries with a declarative record and a `register_*` call.
Adding one is a small pull request against `providers/` (or a runtime call, if
you would rather not publish it at all). Nothing here is gated: there is no
allowlist of blessed vendors, no key to obtain, no tier you must buy.

WHY THIS IS A REGISTRY AND NOT AN INTEGRATION
---------------------------------------------
A connection or a model is *declared*, not *wired*. The record says what the
thing is and how to reach it; the gateway, trust firewall and lattice then treat
it uniformly. That is what makes the corpus tractable: the 20k+ MCP servers in
the wild differ enormously in quality, but they are all the same *shape* to XCP
once declared, and the Trust Firewall grades them by class rather than by who
wrote the adapter.

The same holds for models. XCP is model-agnostic by design — the "Multi-Model"
in the name is a commitment, not branding. A model provider declares how it
emits tool calls; XCP maps that to scoped, mandate-gated actions. Adding a new
model does not require the core to know anything about that vendor.

Status: XCP and ERC-8004x are draft proposals. MCP is an independent
specification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Iterable, Optional


class ToolCallStyle(str, Enum):
    """How a model emits a request to use a tool."""
    NATIVE_MCP = "native_mcp"       # speaks MCP directly
    OPENAI_TOOLS = "openai_tools"   # {"tool_calls": [{"function": {...}}]}
    ANTHROPIC = "anthropic"          # {"type": "tool_use", "name": ..., "input": ...}
    JSON_SCHEMA = "json_schema"      # structured output constrained by a schema
    TEXT_DSL = "text_dsl"            # a text convention the adapter parses
    CUSTOM = "custom"                # bring your own normaliser


class Transport(str, Enum):
    STREAMABLE_HTTP = "streamable_http"   # MCP 2026-07-28 default
    STDIO = "stdio"
    WEBSOCKET = "websocket"
    HTTP_SSE = "http_sse"                 # deprecated in MCP 2026-07-28


class RegistryError(Exception):
    pass


# ── 1. MCP connections ─────────────────────────────────────────────────────

@dataclass
class MCPConnection:
    """
    A declared MCP server. Anyone may add one — for their own deployment, or
    upstream so others benefit.

        register_connection(MCPConnection(
            id="acme-research",
            name="Acme Research Tools",
            endpoint="https://mcp.acme.example/mcp",
            maintainer="anonymous",
        ))
    """
    id: str
    name: str
    endpoint: str
    description: str = ""
    transport: Transport = Transport.STREAMABLE_HTTP
    mcp_spec: str = "2026-07-28"
    auth: str = "xcp-mtls"              # xcp-mtls | oauth2 | none
    trust_class: str = "unknown"         # unknown | probed | attested | contracted
    tags: list[str] = field(default_factory=list)
    maintainer: str = "anonymous"
    homepage: str = ""

    def validate(self) -> list[str]:
        problems = []
        if not self.id or " " in self.id:
            problems.append("id must be non-empty and contain no spaces")
        if not self.endpoint.startswith(("https://", "stdio://")):
            problems.append("endpoint should be https:// (or stdio:// for local)")
        if self.trust_class not in ("unknown", "probed", "attested", "contracted"):
            problems.append(f"unknown trust_class '{self.trust_class}'")
        if self.transport == Transport.HTTP_SSE:
            problems.append("http_sse is deprecated in MCP 2026-07-28 "
                            "(12-month removal window)")
        return problems

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["transport"] = self.transport.value
        return d


_CONNECTIONS: dict[str, MCPConnection] = {}


def register_connection(conn: MCPConnection, *, replace: bool = False) -> MCPConnection:
    """Add an MCP connection. No approval step — validation only."""
    problems = conn.validate()
    hard = [p for p in problems if "deprecated" not in p]
    if hard:
        raise RegistryError(f"invalid connection '{conn.id}': {'; '.join(hard)}")
    if conn.id in _CONNECTIONS and not replace:
        raise RegistryError(f"connection '{conn.id}' already registered "
                            "(pass replace=True to override)")
    _CONNECTIONS[conn.id] = conn
    return conn


def connections() -> list[MCPConnection]:
    return sorted(_CONNECTIONS.values(), key=lambda c: c.id)


def get_connection(cid: str) -> Optional[MCPConnection]:
    return _CONNECTIONS.get(cid)


def apply_to_firewall(firewall: Any) -> int:
    """
    Push every registered connection's trust class into a TrustFirewall, so the
    graded-reachability rules apply without any per-server code.
    """
    from urllib.parse import urlparse
    try:
        from trustfirewall import ServerClass
    except ImportError:
        raise RegistryError("trustfirewall is not importable")
    mapping = {"unknown": ServerClass.UNKNOWN, "probed": ServerClass.PROBED,
               "attested": ServerClass.ATTESTED, "contracted": ServerClass.CONTRACTED}
    n = 0
    for c in connections():
        host = urlparse(c.endpoint).hostname
        if host:
            firewall.classify(host, mapping[c.trust_class])
            n += 1
    return n


# ── 2. inference models ────────────────────────────────────────────────────

@dataclass
class ModelProvider:
    """
    A foundational inference model that can drive an agent through XCP.

    XCP never calls the model itself — the agent does. What XCP needs to know is
    how the model *expresses* a tool call, so the gateway can map it onto a
    scoped, mandate-gated action. That is the whole contract, which is why any
    organisation can add their own model without changing the core.

        register_model(ModelProvider(
            id="acme-llm-1",
            name="Acme LLM 1",
            vendor="anonymous",
            tool_call_style=ToolCallStyle.OPENAI_TOOLS,
        ))
    """
    id: str
    name: str
    vendor: str = "anonymous"
    tool_call_style: ToolCallStyle = ToolCallStyle.NATIVE_MCP
    endpoint: str = ""                    # empty = self-hosted / caller-supplied
    context_window: int = 0
    supports_streaming: bool = True
    supports_parallel_tools: bool = False
    self_hostable: bool = False
    open_weights: bool = False
    notes: str = ""
    # optional: turn a raw model tool-call into (tool_name, arguments)
    normaliser: Optional[Callable[[Any], tuple[str, dict]]] = None

    def validate(self) -> list[str]:
        problems = []
        if not self.id or " " in self.id:
            problems.append("id must be non-empty and contain no spaces")
        if self.tool_call_style == ToolCallStyle.CUSTOM and self.normaliser is None:
            problems.append("tool_call_style=CUSTOM requires a normaliser callable")
        return problems

    def normalise(self, raw: Any) -> tuple[str, dict]:
        """
        Turn this model's tool-call representation into (tool_name, arguments),
        which is what the gateway needs to derive an XCP scope.
        """
        if self.normaliser is not None:
            return self.normaliser(raw)
        return _BUILTIN_NORMALISERS[self.tool_call_style](raw)

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in asdict(self).items() if k != "normaliser"}
        d["tool_call_style"] = self.tool_call_style.value
        d["hasCustomNormaliser"] = self.normaliser is not None
        return d


def _n_native(raw: Any) -> tuple[str, dict]:
    # already MCP-shaped: {"name": ..., "arguments": {...}}
    if isinstance(raw, dict) and "name" in raw:
        return str(raw["name"]), dict(raw.get("arguments") or {})
    raise RegistryError("native_mcp expects {'name':…, 'arguments':{…}}")


def _n_openai(raw: Any) -> tuple[str, dict]:
    # {"function": {"name": ..., "arguments": "<json string>"}}
    fn = (raw or {}).get("function", raw)
    name = fn.get("name", "")
    args = fn.get("arguments", {})
    if isinstance(args, str):
        try:
            args = json.loads(args or "{}")
        except json.JSONDecodeError:
            args = {}
    if not name:
        raise RegistryError("openai_tools expects a function name")
    return name, dict(args)


def _n_anthropic(raw: Any) -> tuple[str, dict]:
    # {"type": "tool_use", "name": ..., "input": {...}}
    if not isinstance(raw, dict) or "name" not in raw:
        raise RegistryError("anthropic expects {'name':…, 'input':{…}}")
    return str(raw["name"]), dict(raw.get("input") or {})


def _n_json_schema(raw: Any) -> tuple[str, dict]:
    if not isinstance(raw, dict):
        raise RegistryError("json_schema expects an object")
    name = raw.get("tool") or raw.get("name") or ""
    if not name:
        raise RegistryError("json_schema expects a 'tool' or 'name' field")
    args = raw.get("arguments") or raw.get("input") or raw.get("parameters") or {}
    return str(name), dict(args)


def _n_text_dsl(raw: Any) -> tuple[str, dict]:
    # "tool_name {json}"  — a minimal convention for models without tool APIs
    s = raw if isinstance(raw, str) else str(raw)
    name, _, rest = s.strip().partition(" ")
    if not name:
        raise RegistryError("text_dsl expects '<tool> <json-args>'")
    try:
        args = json.loads(rest) if rest.strip() else {}
    except json.JSONDecodeError:
        args = {}
    return name, dict(args)


def _n_custom(raw: Any) -> tuple[str, dict]:
    raise RegistryError("CUSTOM style requires a normaliser callable")


_BUILTIN_NORMALISERS: dict[ToolCallStyle, Callable[[Any], tuple[str, dict]]] = {
    ToolCallStyle.NATIVE_MCP: _n_native,
    ToolCallStyle.OPENAI_TOOLS: _n_openai,
    ToolCallStyle.ANTHROPIC: _n_anthropic,
    ToolCallStyle.JSON_SCHEMA: _n_json_schema,
    ToolCallStyle.TEXT_DSL: _n_text_dsl,
    ToolCallStyle.CUSTOM: _n_custom,
}


_MODELS: dict[str, ModelProvider] = {}


def register_model(model: ModelProvider, *, replace: bool = False) -> ModelProvider:
    """Add an inference model. No approval step — validation only."""
    problems = model.validate()
    if problems:
        raise RegistryError(f"invalid model '{model.id}': {'; '.join(problems)}")
    if model.id in _MODELS and not replace:
        raise RegistryError(f"model '{model.id}' already registered "
                            "(pass replace=True to override)")
    _MODELS[model.id] = model
    return model


def models() -> list[ModelProvider]:
    return sorted(_MODELS.values(), key=lambda m: m.id)


def get_model(mid: str) -> Optional[ModelProvider]:
    return _MODELS.get(mid)


def scope_for_model_call(model_id: str, raw_tool_call: Any) -> str:
    """
    End-to-end helper: take whatever a model emitted and return the XCP scope the
    gateway will gate on. This is the seam that makes XCP model-agnostic.
    """
    m = get_model(model_id)
    if m is None:
        raise RegistryError(f"unknown model '{model_id}'")
    name, _args = m.normalise(raw_tool_call)
    try:
        from trustfirewall import scope_for
        return scope_for("tools/call", name)
    except ImportError:
        return f"mcp:tools/{name}"


# ── seeding + export ───────────────────────────────────────────────────────

def load_builtin() -> tuple[int, int]:
    """
    Seed the registries with vendor-neutral reference entries. These exist so
    the shape is obvious and the tests have something to bite on — not as an
    endorsement, and not as a closed list.
    """
    for m in [
        ModelProvider(id="reference-native", name="Reference (native MCP)",
                      tool_call_style=ToolCallStyle.NATIVE_MCP,
                      notes="Any model whose harness already speaks MCP."),
        ModelProvider(id="reference-openai-style", name="Reference (OpenAI-style tools)",
                      tool_call_style=ToolCallStyle.OPENAI_TOOLS,
                      notes="The most common third-party tool-call shape."),
        ModelProvider(id="reference-anthropic-style", name="Reference (Anthropic-style tool_use)",
                      tool_call_style=ToolCallStyle.ANTHROPIC),
        ModelProvider(id="reference-open-weights", name="Reference (self-hosted, open weights)",
                      tool_call_style=ToolCallStyle.JSON_SCHEMA,
                      self_hostable=True, open_weights=True,
                      notes="Run it on your own hardware; XCP never phones home."),
    ]:
        try:
            register_model(m)
        except RegistryError:
            pass
    return len(_MODELS), len(_CONNECTIONS)


def export() -> dict[str, Any]:
    """Everything registered, as plain data — for docs, UIs or catalog builds."""
    return {
        "connections": [c.to_dict() for c in connections()],
        "models": [m.to_dict() for m in models()],
    }


def reset() -> None:
    """Clear both registries (tests)."""
    _CONNECTIONS.clear()
    _MODELS.clear()


__all__ = [
    "MCPConnection", "ModelProvider", "ToolCallStyle", "Transport",
    "register_connection", "connections", "get_connection", "apply_to_firewall",
    "register_model", "models", "get_model", "scope_for_model_call",
    "load_builtin", "export", "reset", "RegistryError",
]
