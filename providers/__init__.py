"""
providers — the open extension points.

Two things anyone can add, without permission and without touching the core:

    register_connection(MCPConnection(...))   # any MCP server, any trust class
    register_model(ModelProvider(...))        # any foundational inference model

See providers/README.md. MIT licensed; no allowlist, no gatekeeper.
"""
from .registry import (MCPConnection, ModelProvider, ToolCallStyle, Transport,
                       register_connection, connections, get_connection,
                       apply_to_firewall, register_model, models, get_model,
                       scope_for_model_call, load_builtin, export, reset,
                       RegistryError)

__all__ = [
    "MCPConnection", "ModelProvider", "ToolCallStyle", "Transport",
    "register_connection", "connections", "get_connection", "apply_to_firewall",
    "register_model", "models", "get_model", "scope_for_model_call",
    "load_builtin", "export", "reset", "RegistryError",
]
