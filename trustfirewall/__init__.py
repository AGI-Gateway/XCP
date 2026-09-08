"""
trustfirewall — stateless identity and graded corpus reachability for MCP.

Targets the MCP 2026-07-28 specification, which removed protocol sessions and
made `Mcp-Method` / `Mcp-Name` mandatory routing headers. XCP replaces the
session with a per-request, call-bound credential, and decides authorization
from headers alone.

    from trustfirewall import TrustFirewall, ServerClass, mint

Status: XCP and ERC-8004x are draft proposals; MCP is an independent spec.
"""
from .stateless import (RequestCredential, McpRequest, mint, verify, scope_for,
                        bind_digest, new_flow, CredentialError,
                        H_MCP_METHOD, H_MCP_NAME, H_XCP_CREDENTIAL,
                        MCP_SPEC_TARGET, DEPRECATED_METHODS)
from .firewall import (TrustFirewall, Decision, Effect, ServerClass,
                       Obligations, reachability, corpus_matrix, is_read_only)

__all__ = [
    "RequestCredential", "McpRequest", "mint", "verify", "scope_for",
    "bind_digest", "new_flow", "CredentialError", "H_MCP_METHOD", "H_MCP_NAME",
    "H_XCP_CREDENTIAL", "MCP_SPEC_TARGET", "DEPRECATED_METHODS",
    "TrustFirewall", "Decision", "Effect", "ServerClass", "Obligations",
    "reachability", "corpus_matrix", "is_read_only",
]
