"""
xcpsec — optional security library for XCP (Multi-Model Secure Context Protocol).

An opt-in layer that hardens an XCP deployment against three threat classes the
core protocol deliberately leaves to the application:

  - MCP05 command injection    -> xcpsec.argfirewall (filter) + xcpsec.sandbox (containment)
  - MCP04 supply-chain tamper   -> xcpsec.supplychain
  - MCP06 prompt injection      -> xcpsec.contentfirewall

all sitting on a hardened mutual-TLS transport:

  - secured mTLS               -> xcpsec.mtls

MCP05 gets two complementary layers: the argument firewall blocks the injection
*surface*, and the sandbox *contains* execution so even a payload that evades the
filter hits a wall (resource limits, no_new_privs, network isolation, timeout).
Together they take MCP05 from "reduced" to "defense-in-depth".

Nothing here changes the XCP wire protocol; it is enforcement you add at the
gateway and inside tools. Each module is independently usable. The Guard class
below composes them into one policy object for the common case.

Install (optional extra): pip install eth-account eth-utils cryptography
Status: XCP / ERC-8004x are draft proposals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import mtls, argfirewall, supplychain, contentfirewall, sandbox
from .argfirewall import ArgumentFirewall, ArgSpec, Verdict
from .contentfirewall import ContentFirewall, Trust, guard_action_source
from .sandbox import (SandboxPolicy, run_sandboxed, run_python_sandboxed,
                      safe_eval, Result as SandboxResult)
from .supplychain import SupplyChainVerifier, ToolManifest
from .mtls import TLSPolicy

__version__ = "0.1.0-draft"


@dataclass
class GuardDecision:
    allowed: bool
    stage: str = ""
    reason: str = ""


@dataclass
class Guard:
    """
    Composes the argument firewall, supply-chain verifier, and content firewall
    into a single policy object a gateway or tool host can call per request.

        guard = Guard()
        guard.register_tool("research", "fetch",
                            {"url": ArgSpec(type="url")})
        guard.supply.pin("research", approved_digest)

        # before executing a call:
        d = guard.check_call("research", "fetch", {"url": url},
                             live_tools=server_tools)
        if not d.allowed: reject(d.reason)

        # after a tool returns, before the result reaches the model:
        block = guard.wrap_result(output, origin="research.fetch")
    """
    supply: SupplyChainVerifier = field(default_factory=SupplyChainVerifier)
    content: ContentFirewall = field(default_factory=ContentFirewall)
    sandbox_policy: SandboxPolicy = field(default_factory=SandboxPolicy)
    _schemas: dict[tuple[str, str], dict[str, ArgSpec]] = field(default_factory=dict)
    enforce_supplychain: bool = True

    def register_tool(self, server: str, tool: str,
                      schema: dict[str, ArgSpec]) -> None:
        self._schemas[(server, tool)] = schema

    def check_call(self, server: str, tool: str, arguments: dict[str, Any],
                   live_tools: Optional[list[dict]] = None) -> GuardDecision:
        # 1. supply chain: is this server's tool surface the one we approved?
        if self.enforce_supplychain and live_tools is not None:
            try:
                self.supply.verify_server(server, live_tools)
            except supplychain.SupplyChainError as e:
                return GuardDecision(False, "supplychain", str(e))
        # 2. argument firewall: are the arguments safe?
        schema = self._schemas.get((server, tool))
        if schema is not None:
            v = ArgumentFirewall(schema).check(arguments)
            if v.blocked:
                return GuardDecision(False, "argfirewall", v.reason())
        return GuardDecision(True, "ok", "")

    def wrap_result(self, content: str, *, trust: Trust = Trust.TOOL,
                    origin: str = "") -> contentfirewall.QuarantinedBlock:
        return self.content.wrap(content, trust=trust, origin=origin)

    def run_tool_sandboxed(self, argv: list, *,
                           policy: Optional[SandboxPolicy] = None) -> SandboxResult:
        """
        Execute a tool subprocess inside the sandbox (containment layer for
        MCP05). Use for any tool that shells out or runs untrusted code, so a
        payload that evades check_call's argument firewall is still contained.

            r = guard.run_tool_sandboxed(["python3", "-c", code],
                                        policy=SandboxPolicy(cpu_seconds=2,
                                                             allow_network=False))
        """
        return run_sandboxed(argv, policy or self.sandbox_policy)


__all__ = [
    "mtls", "argfirewall", "supplychain", "contentfirewall", "sandbox",
    "Guard", "GuardDecision",
    "ArgumentFirewall", "ArgSpec", "Verdict",
    "ContentFirewall", "Trust", "guard_action_source",
    "SupplyChainVerifier", "ToolManifest", "TLSPolicy",
    "SandboxPolicy", "run_sandboxed", "run_python_sandboxed", "safe_eval",
]
