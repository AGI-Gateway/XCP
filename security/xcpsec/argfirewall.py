"""
xcpsec.argfirewall — argument validation and safe execution (MCP05).

Command injection happens when a tool builds a shell command, SQL string, URL,
or path from untrusted input without validation. This module is the enforcement
point that sits between the gateway's authorization decision and the tool's
handler: once XCP has decided *who* may call a tool and *whether* they're
authorized, the argument firewall decides whether the *arguments* are safe.

It provides three layers:

  1. Schema validation — arguments must match a declared type/shape allowlist.
  2. Threat scanning — shell metacharacters, path traversal, SSRF targets, and
     SQL/template metacharacters are detected in string arguments.
  3. Safe execution — helpers that run commands with NO shell and fetch URLs
     with SSRF guards, so even a passed-through value can't spawn a subshell or
     reach internal metadata endpoints.

This does not make an arbitrary tool safe — a tool that deliberately evals its
input is still unsafe — but it removes the default injection surface and gives
tool authors a correct-by-construction path. Pair it with sandboxing for full
MCP05 coverage.

Standard library only. Status: XCP / ERC-8004x are draft proposals.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from urllib.parse import urlparse


class Severity(Enum):
    OK = "ok"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class Finding:
    severity: Severity
    rule: str
    detail: str


@dataclass
class Verdict:
    allowed: bool
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return not self.allowed

    def reason(self) -> str:
        blocks = [f"{f.rule}: {f.detail}" for f in self.findings
                  if f.severity == Severity.BLOCK]
        return "; ".join(blocks) or "ok"


# ── threat signatures ───────────────────────────────────────────────────────

# Shell metacharacters that enable command chaining / substitution.
_SHELL_META = re.compile(r"[;&|`$><\n\r]|\$\(|\|\||&&|>>|<<")
# Common command-injection payload shapes.
_INJECT_HINTS = re.compile(
    r"(?:\b(?:rm|curl|wget|nc|bash|sh|python|perl|eval|exec)\b\s|/etc/passwd"
    r"|\.\./|%2e%2e|\bunion\b\s+\bselect\b|--\s|;\s*drop\b)",
    re.IGNORECASE)
# Template/expression injection.
_TEMPLATE = re.compile(r"\{\{.*?\}\}|\$\{.*?\}|<%.*?%>")

# Hostnames/addresses that indicate SSRF to internal infrastructure.
_SSRF_HOSTS = {
    "localhost", "metadata", "metadata.google.internal",
    "169.254.169.254",  # cloud metadata (AWS/GCP/Azure)
    "kubernetes.default", "kubernetes.default.svc",
}


def _is_internal_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False


# ── schema validation ───────────────────────────────────────────────────────

@dataclass
class ArgSpec:
    """A minimal, allowlist-first argument specification."""
    type: str                                 # str|int|float|bool|list|url|path|enum
    required: bool = True
    max_length: int = 4096
    pattern: Optional[str] = None             # regex the string must fully match
    choices: Optional[list[Any]] = None       # enum allowlist
    item_type: Optional[str] = None           # for list


class ArgumentFirewall:
    """
    Validate and threat-scan a tool call's arguments.

        fw = ArgumentFirewall({
            "url": ArgSpec(type="url"),
            "depth": ArgSpec(type="int", required=False),
        })
        verdict = fw.check({"url": "https://example.com", "depth": 2})
        if verdict.blocked: ...
    """

    def __init__(self, schema: dict[str, ArgSpec], *,
                 block_on_warn: bool = False) -> None:
        self.schema = schema
        self.block_on_warn = block_on_warn

    def check(self, args: dict[str, Any]) -> Verdict:
        findings: list[Finding] = []

        # 1. reject unexpected keys (allowlist)
        for key in args:
            if key not in self.schema:
                findings.append(Finding(Severity.BLOCK, "unknown_arg",
                                        f"argument '{key}' is not in the schema"))

        # 2. per-field validation + scanning
        for name, spec in self.schema.items():
            if name not in args:
                if spec.required:
                    findings.append(Finding(Severity.BLOCK, "missing_arg",
                                            f"required argument '{name}' absent"))
                continue
            findings.extend(self._check_field(name, args[name], spec))

        allowed = not any(f.severity == Severity.BLOCK for f in findings)
        if self.block_on_warn and any(f.severity == Severity.WARN for f in findings):
            allowed = False
        return Verdict(allowed=allowed, findings=findings)

    def _check_field(self, name: str, value: Any, spec: ArgSpec) -> list[Finding]:
        out: list[Finding] = []
        t = spec.type

        # type checks
        if t in ("str", "url", "path", "enum") and not isinstance(value, str):
            return [Finding(Severity.BLOCK, "type", f"'{name}' must be a string")]
        if t == "int" and not isinstance(value, int):
            return [Finding(Severity.BLOCK, "type", f"'{name}' must be an int")]
        if t == "float" and not isinstance(value, (int, float)):
            return [Finding(Severity.BLOCK, "type", f"'{name}' must be a number")]
        if t == "bool" and not isinstance(value, bool):
            return [Finding(Severity.BLOCK, "type", f"'{name}' must be a bool")]
        if t == "list" and not isinstance(value, list):
            return [Finding(Severity.BLOCK, "type", f"'{name}' must be a list")]

        if isinstance(value, str):
            if len(value) > spec.max_length:
                out.append(Finding(Severity.BLOCK, "length",
                                   f"'{name}' exceeds {spec.max_length} chars"))
            if spec.pattern and not re.fullmatch(spec.pattern, value):
                out.append(Finding(Severity.BLOCK, "pattern",
                                   f"'{name}' does not match required pattern"))
            out.extend(self._scan_string(name, value, spec))

        if t == "enum" and spec.choices is not None and value not in spec.choices:
            out.append(Finding(Severity.BLOCK, "enum",
                               f"'{name}' not in allowed choices"))
        if t == "list" and spec.item_type and isinstance(value, list):
            for i, item in enumerate(value):
                out.extend(self._check_field(f"{name}[{i}]", item,
                                             ArgSpec(type=spec.item_type)))
        return out

    def _scan_string(self, name: str, value: str, spec: ArgSpec) -> list[Finding]:
        out: list[Finding] = []
        if spec.type == "url":
            out.extend(self._scan_url(name, value))
            return out
        if spec.type == "path":
            if ".." in value or value.startswith("/") or value.startswith("~"):
                out.append(Finding(Severity.BLOCK, "path_traversal",
                                   f"'{name}' looks like an absolute/traversal path"))
        # generic injection scanning for free-text string args
        if _SHELL_META.search(value):
            out.append(Finding(Severity.BLOCK, "shell_meta",
                               f"'{name}' contains shell metacharacters"))
        if _INJECT_HINTS.search(value):
            out.append(Finding(Severity.BLOCK, "injection",
                               f"'{name}' matches a command-injection signature"))
        if _TEMPLATE.search(value):
            out.append(Finding(Severity.WARN, "template",
                               f"'{name}' contains template/expression syntax"))
        return out

    def _scan_url(self, name: str, value: str) -> list[Finding]:
        out: list[Finding] = []
        try:
            u = urlparse(value)
        except Exception:
            return [Finding(Severity.BLOCK, "url", f"'{name}' is not a valid URL")]
        if u.scheme not in ("http", "https"):
            out.append(Finding(Severity.BLOCK, "url_scheme",
                               f"'{name}' scheme '{u.scheme}' not allowed"))
        host = (u.hostname or "").lower()
        if host in _SSRF_HOSTS or _is_internal_ip(host):
            out.append(Finding(Severity.BLOCK, "ssrf",
                               f"'{name}' targets an internal/metadata host"))
        return out


# ── safe execution helpers ──────────────────────────────────────────────────

def safe_run(argv: list[str], *, timeout: float = 10,
             allow_binaries: Optional[set[str]] = None) -> subprocess.CompletedProcess:
    """
    Run a command with NO shell. `argv` must be a pre-split list — never a
    string — so there is no shell to inject into. Optionally restrict to an
    allowlist of binary names.

        safe_run(["git", "status"], allow_binaries={"git"})
    """
    if not isinstance(argv, list) or not argv:
        raise ValueError("argv must be a non-empty list (never a shell string)")
    if allow_binaries is not None and argv[0] not in allow_binaries:
        raise PermissionError(f"binary '{argv[0]}' is not in the allowlist")
    # shell=False is the default and the whole point; make it explicit.
    return subprocess.run(argv, shell=False, capture_output=True, text=True,
                          timeout=timeout, check=False)


def safe_shlex(untrusted: str) -> list[str]:
    """
    Turn an untrusted string into a safely-split argv, rejecting anything with
    shell metacharacters. Use when you must accept a free-form command-ish
    string but want to pass it to safe_run without a shell.
    """
    if _SHELL_META.search(untrusted):
        raise ValueError("input contains shell metacharacters; refusing to split")
    return shlex.split(untrusted)


def ssrf_guard(url: str) -> None:
    """Raise if a URL targets internal infrastructure. Call before fetching."""
    fw = ArgumentFirewall({"url": ArgSpec(type="url")})
    v = fw.check({"url": url})
    if v.blocked:
        raise PermissionError(f"SSRF guard: {v.reason()}")


__all__ = [
    "ArgumentFirewall", "ArgSpec", "Verdict", "Finding", "Severity",
    "safe_run", "safe_shlex", "ssrf_guard",
]
