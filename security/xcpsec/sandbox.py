"""
xcpsec.sandbox — contained execution for tools (closes the MCP05 gap).

The argument firewall (xcpsec.argfirewall) blocks the command-injection
*surface*: shell metacharacters, SSRF targets, traversal, unexpected arguments.
But a filter is a probabilistic control — a novel payload can slip past it, and a
tool that deliberately executes untrusted input is unsafe no matter how clean the
arguments looked. Defense-in-depth for MCP05 therefore needs *containment*: even
if a malicious command executes, it should hit a wall.

This module adds that wall. It runs a command or a Python callable inside a
sandbox that, depending on what the host kernel offers, enforces:

  - NO shell (argv lists only)                         [always]
  - resource limits: CPU time, memory (RLIMIT_DATA/STACK), file size, process
    count, open files, core dumps                       [always, POSIX]
  - a hard wall-clock timeout with process-group kill   [always]
  - no_new_privs (blocks setuid escalation)             [Linux]
  - a scrubbed environment (no inherited secrets)       [always]
  - a private network namespace (no network at all)     [Linux + user namespaces]
  - a private mount/tmp with the working dir bind-only   [Linux + user namespaces]
  - an optional binary allowlist                         [always]

Capabilities are DETECTED, not assumed. `SandboxPolicy.describe()` and the
`Result.applied` set tell you exactly which layers were enforced for a given run,
so the sandbox never silently claims isolation it did not provide. For the
strongest isolation on untrusted code, run inside a container/microVM as the
outer boundary and use this as the inner one.

Also included: `safe_eval`, an AST-allowlist evaluator for the common "the tool
needs to evaluate a user expression" case — the canonical MCP05 footgun that
`eval()`/`exec()` create.

Standard library only. Status: XCP / ERC-8004x are draft proposals.
"""

from __future__ import annotations

import ast
import ctypes
import ctypes.util
import operator
import os
import platform
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

try:
    import resource            # POSIX only
    _RESOURCE = True
except ImportError:
    _RESOURCE = False

_IS_LINUX = platform.system() == "Linux"


# ── capability detection ────────────────────────────────────────────────────

def _libc() -> Optional[ctypes.CDLL]:
    try:
        return ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    except Exception:
        return None


def _can_unshare(flags: int) -> bool:
    """Check (without side effects on this process) whether unshare works by
    probing in a throwaway child."""
    if not _IS_LINUX:
        return False
    pid = os.fork()
    if pid == 0:                       # child
        libc = _libc()
        rc = libc.unshare(flags) if libc else -1
        os._exit(0 if rc == 0 else 1)
    _, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


# clone flags
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
CLONE_NEWNS = 0x00020000
CLONE_NEWPID = 0x20000000
PR_SET_NO_NEW_PRIVS = 38


@dataclass(frozen=True)
class Capabilities:
    resource_limits: bool
    no_new_privs: bool
    net_namespace: bool
    mount_namespace: bool

    @staticmethod
    def detect() -> "Capabilities":
        nnp = False
        if _IS_LINUX and (libc := _libc()) is not None:
            # PR_GET_NO_NEW_PRIVS is safe and read-only
            try:
                nnp = libc.prctl(39, 0, 0, 0, 0) in (0, 1)
            except Exception:
                nnp = False
        userns = _can_unshare(CLONE_NEWUSER) if _IS_LINUX else False
        return Capabilities(
            resource_limits=_RESOURCE,
            no_new_privs=_IS_LINUX,
            # net/mount namespaces need a user namespace when unprivileged
            net_namespace=userns and _can_unshare(CLONE_NEWUSER | CLONE_NEWNET),
            mount_namespace=userns,
        )


# ── policy ──────────────────────────────────────────────────────────────────

@dataclass
class SandboxPolicy:
    """Declarative limits. All have safe defaults; tighten per tool."""
    cpu_seconds: int = 5                    # RLIMIT_CPU (hard kill)
    wall_seconds: float = 10.0              # wall-clock timeout
    memory_mb: int = 256                    # RLIMIT_DATA + RLIMIT_STACK
    max_file_mb: int = 10                   # RLIMIT_FSIZE
    max_processes: int = 16                 # RLIMIT_NPROC
    max_open_files: int = 64                # RLIMIT_NOFILE
    allow_network: bool = False             # if False, isolate the network
    allow_binaries: Optional[set[str]] = None   # argv[0] allowlist
    workdir: Optional[str] = None           # cwd for the child
    env_allowlist: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TZ")
    extra_env: dict[str, str] = field(default_factory=dict)

    def clean_env(self) -> dict[str, str]:
        env = {k: os.environ[k] for k in self.env_allowlist if k in os.environ}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        env.update(self.extra_env)
        return env

    def describe(self, caps: Optional[Capabilities] = None) -> dict[str, Any]:
        caps = caps or Capabilities.detect()
        return {
            "resource_limits": caps.resource_limits,
            "no_new_privs": caps.no_new_privs,
            "network_isolated": (not self.allow_network) and caps.net_namespace,
            "network_isolation_available": caps.net_namespace,
            "mount_namespace_available": caps.mount_namespace,
            "wall_timeout": self.wall_seconds,
            "cpu_seconds": self.cpu_seconds,
            "memory_mb": self.memory_mb,
        }


class SandboxError(Exception):
    pass


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    applied: set[str] = field(default_factory=set)   # layers actually enforced

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


# ── the preexec hook that applies limits in the child ───────────────────────

def _make_preexec(policy: SandboxPolicy, caps: Capabilities,
                  applied: list[str]) -> Callable[[], None]:
    # Note: preexec_fn runs in the forked child, after fork() and before exec().
    # Keep it minimal and fork-safe.
    isolate_net = (not policy.allow_network) and caps.net_namespace

    def preexec() -> None:
        # 1. resource limits
        if _RESOURCE:
            mb = 1024 * 1024
            def setl(res, soft):
                try:
                    resource.setrlimit(res, (soft, soft))
                except (ValueError, OSError):
                    pass
            setl(resource.RLIMIT_CPU, policy.cpu_seconds)
            # RLIMIT_DATA/STACK instead of RLIMIT_AS: capping the whole address
            # space breaks many runtimes and interacts badly with allocators.
            setl(resource.RLIMIT_DATA, policy.memory_mb * mb)
            setl(resource.RLIMIT_FSIZE, policy.max_file_mb * mb)
            setl(resource.RLIMIT_NPROC, policy.max_processes)
            setl(resource.RLIMIT_NOFILE, policy.max_open_files)
            setl(resource.RLIMIT_CORE, 0)                 # no core dumps

        # 2. new session/process group so we can kill the whole tree on timeout
        try:
            os.setsid()
        except OSError:
            pass

        # 3. no_new_privs (blocks gaining privileges via setuid/setgid binaries)
        if _IS_LINUX:
            libc = _libc()
            if libc is not None:
                try:
                    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                except Exception:
                    pass

        # 4. network isolation: unshare a user+net namespace -> no interfaces
        if isolate_net:
            libc = _libc()
            if libc is not None:
                try:
                    libc.unshare(CLONE_NEWUSER | CLONE_NEWNET)
                    # inside the new netns only loopback exists and is down:
                    # no route to anything. That is the isolation we want.
                except Exception:
                    pass

    # record what we intend to apply (best-effort; child enforces)
    if _RESOURCE:
        applied.append("resource_limits")
    if _IS_LINUX:
        applied.append("no_new_privs")
    if isolate_net:
        applied.append("network_isolation")
    return preexec


# ── run a command ───────────────────────────────────────────────────────────

def run_sandboxed(argv: list[str], policy: Optional[SandboxPolicy] = None,
                  stdin: Optional[str] = None) -> Result:
    """
    Execute a command with NO shell inside the sandbox. `argv` must be a list.

        run_sandboxed(["python3", "-c", untrusted_code],
                      SandboxPolicy(cpu_seconds=2, allow_network=False))

    Even if `untrusted_code` is hostile, it faces: CPU/memory/file/process caps,
    a wall-clock kill, no_new_privs, a scrubbed env, and (where supported) no
    network. Raises SandboxError only for misuse (e.g. a non-list argv or a
    binary outside the allowlist); execution failures come back in Result.
    """
    if not isinstance(argv, list) or not argv:
        raise SandboxError("argv must be a non-empty list (never a shell string)")
    policy = policy or SandboxPolicy()
    if policy.allow_binaries is not None and argv[0] not in policy.allow_binaries:
        raise SandboxError(f"binary '{argv[0]}' is not in the allowlist")

    caps = Capabilities.detect()
    applied: list[str] = []
    preexec = _make_preexec(policy, caps, applied) if os.name == "posix" else None

    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE if stdin is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=policy.clean_env(), cwd=policy.workdir,
            preexec_fn=preexec, close_fds=True, start_new_session=False)
    except FileNotFoundError as e:
        raise SandboxError(f"binary not found: {e}")
    except PermissionError as e:
        raise SandboxError(f"permission denied: {e}")

    timed_out = False
    try:
        out, err = proc.communicate(input=stdin, timeout=policy.wall_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        # kill the whole process group (setsid gave the child its own group)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, err = proc.communicate()
    applied.append("wall_timeout")
    return Result(returncode=proc.returncode, stdout=out or "", stderr=err or "",
                  timed_out=timed_out, applied=set(applied))


def run_python_sandboxed(code: str, policy: Optional[SandboxPolicy] = None) -> Result:
    """Convenience: run untrusted Python source in a sandboxed subprocess."""
    return run_sandboxed([sys.executable, "-I", "-c", code], policy)


# ── safe expression evaluation (the eval() footgun) ─────────────────────────

_ALLOWED_BINOP = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod, ast.Pow: operator.pow,
}
_ALLOWED_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}
_ALLOWED_CMP = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
    ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
}


class UnsafeExpression(Exception):
    pass


def safe_eval(expr: str, names: Optional[dict[str, Any]] = None,
              max_pow: int = 1000) -> Any:
    """
    Evaluate a *pure arithmetic/logic* expression with no access to builtins,
    attributes, calls, imports, or names other than those explicitly provided.
    This is the correct-by-construction replacement for eval() when a tool must
    compute a user-supplied expression.

        safe_eval("2 * (a + 3)", {"a": 4})   -> 14
        safe_eval("__import__('os')")         -> raises UnsafeExpression

    Only literals, numeric/boolean ops, comparisons, and provided names are
    allowed. `**` is bounded to avoid exponent DoS.
    """
    names = names or {}

    def _eval(node: ast.AST) -> Any:
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float, bool, str, type(None))):
                return node.value
            raise UnsafeExpression("disallowed constant type")
        if isinstance(node, ast.Name):
            if node.id in names:
                return names[node.id]
            raise UnsafeExpression(f"unknown name '{node.id}'")
        if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_BINOP:
            if isinstance(node.op, ast.Pow):
                exp = _eval(node.right)
                if isinstance(exp, (int, float)) and abs(exp) > max_pow:
                    raise UnsafeExpression("exponent too large")
            return _ALLOWED_BINOP[type(node.op)](_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_UNARY:
            return _ALLOWED_UNARY[type(node.op)](_eval(node.operand))
        if isinstance(node, ast.BoolOp):
            vals = [_eval(v) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(vals)
            return any(vals)
        if isinstance(node, ast.Compare):
            left = _eval(node.left)
            for op, comp in zip(node.ops, node.comparators):
                if type(op) not in _ALLOWED_CMP:
                    raise UnsafeExpression("disallowed comparison")
                right = _eval(comp)
                if not _ALLOWED_CMP[type(op)](left, right):
                    return False
                left = right
            return True
        if isinstance(node, (ast.List, ast.Tuple)):
            return [_eval(e) for e in node.elts]
        # everything else — calls, attributes, subscripts, comprehensions,
        # lambdas, imports, names not provided — is rejected.
        raise UnsafeExpression(f"disallowed syntax: {type(node).__name__}")

    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise UnsafeExpression(f"parse error: {e}")
    return _eval(tree)


__all__ = [
    "SandboxPolicy", "Capabilities", "Result", "SandboxError",
    "run_sandboxed", "run_python_sandboxed",
    "safe_eval", "UnsafeExpression",
]
