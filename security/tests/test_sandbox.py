"""
test_sandbox.py — proves xcpsec.sandbox actually contains untrusted execution.

Tests are written to be non-destructive to the host (no large allocations): we
verify the *enforcement* of each limit through effects that are safe to trigger.

    python security/tests/test_sandbox.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xcpsec.sandbox import (SandboxPolicy, Capabilities, run_sandboxed,
                            run_python_sandboxed, safe_eval, UnsafeExpression,
                            SandboxError)


def test_capabilities_detect_runs():
    caps = Capabilities.detect()
    # we don't assert specific values (host-dependent) — just that detection
    # returns a coherent object and describe() reflects it.
    d = SandboxPolicy().describe(caps)
    assert "resource_limits" in d and "network_isolated" in d
    print(f"    caps: rlimits={caps.resource_limits} nnp={caps.no_new_privs} "
          f"netns={caps.net_namespace} mountns={caps.mount_namespace}")


def test_no_shell_string_rejected():
    try:
        run_sandboxed("echo hi")            # a string, not a list
        assert False, "should reject shell string"
    except SandboxError:
        pass


def test_basic_command_runs_and_captures():
    r = run_sandboxed(["echo", "hello sandbox"])
    assert r.ok, (r.returncode, r.stderr)
    assert "hello sandbox" in r.stdout
    assert "wall_timeout" in r.applied


def test_shell_metachars_are_literal_not_executed():
    # if a shell were involved, the ; and rm would do damage; with no shell the
    # whole thing is a single literal argument to echo.
    r = run_sandboxed(["echo", "x; rm -rf /tmp/should_not_happen"])
    assert "rm -rf" in r.stdout       # printed literally => never executed
    assert not Path("/tmp/should_not_happen").exists()


def test_binary_allowlist_enforced():
    try:
        run_sandboxed(["curl", "http://example.com"],
                      SandboxPolicy(allow_binaries={"echo", "python3"}))
        assert False, "curl should be blocked by the allowlist"
    except SandboxError:
        pass
    # allowed binary passes the check
    r = run_sandboxed(["echo", "ok"], SandboxPolicy(allow_binaries={"echo"}))
    assert r.ok


def test_cpu_limit_kills_busy_loop():
    # an infinite loop must be killed by RLIMIT_CPU or the wall timeout.
    t0 = time.time()
    r = run_python_sandboxed("i=0\nwhile True:\n    i+=1",
                             SandboxPolicy(cpu_seconds=1, wall_seconds=6))
    elapsed = time.time() - t0
    assert not r.ok                     # it was killed, not clean
    assert elapsed < 6                  # killed by CPU limit before wall time
    print(f"    busy loop killed after {elapsed:.1f}s (rc={r.returncode})")


def test_wall_timeout_kills_sleeper():
    # a process that sleeps past the wall clock is killed and flagged.
    t0 = time.time()
    r = run_python_sandboxed("import time\ntime.sleep(30)",
                             SandboxPolicy(cpu_seconds=30, wall_seconds=2))
    elapsed = time.time() - t0
    assert r.timed_out
    assert elapsed < 8, f"should have been killed near 2s, took {elapsed:.1f}s"
    print(f"    sleeper killed after {elapsed:.1f}s (timed_out={r.timed_out})")


def test_file_size_limit_blocks_large_write():
    # writing beyond RLIMIT_FSIZE fails inside the sandbox.
    code = ("try:\n"
            "    open('/tmp/xcp_big','w').write('A'*5_000_000)\n"
            "    print('WROTE')\n"
            "except Exception as e:\n"
            "    print('BLOCKED', type(e).__name__)")
    r = run_python_sandboxed(code, SandboxPolicy(max_file_mb=1, cpu_seconds=3))
    assert "WROTE" not in r.stdout, "large write should be blocked"
    # cleanup any partial file
    try:
        Path("/tmp/xcp_big").unlink()
    except FileNotFoundError:
        pass


def test_env_is_scrubbed():
    # a secret in the parent env must not reach the child (only allowlist passes)
    import os
    os.environ["SUPER_SECRET"] = "leak-me"
    try:
        r = run_python_sandboxed(
            "import os\nprint('SECRET' if 'SUPER_SECRET' in os.environ else 'CLEAN')")
        assert "CLEAN" in r.stdout, "env should be scrubbed"
    finally:
        del os.environ["SUPER_SECRET"]


def test_network_isolation_when_available():
    caps = Capabilities.detect()
    if not caps.net_namespace:
        print("    (skip: network namespaces not available on this host)")
        return
    code = ("import socket\n"
            "socket.setdefaulttimeout(3)\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1',53),timeout=3)\n"
            "    print('REACHABLE')\n"
            "except Exception as e:\n"
            "    print('BLOCKED', type(e).__name__)")
    r = run_python_sandboxed(code, SandboxPolicy(allow_network=False, wall_seconds=8))
    assert "REACHABLE" not in r.stdout, "network should be isolated"
    assert "network_isolation" in r.applied
    print(f"    network isolated: {r.stdout.strip()}")


# ── safe_eval ───────────────────────────────────────────────────────────────

def test_safe_eval_arithmetic():
    assert safe_eval("2 * (3 + 4)") == 14
    assert safe_eval("a + b", {"a": 10, "b": 5}) == 15
    assert safe_eval("2 ** 8") == 256
    assert safe_eval("10 > 3 and 4 <= 4") is True
    assert safe_eval("[1, 2, 3]") == [1, 2, 3]


def test_safe_eval_blocks_escapes():
    for payload in [
        "__import__('os').system('id')",
        "().__class__.__bases__",
        "open('/etc/passwd').read()",
        "eval('1+1')",
        "(lambda: 1)()",
        "[x for x in range(10)]",
        "a.b",
        "globals()",
        "unknown_name + 1",
    ]:
        try:
            safe_eval(payload)
            assert False, f"should reject: {payload}"
        except UnsafeExpression:
            pass


def test_safe_eval_bounds_exponent():
    try:
        safe_eval("2 ** 999999999")
        assert False, "huge exponent should be rejected"
    except UnsafeExpression:
        pass


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
