# xcpsec — Optional Security Library for XCP

An opt-in defense layer that hardens an XCP deployment against three threat
classes the core protocol deliberately leaves to the application, on top of a
hardened mutual-TLS transport.

| Module | Threat class | What it does |
|--------|-------------|--------------|
| [`mtls`](xcpsec/mtls.py) | transport | TLS 1.3 mutual auth, cert pinning by footprint, AgentBinding-OID extraction, RFC 9266 channel binding |
| [`argfirewall`](xcpsec/argfirewall.py) | **MCP05** command injection (filter) | argument allowlist + shell/SSRF/traversal scanning + no-shell execution helpers |
| [`sandbox`](xcpsec/sandbox.py) | **MCP05** command injection (containment) | resource limits + no_new_privs + network/mount isolation + wall-clock kill + `safe_eval` |
| [`supplychain`](xcpsec/supplychain.py) | **MCP04** supply chain | signed, pinned tool manifests — rug pulls and schema poisoning become digest mismatches |
| [`contentfirewall`](xcpsec/contentfirewall.py) | **MCP06** prompt injection | provenance tainting + quarantine boundaries + injection scanning + confused-deputy guard |

```bash
pip install eth-account eth-utils cryptography   # optional extras
python security/tests/test_xcpsec.py             # 17 passing tests
python security/examples/secured_gateway.py      # end-to-end demo
```

## An honest statement of what this does

None of these modules "solve" their threat class in the sense of making it
impossible — that would be a false claim, especially for prompt injection.
What they do is **turn open-ended attacks into contained, observable, and
mostly-blocked events**, and give developers a correct-by-construction path.
The precise coverage:

- **Command injection (MCP05): defense-in-depth (filter + containment).** Two
  complementary layers. The argument firewall (`xcpsec.argfirewall`) blocks the
  injection *surface* — shell metacharacters, SSRF targets, path traversal,
  unexpected arguments — and `safe_run` removes the shell entirely. The sandbox
  (`xcpsec.sandbox`) then *contains* execution, so a payload that evades the
  filter still hits a wall: CPU/memory/file/process limits, a wall-clock kill,
  `no_new_privs`, a scrubbed environment, and — where the kernel supports it —
  network and mount-namespace isolation. `safe_eval` closes the `eval()` footgun
  for tools that must evaluate a user expression. Capabilities are *detected*,
  and `Result.applied` reports exactly which layers were enforced, so the
  sandbox never overstates its isolation. For fully untrusted code, run inside a
  container/microVM as the outer boundary too.
- **Supply chain (MCP04): strongly addressed for tool-surface tampering.**
  Pinned, signed manifests detect rug pulls, schema poisoning, tool shadowing,
  and unapproved (shadow) servers as cryptographic mismatches. It does not scan
  your dependency tree — pair with SBOM/dependency scanning for the code-level
  supply chain.
- **Prompt injection (MCP06): materially mitigated, not eliminated.** Provenance
  boundaries and scanning stop the *common* mechanisms (instruction override,
  role switching, tool lures, exfiltration markers) and — crucially — the
  confused-deputy guard plus XCP's scoped authorization mean an injected
  instruction still can't invoke a tool the mandate doesn't grant. A novel
  phrasing can still slip past a signature scan; this reduces probability and
  blast radius rather than guaranteeing prevention.

This honest framing is the point: the library raises the cost of each attack
substantially while being clear about its limits.

## Why this belongs with XCP

XCP already answers *who* is on the connection and *whether* they're authorized.
These three problems are about the *content and effects* of an otherwise
authorized call, which is why the core spec left them out. The security library
closes the loop by adding enforcement at the two points XCP touches — the
gateway (before a call is routed) and the boundary where results return — and by
anchoring supply-chain approval in the same on-chain mandate root that already
governs actions.

```
        authorized call ─▶ [argfirewall] ─▶ [supplychain] ─▶ tool
                                                              │
        model context ◀─ [contentfirewall quarantine] ◀──────┘
   transport underneath all of it: [mtls] TLS 1.3 + pinning + channel binding
```

## 1. Secured mTLS (`xcpsec.mtls`)

The transport foundation. Build hardened TLS 1.3 mutual-auth contexts:

```python
from xcpsec.mtls import TLSPolicy, server_context, client_context, \
    verify_peer_footprint, extract_agent_id, channel_binding

policy = TLSPolicy(ca_path="ca.crt", cert_path="gateway.crt",
                   key_path="gateway.key", require_client_cert=True,
                   pinned_footprints={"0xceb0…"})   # optional pin allowlist
ctx = server_context(policy)                          # TLS 1.3 only, client cert required

# after handshake:
der = ssl_sock.getpeercert(binary_form=True)
footprint = verify_peer_footprint(der, policy)        # enforces the pin allowlist
agent_id  = extract_agent_id(der)                     # reads the AgentBinding OID
cb        = channel_binding(ssl_sock)                 # RFC 9266, to bind tokens
```

Guarantees: no TLS below 1.3, no compression, client certificates required, and
the peer's certificate footprint computed the same way the on-chain registry
expects — so the transport and the Session Registry agree on identity.

## 2. Argument firewall (`xcpsec.argfirewall`)

```python
from xcpsec.argfirewall import ArgumentFirewall, ArgSpec, safe_run

fw = ArgumentFirewall({
    "url": ArgSpec(type="url"),            # SSRF-scanned, http/https only
    "depth": ArgSpec(type="int", required=False),
})
verdict = fw.check({"url": user_url, "depth": 2})
if verdict.blocked:
    raise ValueError(verdict.reason())

# run external commands with no shell, ever:
safe_run(["git", "status"], allow_binaries={"git"})   # list argv, shell=False
```

Blocks: unknown/missing arguments, type violations, shell metacharacters,
command-injection signatures, path traversal, template injection, and SSRF to
internal/metadata hosts (`169.254.169.254`, `localhost`, private IPs, etc.).

## 2b. Sandbox (`xcpsec.sandbox`) — the containment layer for MCP05

The firewall is a filter; the sandbox is the wall behind it. Run any tool that
shells out or executes untrusted input inside a contained subprocess:

```python
from xcpsec.sandbox import run_sandboxed, run_python_sandboxed, SandboxPolicy, safe_eval

policy = SandboxPolicy(cpu_seconds=2, memory_mb=128, max_file_mb=10,
                       allow_network=False, allow_binaries={"python3"})
r = run_python_sandboxed(untrusted_code, policy)
print(r.stdout, r.timed_out, r.applied)   # r.applied lists enforced layers

# the eval() footgun, defused — pure arithmetic/logic only:
safe_eval("2 * (a + 3)", {"a": 4})        # -> 14
safe_eval("__import__('os').system('id')")# -> raises UnsafeExpression
```

Enforced layers (all detected, never assumed — see `Result.applied`):

| Layer | Mechanism | Availability |
|-------|-----------|--------------|
| no shell | argv lists only; string argv refused | always |
| CPU / memory / file / process / fd caps | `setrlimit` | POSIX |
| wall-clock kill | timeout + process-group `SIGKILL` | always |
| no privilege escalation | `prctl(PR_SET_NO_NEW_PRIVS)` | Linux |
| scrubbed environment | env allowlist (no inherited secrets) | always |
| network isolation | `unshare(CLONE_NEWUSER\|CLONE_NEWNET)` | Linux + userns |
| mount isolation | user/mount namespace | Linux + userns |

`SandboxPolicy.describe()` reports what a given host will enforce. When a layer
isn't available (e.g. namespaces on a restricted kernel), the sandbox still
applies everything else and tells you what it applied — it does not pretend to
isolate what it cannot. For fully untrusted code, use a container or microVM as
the outer boundary and this as the inner one.

## 3. Supply-chain verifier (`xcpsec.supplychain`)

```python
from xcpsec.supplychain import SupplyChainVerifier, ToolManifest, \
    sign_manifest, manifest_digest

# publisher side: sign the approved tool surface
manifest = sign_manifest(publisher_key, ToolManifest(server="research", tools=APPROVED))

# gateway side: pin it, then verify live servers
v = SupplyChainVerifier(trusted_publishers={publisher_addr})
v.pin_manifest(manifest)
v.verify_full("research", live_tools, manifest)       # raises on mismatch
```

A rug pull (changed behavior), schema poisoning (changed interface), or tool
shadowing all change the canonical digest and are rejected. The digest can be
committed into the session's on-chain `mandateRoot`, so approval is enforced by
the same gate that authorizes actions.

## 4. Content firewall (`xcpsec.contentfirewall`)

```python
from xcpsec.contentfirewall import ContentFirewall, Trust, \
    guard_action_source, CapabilityViolation

fw = ContentFirewall()
block = fw.wrap(tool_output, trust=Trust.TOOL, origin="research.fetch")
# put block.prompt_block in the model context; instruct the model (once, in the
# system prompt) to treat everything inside the boundary as data, not instructions.

# refuse to let untrusted content authorize a privileged action:
guard_action_source(source_trust)   # raises if the action was triggered by TOOL/WEB content
```

Provenance travels through tool chains (`TaintedContent.combine` takes the
*minimum* trust), so data laundered through several tools stays untrusted. The
quarantine boundary uses a per-call nonce that content cannot spoof.

## The composed `Guard`

For the common case, `Guard` wires the three application-layer modules together:

```python
from xcpsec import Guard, Trust
from xcpsec.argfirewall import ArgSpec

guard = Guard()
guard.register_tool("research", "fetch", {"url": ArgSpec(type="url")})
guard.supply.pin_manifest(signed_manifest)

# before executing a call:
d = guard.check_call("research", "fetch", {"url": url}, live_tools=server_tools)
if not d.allowed:
    reject(d.reason)      # d.stage tells you which layer blocked it

# after the tool returns, before results reach the model:
block = guard.wrap_result(output, trust=Trust.TOOL, origin="research.fetch")
```

## Enabling it in the gateway

The reference gateway integrates the argument firewall when you set an env var —
no code change, and it degrades gracefully if the library isn't installed:

```bash
XCP_SECURITY=1 \
XCP_UPSTREAMS='{"research":"http://localhost:9001/mcp"}' \
  uvicorn xcp_gateway:app --port 8080     # in gateway/
```

With `XCP_SECURITY=1`, A2T tool arguments are firewall-checked before routing;
SSRF and shell-injection arguments are rejected with a 400 at the gateway.

## Tests

```bash
python security/tests/test_xcpsec.py
```

17 tests covering: shell/SSRF/traversal blocking, no-shell execution, rug-pull
and shadow-server detection, manifest signature round-trips, injection-signature
detection, boundary anti-spoofing, taint propagation, the confused-deputy guard,
and the composed policy.

## Status

XCP and the ERC-8004x Session Registry are draft proposals. This library is
reference code, not audited. The signature-based scanners are a floor, not a
ceiling — treat them as one layer in defense-in-depth.
