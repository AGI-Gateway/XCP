# Operator runbook

For the person who was paged. Start here, not with the architecture docs.

```bash
xcp triage https://your-node.example
```

That runs the first five minutes of diagnosis automatically and orders findings
worst-first. Exit code `2` means something CRITICAL, `1` means HIGH, `0` means
nothing urgent. Each playbook below is keyed to a finding it can produce.

!!! danger "The one irreversible thing"
    **Losing `XCP_NODE_KEY` is unrecoverable.** The node loses its identity and
    every attestation any peer ever made about it. A certificate can be rotated;
    this cannot. Before anything else: confirm it is backed up offline.

---

## Day 0 — standing up a node

Six steps. `xcp triage` at the end tells you whether you actually succeeded.

### 1. Create the node identity — once, and back it up first

```bash
python scripts/rotate-cert.py --init
#   XCP_NODE_KEY=0x...
#   node_id=0x...
```

!!! danger "Back this up offline before you use it"
    Losing `XCP_NODE_KEY` is the only unrecoverable failure in this system. The
    node loses its identity and **every attestation any peer ever made about
    it**. A certificate can be rotated; this cannot. Put it in a secret backend
    and verify the offline copy restores before you depend on it.

### 2. Get a real certificate

Let's Encrypt, your own CA, whatever you already run. The dev PKI from
`xcp certs` is for local testing and nothing else.

### 3. Publish the node record

```bash
XCP_NODE_KEY=... python scripts/rotate-cert.py \
    --cert /etc/letsencrypt/live/you/fullchain.pem \
    --domain node.example.org \
    --record /var/www/.well-known/xcp-node.json
```

Serve `/.well-known/xcp-node.json` **unauthenticated** (RFC 8615) — a peer must
read it before any relationship exists. Then wire the same command as a certbot
deploy hook, so renewal never needs remembering.

### 4. Start the gateway

```bash
docker run -p 8080:8080 \
  -e ROLE=gateway \
  -e XCP_POSTURE=enforce \
  -e XCP_SECURITY=1 \
  -e XCP_RATE_LIMIT=1 \
  -e XCP_UPSTREAMS='{"research":"https://your-mcp/mcp"}' \
  -e XCP_NODE_KEY=... -e XCP_NODE_DOMAIN=node.example.org \
  ghcr.io/agi-gateway/xcp@sha256:<digest>
```

Or Helm — see [deployment](deployment.md). **Pin the digest**: a tag is mutable,
and this chart deploys the component that polices everyone else's supply chain.

### 5. Install the native crypto backend

```bash
pip install coincurve     # already in requirements.txt
```

Without it, signature verification costs **6.5 ms instead of 0.19 ms** on every
call and nothing tells you. `xcp triage` checks it.

### 6. Verify you actually succeeded

```bash
xcp triage https://node.example.org     # exit 0 means nothing urgent
xcp conform https://node.example.org    # does it speak the protocol correctly
```

A node that starts is not a node that is configured. Step 6 is the step people
skip and then discover during an incident.

---

## Diagnostic tools

Everything available, and the question each answers.

| tool | answers |
|---|---|
| `xcp triage <url>` | **"what is wrong right now?"** — 14 checks, worst-first, each with a next action. Exit 2 CRITICAL, 1 HIGH |
| `xcp doctor` | "is my local environment able to run this?" — dependencies, config file, tier |
| `xcp config` | "what settings exist, and which are dangerous?" — `--unsafe` for just those |
| `xcp conform <url>` | "does this implementation obey the protocol?" — works against any node, not just ours |
| `xcp compliance recovery` | "what state must survive a restart, and what is unrecoverable?" |
| `xcp compliance gaps` | "what is not covered, and who carries it?" |
| `xcp privacy reconcile` | "do my retention settings satisfy the floors that apply?" |
| `xcp catalog` | "what can this node reach, and how much of it is verified?" |
| `make bench` | "what does the trust layer cost on **my** hardware?" |
| `GET /health` | posture, limiter, crypto backend, telemetry, protocol versions |
| `GET /metrics` | Prometheus metrics for scraping |
| `GET /v1/federation/peers` | who this node trusts, and at what hop count |

When paged, the order is: `triage` → the matching playbook below → capture state
before restarting.

---

## Configuration reference

**!** weakens a control when set — find these deliberately, never by accident.
**#** is a secret: secret backend only, never an image or a compose file.

**gateway**

| setting | default | |
|---|---|---|
| `XCP_POSTURE` **!** | `enforce` | enforce | observe. Observe logs decisions without blocking them — for onboarding an endpoint you have not vetted, never a steady state. |
| `XCP_GATEWAY_ID` | `gw-local` | Identifier stamped on audit records and forwarded downstream as XCP-Verified-By. |
| `XCP_UPSTREAMS` | `{}` | JSON map of name to MCP url, e.g. {"research":"https://.../mcp"}. Empty means every a2t call 404s. |
| `XCP_VERIFY_URL` | `—` | External verifier. Unset uses in-memory bindings, which is fine for one node and insufficient for a federation. |
| `XCP_CACHE_TTL` | `30` | Seconds to cache a verification result. Longer means a revocation takes longer to bite. |
| `XCP_SECURITY` | `0` | Enable the xcpsec argument firewall. The gateway REFUSES TO START if this is 1 and xcpsec is unavailable, rather than running with a control you asked for silently absent. |
| `XCP_RATE_LIMIT` **!** | `1` | Abuse controls. Setting 0 on a node reachable by strangers makes it an open relay. |
| `XCP_GLOBAL_RATE` | `120000` | Node-wide cost units per minute, independent of any caller's tier. |
| `XCP_GLOBAL_CONCURRENCY` | `256` | Node-wide in-flight request cap. |
| `XCP_LIMIT_FAIL_OPEN` **!** | `0` | Serve traffic if the limiter itself fails. Turns any limiter bug into an abuse bypass; only for private deployments behind another limiter. |
| `XCP_SECRET_*` `#` | `—` | Prefix for the env secret backend, e.g. XCP_SECRET_CONNECTORS_GITHUB_CLIENT_ID. Development only. |

**server**

| setting | default | |
|---|---|---|
| `REQUIRE_VERIFIED` **!** | `1` | Refuse calls that did not arrive through a gateway. Setting 0 lets anyone reach the tools directly, bypassing every control. |
| `XCP_SERVER_NAME` | `research` | Name this server answers to in XCP_UPSTREAMS. |

**verifier**

| setting | default | |
|---|---|---|
| `CHAIN_RPC` | `—` | EVM RPC endpoint. Unset means in-memory verification. |
| `CHAIN_ID` | `8453` | Chain id for EIP-712 domains. |
| `SESSION_REGISTRY` | `—` | Deployed SessionRegistry address. Required with CHAIN_RPC. |
| `SESSION_REGISTRY_ABI` | `—` | Path to an ABI override. Defaults to the generated artifact. |

**node**

| setting | default | |
|---|---|---|
| `XCP_NODE_KEY` `#` | `—` | Long-lived node identity key. LOSING THIS IS UNRECOVERABLE: the node loses its identity and every attestation any peer made about it. Back it up offline before first use. |
| `XCP_NODE_DOMAIN` | `—` | Domain this node claims. Must match where the record is served. |
| `XCP_NODE_URL` | `—` | Public gateway URL published to peers. |
| `XCP_NODE_CERT_FOOTPRINT` | `—` | keccak256(DER(cert)) of the certificate currently served. scripts/rotate-cert.py maintains this. |
| `XCP_NODE_OPERATOR` | `anonymous` | Operator name published in the node record. |
| `XCP_PRIVATE_PEER_CIDRS` **!** | `—` | Comma-separated internal ranges that may hold peers, e.g. `10.40.0.0/16,fd00:dc1::/48`. Required for a private federation: without it a peer on a private address is unreachable. Narrower than `XCP_ALLOW_INSECURE_PEERS` — an undeclared range is still refused, loopback and cloud-metadata addresses stay refused even inside a declaration, and TLS is still required. Declarations broader than /8 (IPv4) or /7 (IPv6) are refused, and a malformed entry stops the node. |
| `XCP_PEER_CA_BUNDLE` | `—` | PEM bundle of the authorities that sign this federation's peers. REPLACES the public trust store for peer fetches and footprint retrieval, and for those only — upstream tool calls keep public trust. An unreadable or empty bundle stops the node. |

**wrapper**

| setting | default | |
|---|---|---|
| `XCP_SEAL_PRIVATE` `#` | `—` | X25519 private key for sealed credentials. Without it a sealed wrapper refuses to start, because regenerating silently invalidates every credential already sealed to it. |
| `XCP_SEAL_PREVIOUS` `#` | `—` | Comma-separated previous sealing keys, accepted during a rotation so in-flight requests do not break. |
| `XCP_SEAL_EPHEMERAL` **!** | `0` | Accept a throwaway sealing key. Every restart invalidates every sealed credential; local testing only. |
| `UPSTREAM_CREDENTIAL` `#` | `—` | Fallback upstream credential when no vault backend is configured. Prefer a vault:// reference. |

**telemetry**

| setting | default | |
|---|---|---|
| `XCP_OTEL` | `0` | Enable OpenTelemetry. |
| `XCP_OTEL_DETAIL` **!** | `scrubbed` | scrubbed | hosts | full. `full` exports raw agent ids, scopes and hostnames — self-hosted collectors only. Sending it to a vendor is a new processor and usually an international transfer. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `—` | Collector endpoint. Enabled with no endpoint sends spans to the console, which is work nobody collects. |
| `OTEL_SERVICE_NAME` | `xcp-gateway` | Service name on exported telemetry. |

## Administrative access

`/admin/*` and the full peer list require a bearer token:

```bash
XCP_ADMIN_TOKEN=$(openssl rand -hex 32)
curl -H "Authorization: Bearer $XCP_ADMIN_TOKEN" https://your-node/admin/revoke ...
```

!!! danger "Unset means disabled, not open"
    With no `XCP_ADMIN_TOKEN` the administrative endpoints refuse everything.
    This was a real finding: the kill switch previously accepted a footprint
    from anyone who could reach the port, so one unauthenticated request could
    revoke any agent on the node.

`XCP_ALLOW_INSECURE_PEERS=1` disables the SSRF guard on peer-record fetches,
permitting plain HTTP and **any** private or loopback address. **Local
development only.** On a reachable node it lets a caller make your gateway fetch
internal services it can reach and you cannot. The production profile refuses to
start with it set. If you reached for it because your peers are on internal
addresses, you want `XCP_PRIVATE_PEER_CIDRS` — see below.

## Private federation — peers inside your own network

For several datacentres inside one organisation, peering over internal
addresses with certificates from your own CA.

Two settings, and they answer different questions. **Where** your peers are:

```bash
XCP_PRIVATE_PEER_CIDRS=10.40.0.0/16,10.41.0.0/16,fd00:dc1::/48
```

and **who signs** them:

```bash
XCP_PEER_CA_BUNDLE=/etc/xcp/internal-roots.pem
```

!!! warning "Do not reach for XCP_ALLOW_INSECURE_PEERS here"
    It used to be the only way to reach a private peer, and it is the wrong
    one. It also accepts plain-HTTP peering, and the production profile refuses
    to start with it set — so a private federation could not run the profile at
    all. `XCP_PRIVATE_PEER_CIDRS` is the half of it that is safe in production.

### What declaring a range does and does not buy

A declaration makes a peer **reachable**. It changes nothing else:

- a host resolving outside every declared range is still refused, so a
  hostname an attacker controls cannot aim your gateway anywhere new;
- loopback, link-local, cloud-metadata (`169.254.169.254`) and CGNAT addresses
  stay refused **even if a declaration contains them**;
- every address a name resolves to must pass, so a name answering with one
  declared and one undeclared address is refused;
- TLS is still required, and the certificate footprint binding still runs.

Declare the ranges that actually hold gateways, not the whole of `10.0.0.0/8`.
The declaration is the scope of what peering can reach, so it is worth the ten
minutes with whoever owns the address plan.

### Certificates

Issue peer certificates from your internal CA as you would for any internal
service, with the gateway's domain in the SAN. Then put the root — and only the
roots you actually need — in the bundle:

```bash
cat /etc/pki/internal-root.pem > /etc/xcp/internal-roots.pem
# a mixed federation adds the public roots it needs to the SAME file:
# cat /etc/ssl/certs/ISRG_Root_X1.pem >> /etc/xcp/internal-roots.pem
```

The bundle **replaces** the public trust store for peer verification rather than
adding to it. That is deliberate: setting the variable is a statement about who
signs your peers, and leaving 150-odd public roots trusted contradicts it. A
mis-issuance for an internal name would otherwise be accepted on a **first**
peering — the one moment the footprint binding cannot help, because there is no
prior footprint to compare against.

The scope is federation only. Upstream tool calls keep the public trust store,
so declaring an internal CA does not break the external APIs your agents reach.

### Confirming the posture

```bash
curl -s https://dc1-gw.internal.example/health | jq .privateFederation
# { "declaredRanges": 3, "peerTrustAnchor": "declared" }

curl -s -H "Authorization: Bearer $XCP_ADMIN_TOKEN" \
  https://dc1-gw.internal.example/v1/federation/trust | jq
```

`/health` publishes counts only. The ranges themselves are a map of where your
gateways live, so `/v1/federation/trust` needs the admin token — same reasoning
as the peer list.

`xcp triage` honours `XCP_PEER_CA_BUNDLE`, so run it with the same environment
as the node or every check reports unreachable.

### When peering fails

| symptom | cause |
|---|---|
| `host does not resolve to a permitted address` | the peer's address is outside every declared range, or it is loopback / metadata / CGNAT, which no declaration re-admits |
| `plain HTTP is refused` | the peer URL is `http://`. Declaring a range does not waive TLS |
| `could not bind the peer record to its certificate` | the chain did not verify. The peer's issuer is not in your bundle, or the SAN does not cover the name you peered to |
| gateway will not start, naming `XCP_PRIVATE_PEER_CIDRS` | a malformed entry, or a declaration broader than /8. It stops rather than silently dropping the entry |
| gateway will not start, naming `XCP_PEER_CA_BUNDLE` | the file is missing or holds no authorities. It stops rather than falling back to the public store, which would leave you believing peers are verified against your CA |

### What this does not yet do

Reachability and trust anchoring, not the rest of a private federation. Still
outstanding: off-chain cluster membership (`cluster_id` currently anchors to
`NodeRegistry.sol`), a membership-gated node record, destination authentication
for cross-boundary A2A — `/v1/a2a/delegate` returns `delivered: false` and
authorises a delegation rather than opening a channel — and datacentre locality
in route selection. See `ROADMAP.md`.

## Severity, and what it actually means

| | meaning | response |
|---|---|---|
| **CRITICAL** | traffic is being mishandled *right now* | page someone, act immediately |
| **HIGH** | a control is off or badly degraded | fix within the hour |
| **MEDIUM** | will hurt under load or over time | next working day |

---

## CRITICAL: anonymous calls are being accepted

`triage` reports *"an unauthenticated call was ACCEPTED"*.

The node is routing for anyone who finds it. Treat as an active incident.

1. **Stop the bleeding.** Set `XCP_POSTURE=enforce` and restart. If it was already
   enforce, take the node out of rotation — something is more wrong than config.
2. **Establish scope.** Grep the audit log for calls with no `agent=` or
   `agent=0`. Everything there was unauthorised.
3. **Check what they reached.** Any upstream with credentials is now suspect;
   rotate those credentials, not just the gateway config.
4. **Then diagnose.** Usually posture, occasionally a session registry returning
   success for unbound footprints.

---

## CRITICAL: rate limiting is disabled

A node in a public catalog with no limits is an **open relay** — the failure mode
of every open SMTP relay and DNS resolver in history, and this node is *designed*
to be discovered.

1. Unset `XCP_RATE_LIMIT=0` and restart.
2. If it was deliberate because another limiter fronts you, confirm that limiter
   is actually in the path — assumptions about ingress are a common gap.
3. Check `rateLimit.rejections` afterwards. A sudden spike means you were being
   used.

Note the gateway **refuses to start** if `XCP_RATE_LIMIT=1` and the limiter
cannot load. If you see that, the image is missing `trustfirewall` — see
*"gateway will not start"* below.

---

## CRITICAL: a peer is compromised

The 3am case. Order matters: **contain first, investigate second.**

```bash
# 1. Revoke locally — takes effect immediately for your node
curl -X POST https://your-node/admin/revoke \
     -d '{"footprint":"0x..."}' -H 'Content-Type: application/json'

# 2. Tell your peers. They accept revocations only from verified peers,
#    so this only works from a node they already trust.
for peer in $(xcp triage https://your-node --json | jq -r '...'); do
  curl -X POST "$peer/v1/federation/revoke" \
       -d "{\"nodeId\":\"<their-node-id>\",\"from\":\"your-domain\"}"
done
```

3. **Assume the transitive blast radius.** Anyone that peer *introduced* to you
   inherited trust from it. Check `/v1/federation/peers` for entries with
   `introduced_by` set to the compromised peer and re-verify them directly.
4. **Time is on your side.** Request credentials live seconds and session
   bindings are capped at 7 days, so a compromised peer ages out even if gossip
   never reaches someone. That is the backstop, not the plan.
5. If you run with chain anchoring, an on-chain revocation is unsuppressable and
   reaches everyone who reads the chain — prefer it when available.

---

## HIGH: the crypto fast path is off

`triage` reports a pure-Python backend.

Every call pays **~35× more** for signature verification: 6.5 ms instead of
0.19 ms. `pip install coincurve` and restart. The name `NativeECCBackend` is
eth-keys' *pure Python* implementation — it reads like native code and is not.

---

## HIGH: the node has no signed certificate binding

This identity cannot survive a renewal. When your certificate rotates, every
peer will see a stranger, and any attestation made about you becomes worthless.

```bash
python scripts/rotate-cert.py --init          # once — store XCP_NODE_KEY safely
python scripts/rotate-cert.py --cert /etc/letsencrypt/live/you/fullchain.pem \
    --domain your.domain --record /var/www/.well-known/xcp-node.json
```

Then wire it as a certbot deploy hook so it never needs remembering.

---

## The gateway will not start

**This is usually correct behaviour.** The gateway fails closed rather than
running without a control you asked for.

| message | cause | fix |
|---|---|---|
| `abuse controls are enabled but unavailable` | image missing `trustfirewall` | rebuild from the repo root `Dockerfile`; do not set `XCP_RATE_LIMIT=0` to silence it |
| `XCP_SECURITY=1 but xcpsec is unavailable` | image missing `security/` | same |
| `sealed mode needs a persistent key` | `XCP_SEAL_PRIVATE` unset on a sealed wrapper | set it, or `XCP_SEAL_EPHEMERAL=1` if you accept that restarting invalidates every sealed credential |

The temptation is to disable the control to get the process up. That converts a
loud failure into a silent one, which is how the packaged gateway once shipped
with abuse controls absent and nobody noticed.

---

## Legitimate traffic is being throttled

1. Check which limit fired — `rateLimit.rejections` distinguishes `rate`,
   `concurrency`, `body` and `global`.
2. **`global`** means the node is saturated, not one caller. Scale out; raising
   `XCP_GLOBAL_RATE` just moves the failure.
3. **`rate`** on a legitimate caller usually means their tier is too low.
   Capacity follows authority: an `A0xH0` caller gets 60 units/min, `A2xH2` gets
   30,000. The fix is usually to raise their *tier*, which is a trust decision,
   rather than to raise the limit, which is not.
4. **`concurrency`** with low request rates suggests slow upstreams holding
   connections. Check upstream latency before touching the limiter.

---

## An erasure request arrives

```bash
xcp privacy erase --subject sub_ab12 --classes call_chain,settlement_receipt
```

The response tells the subject what was erased **and what was not, with the
lawful basis and the date it goes anyway**. Send them that, not a bare
confirmation.

Two things the tool cannot do for you:

- **Reach your backups.** Key destruction removes it from the running process.
  Snapshots and replicas are yours (covenant `COV-15`), and this is where erasure
  most often fails in practice.
- **Reach peers.** Anything already federated is beyond your control; a processor
  agreement has to cover it.

---

## Capacity planning

Measured, not estimated — see [performance](performance.md).

| | |
|---|---|
| Trust-layer overhead | **+0.21 ms p50**, +0.27 ms p95 over a bare proxy |
| Rejected call | 0.59 ms, metered pre-auth so floods stay bounded |
| Dominant cost | signature verification, ~185 µs |
| Everything else | single-digit microseconds |

The overhead is roughly **0.7% of one 30 ms cross-region RTT**. If your node is
slow, the cause is almost certainly upstream latency or connection handling, not
verification — that was true of this codebase itself, where a missing connection
pool accounted for 99% of observed latency while the trust layer measured 225 µs.

Re-measure on your own hardware with `make bench`.

---

## Observability (OpenTelemetry)

Off unless asked for. Without the SDK, or without `XCP_OTEL=1`, every
instrumentation call is a no-op — a node runs identically whether or not anyone
is collecting.

```bash
XCP_OTEL=1 \
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 \
OTEL_SERVICE_NAME=xcp-gateway-eu-west \
XCP_OTEL_DETAIL=scrubbed \
  uvicorn core.gateway.xcp_gateway:app --port 8080
```

Helm: set the same as `gateway.env`. Confirm it is live with
`xcp triage <url>` — it reports the endpoint and detail level, and flags an
enabled exporter with no endpoint (spans going to the console is work nobody
collects).

### What a span tells you

A latency number says a call was slow. These spans say **why a call was
refused**, which is the question you actually have:

| attribute | |
|---|---|
| `xcp.decision` | `allow` / `block` / `reject` |
| `xcp.decision.reason` | why — the useful half |
| `xcp.trust.tier` | the lattice cell, e.g. `A2xH2` |
| `xcp.scope` | scope **family**, e.g. `mcp:tools/*` |
| `xcp.limit.kind` | which limit fired: `rate`, `concurrency`, `body`, `global` |
| `xcp.server.trust_class` | `unknown` / `probed` / `attested` / `contracted` |

A refusal is recorded as span status **OK with `xcp.refused=true`**, not ERROR.
Marking refusals as errors makes every dashboard look like an outage during an
attack the gateway successfully repelled.

### Metrics to alert on

| metric | alert when |
|---|---|
| `xcp.calls{decision="reject"}` | rate jumps — probe or misconfigured client |
| `xcp.limit.rejections{kind="global"}` | non-zero — the **node** is saturated, not one caller |
| `xcp.verify.duration` | p95 above ~2 ms — the crypto fast path was lost |
| `xcp.peers` | drops — a peer revoked or became unreachable |

`xcp.verify.duration` is the canary for the 35× pure-Python ECDSA regression: it
sits near 0.19 ms healthy and ~6.5 ms broken.

!!! danger "Telemetry is a data-export path"
    Default is `scrubbed`: agent ids are pseudonymised per process, scope names
    are reduced to their family (`mcp:tools/patient_lookup` becomes
    `mcp:tools/*`), and hostnames are hashed. **Tool arguments and result
    payloads are never recorded at any level.**

    `XCP_OTEL_DETAIL=full` exports raw identifiers and is only appropriate for a
    **self-hosted** collector. Sending it to a third-party vendor is a new
    processor and usually an international transfer. `triage` flags it as HIGH.

    Telemetry is a declared class in the [data map](privacy.md) — 30 days,
    legitimate interest, erasable — because adding it without declaring it
    creates processing your Art. 30 record does not cover.

    `telemetry.SENSITIVE_AT_FULL` lists the attributes a collector should drop
    before forwarding, so the decision can be enforced in config rather than
    trusted.

## Routine operations

| task | cadence | command |
|---|---|---|
| Certificate rotation | automatic | certbot deploy hook → `scripts/rotate-cert.py` |
| Retention sweep | daily | `xcp privacy retention` and delete what is due |
| Catalog refresh | weekly | `python scripts/build-snapshot.py --fetch` |
| Conformance check | per release | `xcp conform https://your-node` |
| Recovery rehearsal | annual | `xcp compliance recovery`, then actually restore |
| Node key backup verify | quarterly | confirm the offline copy still restores |

---

## What to capture before restarting anything

Restarting discards in-memory state and the evidence with it.

1. `xcp triage <url> --json > triage.json`
2. `curl -s <url>/health > health.json`
3. `curl -s <url>/metrics > metrics.txt`
4. The last few thousand audit lines
5. `curl -s <url>/v1/federation/peers > peers.json` if federated

Then restart. Incident classification and regulator reporting deadlines are
covenant `COV-13`; the clock starts at detection, not at resolution.
