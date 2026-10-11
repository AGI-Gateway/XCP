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
| `XCP_CLUSTER_CHARTER` | `—` | Path to the signed cluster charter this node federates under. Commits to the member set with a Merkle root and carries no roster, so the same file goes to every node without publishing who is in the cluster. A closed cluster refuses any peer whose proof does not verify against THIS charter's root. A charter that does not verify stops the node. |
| `XCP_CLUSTER_MEMBERSHIP` | `—` | Path to this node's own membership proof, published in its node record. The node stops if the proof does not verify, or if it is a proof for a different node — which catches a membership file copied from another datacentre. |
| `XCP_CLUSTER_AUTHORITY` | `—` | Address of the key allowed to sign this cluster's charters. Without it a node accepts any correctly-signed charter naming its cluster id, so anyone could mint one. Set it on every node. |
| `XCP_CLUSTER_MIN_EPOCH` | `0` | Refuse a charter below this epoch. Raising the epoch is how a removal takes effect, so pinning the floor stops a rolled-back charter file re-admitting a removed node. |
| `XCP_NODE_RECORD_PUBLIC` **!** | `0` | Serve the FULL node record to anyone, even in a closed cluster. A closed cluster gates it by default. Set this only for a node that must stay publicly discoverable — a public-facing gateway inside a private organisation, or one under external monitoring. It publishes this node's id, gateway URL, operator and seed peers. |
| `XCP_A2A_ACCEPT` | `0` | Accept delegated tasks from peer gateways at `/v1/a2a/accept`. Off by default: a node that accepts them executes work on another datacentre's say-so. A ticket is still only admitted from a verified peer, in this node's cluster, naming this node, within its expiry, for the exact task committed to. |
| `XCP_A2A_TIER_CEILING` | `A2xH2` | The most authority a cross-boundary delegation may carry here, whatever the origin asserted. Narrowed leg by leg, so authority can only shrink at a boundary. The gateway refuses to start on a value it cannot parse — a ceiling nobody can read is a ceiling that does not apply. |
| `XCP_A2A_MAX_HOPS` | `3` | How many boundaries one delegation may cross. The originator sets the budget in the ticket and no hop can raise it. |
| `XCP_NODE_SITE` | `—` | This node's datacentre, region or zone — an opaque label you choose. Peers prefer local routes and apply their own residency rules against it. Unset means no locality: every peer is equally near. |
| `XCP_TOOL_RELAY` | `0` | Serve tool calls on a peer's behalf. Off by default: relaying spends THIS node's vendor credential on another datacentre's say-so. Enabling it also advertises this node's server names to peers. |
| `XCP_TOOL_FALLBACK` | `0` | Ask a peer for a tool this node cannot reach. Off by default: a call leaving for another datacentre is a different data path than the one configured in `XCP_UPSTREAMS`. |
| `XCP_RESIDENCY_SITES` | `—` | Sites where a relayed call's data may be processed. When set, a peer outside is INADMISSIBLE, not merely expensive. A peer declaring no site fails this. |
| `XCP_UPSTREAM_RELAY_CREDENTIAL` `#` | `—` | The credential this node presents upstream when serving a relayed call. It belongs to this node; the asking datacentre never holds or sees it. Prefer a `vault://` reference. |

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

## Cluster membership — who may peer at all

The two settings above decide where peers are and who signs them. A cluster
decides **which** of them may peer, without any node holding a list of the
others.

The authority — you — keeps the member list and publishes only a Merkle root.
Each node gets the same charter and its own proof. A node outside the root
cannot peer, and nobody learns the roster from anything that is distributed.

### Standing one up

On the authority's machine, once:

```bash
python scripts/cluster-charter.py init --name acme-internal
# prints the cluster id, the authority address, and the authority key
```

**Back the authority key up offline before going further.** Every node is
configured with the matching address and refuses a charter signed by anything
else, so losing the key means reconfiguring every node in the cluster.

Then, with each node's `node_id` to hand (`xcp doctor` prints it, as does
`/.well-known/xcp-node.json`):

```bash
export XCP_CLUSTER_AUTHORITY_KEY=0x...
python scripts/cluster-charter.py issue --name acme-internal --epoch 1 \
    --member 0x<dc1-node-id> \
    --member 0x<dc2-node-id> \
    --member 0x<dc3-node-id> \
    --out ./cluster/
```

Distribute what it writes:

| file | goes to | as |
|---|---|---|
| `charter.json` | every node | `XCP_CLUSTER_CHARTER` |
| `membership-<id>.json` | that one node | `XCP_CLUSTER_MEMBERSHIP` |
| `members.json` | **nobody** | keep on the authority |

`members.json` is the roster the charter exists in order not to publish. It
stays with the authority, and it is also what lets you re-issue later without
disturbing the root.

Every node also gets `XCP_CLUSTER_AUTHORITY=0x<authority address>`. Without it
a node accepts any correctly-signed charter naming its cluster id, which means
anyone can mint one.

### Removing a node

Re-issue at a higher epoch, without it:

```bash
python scripts/cluster-charter.py issue --name acme-internal --epoch 2 \
    --member 0x<dc1-node-id> --member 0x<dc2-node-id> \
    --members-in ./cluster/members.json --out ./cluster/
```

Ship the new `charter.json` to the remaining nodes and raise
`XCP_CLUSTER_MIN_EPOCH` to `2` on each.

That is the whole procedure. The removed node still holds a proof the authority
genuinely issued, and it no longer verifies against the root its former peers
hold — so there is no revocation list to distribute, nothing to gossip, and
nothing to wait out. Raising `XCP_CLUSTER_MIN_EPOCH` matters because it is what
stops someone reinstating the older charter file and re-admitting the node.

!!! note "Membership is not authority"
    A member peers at `VERIFIED` like any other peer. What it may then *do* is
    still decided by the trust lattice and its mandates. A cluster answers "may
    you peer", not "what may you call".

### Confirming it

```bash
curl -s https://dc1-gw.internal.example/health | jq .privateFederation.cluster
# { "configured": true, "clusterId": "0x40b1ac…", "epoch": 2,
#   "closed": true, "selfIsMember": true }

python scripts/cluster-charter.py verify \
    --charter ./cluster/charter.json \
    --membership ./cluster/membership-abc123456789.json \
    --authority 0x<authority address> --min-epoch 2
```

`/health` publishes the cluster id, the epoch and whether it is closed. The
membership root and the proofs need the admin token on
`/v1/federation/trust`: the root is a commitment to the member set, and it has
no business on an unauthenticated endpoint.

### When membership fails

| symptom | cause |
|---|---|
| `the peer presented no membership claim` | the peer has no `XCP_CLUSTER_MEMBERSHIP`, or is not in a cluster at all |
| `membership proof does not verify against this cluster's root` | the peer was removed, or the two nodes hold charters from different epochs. Check both ends report the same `epoch` on `/health` |
| `claim proves membership of epoch N` | the peer's proof predates your charter. Re-issue its proof at the current epoch |
| `claim is for a different node` | the peer is presenting someone else's proof — most often a membership file copied between datacentres |
| node will not start, `claim for node 0x…, but this node is 0x…` | the same copied-file mistake, caught locally |
| node will not start, `charter is signed by 0x…, not the expected authority` | `XCP_CLUSTER_AUTHORITY` does not match whoever signed the charter |

### The node record is gated too

A node in a closed cluster stops publishing its full record. This needs no
configuration — it follows from the cluster being closed, because publishing
the topology of a federation only members may join is incoherent.

An unauthenticated caller gets a reduced record: the domain, the protocol
versions, and the cluster id so it knows what to prove. Withheld are the node
id, gateway URL, operator, certificate bindings and seed peers — everything you
would use to map the estate.

```bash
# a stranger
curl -s https://dc1-gw.internal.example/.well-known/xcp-node.json
# { "domain": "...", "protocol_versions": ["1"], "cluster_id": "0x40b1ac…",
#   "gated": true, "authentication": "present XCP-Cluster-Access: …" }
```

The full record goes to a caller presenting `XCP-Cluster-Access`: its
membership claim plus a signature from its node key, naming this domain as the
audience and valid for 60 seconds. Your gateways mint this for each other
automatically when peering — there is nothing to configure, and nothing to
rotate.

The claim alone would have been a bearer credential: a static document, so
possession would be access. The signature makes it proof that the caller *is*
the node its claim names; the audience stops one captured credential opening
every node in the cluster; the expiry bounds replay. A member cannot mint
itself a longer-lived one, because the verifier refuses a TTL above 60s.

!!! note "Removal now costs discovery as well as peering"
    A removed node's proof stops verifying here too, so it can no longer read
    the record it would need in order to attempt peering. That falls out of the
    same epoch bump — there is nothing extra to do.

Every refusal returns the same reduced record, deliberately. A precise
complaint would tell an unauthenticated caller which part of their credential
was wrong, which is a probing oracle. The reason goes to the node's audit log
instead, so `XCP_CLUSTER_MEMBERSHIP` problems are diagnosed from the serving
side:

```
federation record access refused for 0x8b935c8b36f7b2…: access request has expired
```

If a peering attempt fails with *"the peer gates its node record and did not
accept this node as a member"*, check that both nodes report the same `epoch`
on `/health`, and that the one being refused has a current
`XCP_CLUSTER_MEMBERSHIP`.

To keep a node publicly discoverable despite a closed cluster, set
`XCP_NODE_RECORD_PUBLIC=1`. It only affects what the record publishes — peering
is still members-only.

## Agents talking across a boundary

An agent in one datacentre asking an agent in another. `/v1/a2a/delegate` with
a `destination` mints a signed ticket, carries it to that peer's
`/v1/a2a/accept`, and returns the destination's own decision.

```bash
XCP_A2A_ACCEPT=1                 # on the DESTINATION. Off by default.
XCP_A2A_TIER_CEILING=A1xH1       # the most a delegation may carry here
```

Both ends must peer with each other first, in **both** directions. Peering is
directional — dc1 verifying dc2's record says nothing about what dc2 knows —
and the destination is the end that checks whether a ticket's origin is a peer.
A one-way peering fails with *"the originating node is not a verified peer"*.

### Authority narrows at the boundary and never widens

This is the whole point of the ticket carrying a tier rather than the
destination simply trusting the originator. The origin asserts what it
verified; the destination decides what that is worth **here**:

```
asserted A2xH2  ·  ceiling A2xH2  ->  A2xH2   (nothing to narrow)
asserted A2xH2  ·  ceiling A1xH1  ->  A1xH1
asserted A2xH2  ·  ceiling A2xH0  ->  A2xH0   (human leg capped only)
asserted A0xH0  ·  ceiling A2xH2  ->  A0xH0   (a ceiling cannot lift)
```

Narrowing is per leg, not per cell: what backs the agent and what backs the
human are different claims, so a destination that caps one has said nothing
about the other. It's the same invariant the OAuth bridge enforces when a grant
becomes a mandate, and that the lattice enforces when an employer's IdP
attributes meet a cell — applied to the hop between datacentres, because a
trust boundary is where a widening would be most useful to an attacker and
least visible to you.

Set `XCP_A2A_TIER_CEILING` to the most you want delegated work to carry. The
default `A2xH2` means "whatever the origin verified", which is the right
default for datacentres of one organisation and the wrong one if you federate
with anybody you would not hand a local session to.

### A ticket is not a credential for your tools

It authorises **one task, by digest**, to one named destination, for 120
seconds. A delegated call still passes your own mandate gate, argument
firewall and limits — against the **narrowed** tier, so it arrives with less
authority than a local call rather than more.

### What delivered means

```json
{"authorized": true, "delivered": true,
 "destinationDecision": {"admitted": true, "effectiveTier": "A1xH1",
                         "narrowed": true, "ceiling": "A1xH1"}}
```

`authorized` is this gateway's answer, `delivered` means the destination
answered, and `admitted` is the destination's own decision. They are three
different facts and a refusal you *heard* still counts as delivered —
conflating authorisation with delivery is the bug this path exists to stop
making. With no `destination`, nothing is delivered and the response says so.

### When a delegation is refused

Every problem is reported at once rather than one per round trip.

| problem | cause |
|---|---|
| `the originating node is not a verified peer of this node` | peer the two ends, in both directions |
| `the originating node is not a member of this node's cluster` | closed cluster, and the origin isn't in the charter this node holds |
| `ticket was minted for a different destination` | a ticket for dc2 presented at dc3. Working as intended |
| `the task presented is not the task the ticket authorises` | the task changed in flight, or whoever carried the ticket chose a different one |
| `ticket has expired` | more than 120s in flight; check clock skew between the two nodes |
| `delegation budget exhausted` | the chain is longer than the originator permitted |
| `this node is already on the delegation path` | a cycle. Two datacentres were passing it back and forth |
| `ticket is not signed by the node it claims to come from` | the origin's node key does not match the `origin_node` in the ticket |
| `this node does not accept delegated tasks` | `XCP_A2A_ACCEPT` is unset on the destination |

## One egress gateway for the estate

`XCP_UPSTREAMS` is per-gateway, so by default every datacentre needs its own
egress path and its own copy of every vendor credential. That means as many
copies of each secret as you have sites, and the blast radius of one compromise
is the estate.

Instead, let one site hold the credential and serve the others:

```bash
# on the EGRESS gateway — it has the tool and the secret
XCP_NODE_SITE=dc2-frankfurt
XCP_TOOL_RELAY=1
XCP_UPSTREAMS='{"stripe":"https://mcp.vendor.example/mcp"}'
XCP_UPSTREAM_RELAY_CREDENTIAL=vault://prod/stripe-key

# on the ASKING gateways — no credential at all
XCP_NODE_SITE=dc1-dublin
XCP_TOOL_FALLBACK=1
```

A call to a server the asking node doesn't have is routed to a peer that
advertises it. The asking node never holds or sees the vendor key — that is the
entire reason to centralise egress: one place to audit, one rate limit against
the vendor's quota, one copy of the secret to rotate.

Both are **off by default**. Relaying spends your own credential on another
datacentre's say-so; asking sends a call down a data path you didn't configure
in `XCP_UPSTREAMS`. Each end opts in.

A node with `XCP_TOOL_RELAY` unset advertises no servers, so it never appears
as a candidate — you cannot aim a relay at a site that hasn't opted in, and the
endpoint refuses a direct attempt as well.

### A relay is authorised like any cross-boundary call

Because it spends this node's credential, a relayed call is admitted exactly as
a delegation is: verified peer, this node's cluster, naming this node, within
expiry, for the exact call committed to by digest — and it runs at the tier
**narrowed under this node's ceiling**, through this node's own mandate gate,
argument firewall and limits. A relay does not forward onward; an advertised
server it cannot actually reach is refused plainly rather than chained.

### Locality and residency are different levers

```bash
XCP_NODE_SITE=dc1-dublin                          # where this node is
XCP_RESIDENCY_SITES=eu-west-1,eu-central-1        # where data MAY be processed
```

**Locality is a cost.** A peer in another site is worse, not forbidden — when
the local one is down, routing must still reach it. A preference that cannot be
overcome is an outage waiting for your local site to fail.

It also closes a real gap: an untested peer has no measured latency and so
looks *free*. Without a locality prior a node rates a remote peer it has never
called better than the local one it has measured, and finds out by sending
traffic. The prior is what stops the first request being the experiment.

**Residency is a constraint.** A jurisdiction is not a quantity you can be
compensated for crossing, so `XCP_RESIDENCY_SITES` is checked *before*
optimisation. A peer outside it is refused at any latency, cost or trust level,
and it beats locality: a node in `dc1` whose residency list names only `dc2`
routes to `dc2`.

!!! warning "A peer that declares no site fails residency"
    Not knowing where a peer is is not the same as it being somewhere
    permitted. Defaulting the other way would make the control absent exactly
    when it matters. If a peer is refused for an `'undeclared'` site, set
    `XCP_NODE_SITE` on it.

Site labels are opaque — `dc1-dublin`, `eu-west-1`, whatever your estate uses.
XCP compares them and never parses them.

### Checking where traffic actually goes

A routing decision reports its site and whether it left yours. The
concentration index is the thing to watch: locality narrows the pool to the
local site, and path diversity has to keep operating *inside* it.

```bash
curl -s -H "Authorization: Bearer $XCP_ADMIN_TOKEN" \
  https://dc1-gw.internal.example/v1/federation/peers | jq '.summary'
```

A single peer in your local site means an HHI of 1.0 — everything goes to it.
That is a property of the deployment, not a routing fault, and the honest fix
is a second local peer rather than a routing setting.

### Anchoring on-chain later, if you ever want to

The root is byte-identical to what `NodeRegistry.upsertCluster` takes, and
proofs issued here verify under `verifyMembership` unchanged. So a deployment
can run privately now and anchor the same charter later without recomputing
anything, or run both at once off one root. Nothing above requires a chain, and
the test suite asserts the two implementations agree rather than assuming it.

### What a private federation now covers

Reachability, trust anchoring, cluster membership, gated discovery,
cross-boundary delegation, site locality with data residency, and one egress
gateway for the estate. That is the list this section used to end by saying was
outstanding.

What it still is not: audited by anyone paid to put their name on the result,
and deployed anywhere in anger. `ROADMAP.md` has what comes next; nothing on it
is load-bearing for a private federation.

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
