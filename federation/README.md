# Federation — run a node, join the web


**Deploy XCP yourself, peer with whoever you like, depend on nobody.**

A single XCP gateway is useful. A *web* of independently-operated gateways that
verify each other directly is something else: an agentic internet, where any
organisation can join without asking permission and none can be de-listed.

This guide is for operators who want to run a node and federate. It assumes
nothing about who you are and requires no account with anyone, including us.

---

## What you actually depend on

Worth being precise, because the loose version of "no centralised dependencies"
is false and you should know exactly what you're inheriting.

**Still depended on**

| | |
|---|---|
| **DNS** | to resolve a domain to a host |
| **Certificate authorities** | to attest the domain ↔ key binding |

These are the web's existing trust roots. This design deliberately inherits them
rather than inventing a replacement, because an agentic internet that demands its
own naming system and its own PKI will not be adopted. They are *federated* —
many registrars, many CAs, no single operator — not centralised. You can narrow
them further with DANE/TLSA, or a private CA inside a consortium.

**Not depended on**

- any registry, index or directory that one party operates
- any blockchain — chain anchoring is **optional and off by default**
- any vendor's API, account, key or approval
- this project, its maintainers, or any infrastructure we run

!!! success "The test of open infrastructure"
    A node that never talks to us works exactly as well as one that does. If that
    stops being true, the project has failed at its purpose.

---

## 1. Stand up a node

```bash
git clone https://github.com/AGI-Gateway/XCP && cd XCP
make install
./xcp init --domain node.example.org --org "Anything or nothing"
```

Get a real certificate for your domain (Let's Encrypt, your own CA, whatever you
already use). The dev PKI from `xcp certs` is for local testing only.

```bash
XCP_POSTURE=enforce XCP_SECURITY=1 \
  uvicorn xcp_gateway:app --host 0.0.0.0 --port 8080   # in core/gateway/
```

Or Kubernetes:

```bash
helm install xcp ./deploy/helm \
  --set gateway.posture=enforce \
  --set mtls.secretName=your-tls-secret
```

Because MCP 2026-07-28 is stateless, replicas need **no sticky sessions and no
shared session store**. Scale behind a plain round-robin load balancer.

---

## 2. Publish your node record

Your node's identity is a **long-lived key**, not the certificate:

```
node_id       keccak(stable public key)      never changes
cert binding  footprint + sequence + validity, SIGNED by the stable key
```

That split matters. If identity *were* the certificate footprint, every Let's
Encrypt renewal would produce a stranger: peers orphaned, attestations others
issued invalidated, revocations keyed to an id that no longer exists. A trust
network whose members lose their identity four times a year is not a trust
network.

```bash
python scripts/rotate-cert.py --init      # once — store XCP_NODE_KEY safely
```

!!! danger "Guard the node key"
    Rotating a certificate is routine. Rotating this key is not — losing it
    means losing the node's identity and every attestation any peer has made
    about it. Keep it in a secret backend, not on the web server.

Then publish the record:

```python
from federation import build_node_record

rec = build_node_record(
    domain="node.example.org",
    cert_pem=open("node.crt","rb").read(),
    gateway_url="https://node.example.org",
    operator="anonymous",                 # or your name — your choice
    seed_peers=["some-node-you-know.example"],
)
open("well-known/xcp-node.json","w").write(rec.to_json())
```

Serve it at **`/.well-known/xcp-node.json`**, unauthenticated (RFC 8615).

### Renewal is automatic and costs you nothing

```bash
# /etc/letsencrypt/renewal-hooks/deploy/xcp-rotate.sh
XCP_NODE_KEY=... python scripts/rotate-cert.py \
    --cert "$RENEWED_LINEAGE/fullchain.pem" \
    --domain node.example.org \
    --record /var/www/.well-known/xcp-node.json
```

A renewal publishes a **new signed binding, not a new node**. Peers pick it up on
their next fetch; trust, hop counts and introductions all survive. No re-peering.

Two details that make it safe rather than merely convenient:

- **Overlap.** Both certificates are briefly live during a renewal, so a record
  carries the current binding *and* the previous one. A peer connecting
  mid-rotation verifies against the old certificate and notes the rotation
  instead of alarming. The grace window closes after 48 hours.
- **Downgrade.** Bindings carry a monotonic sequence, and a peer refuses any
  binding older than the newest it has seen. Without that, an attacker could
  replay a superseded binding to make peers accept a certificate you rotated
  away from — perhaps one whose key they stole.

That file plus your TLS certificate is your entire claim to identity. There is no
registration step, because there is nobody to register with.

---

## 3. Peer with another node

A peer verifies you with three local checks and no third party:

1. the record is well-formed
2. it was served from the domain it claims
3. its `node_id` matches the certificate the TLS handshake actually presented

```python
from federation import Federation, NodeRecord, verify_node_record

fed = Federation(self_domain="node.example.org", self_node_id=my_id)

rec = NodeRecord.from_dict(fetched_json)
problems = verify_node_record(rec, tls_cert_der, served_from_domain="peer.example")
if not problems:
    fed.add_verified_peer(rec.domain, rec.node_id, rec.gateway_url, mutual=True)
```

If those three hold, the domain owner published it. That is the whole trust
argument, and it's the same one the web already runs on.

---

## 4. Let trust travel

You cannot hand-verify thousands of nodes, so trust propagates: a peer you trust
vouches for a peer you don't.

```python
fed.ingest_attestation(attestation)      # b vouches for c
fed.trust_of("c.example")                # → (trust, weight)
```

Two hard limits make this safe rather than reckless:

- **Decay** — each hop multiplies trust by `0.5`. A peer-of-a-peer is never
  trusted as much as a peer.
- **Cap** — beyond `3` hops it converges to nothing.

!!! warning "Why decay is not optional"
    Without it, transitive trust is a security hole: one compromised node would
    launder full trust to everything it vouches for. With decay, a chain of
    vouching gets weaker with distance — which is the only honest model, since
    your confidence in a stranger's stranger genuinely is lower.

A direct relationship always beats an introduced one, so peering with someone
directly upgrades them regardless of what the web says.

---

## 5. Revocation without a chain

```python
targets = fed.revoke(compromised_node_id)   # returns peers to gossip to
fed.ingest_revocation(node_id, from_domain="b.example")  # only from trusted peers
```

Revocation is **eventually consistent**: it spreads by gossip, and only from
peers you already trust, so a hostile node cannot revoke its rivals.

The backstop is time. XCP request credentials live for *seconds* and session
bindings are capped at 7 days, so a compromised node ages out even if the gossip
never reaches you. That is why the chain is optional — it buys faster, globally
consistent revocation, not correctness.

**Add chain anchoring only if you need it:**

```python
rec = build_node_record(..., chain_id=8453, session_registry="0xYourRegistry")
```

Peers that don't use a chain still federate with you normally.

---

## 6. Bootstrap without a central registry

The genuine hard problem in any federated network: how does the first connection
happen?

```python
fed.bootstrap_targets(record)     # seeds from a node record
```

Any of these work, and none is authoritative:

- a colleague's or vendor's node, given to you directly
- a node listed in an [ARD catalog](../docs/discovery.md) you already crawl
- a domain printed in a README, a talk, or a conference badge
- your own second node, in another region

Seed lists are a **convenience, not an authority**. A node starting from a
completely different seed list reaches the same web, and nodes are free to
disagree about who is trustworthy — there is no consensus requirement and nothing
breaks when views diverge.

---

## 7. Federate discovery

Nodes that set `federates_catalogs` ingest each other's ARD catalogs, so
capabilities published on one node become findable from others:

```bash
./xcp publish --introspect     # your own /.well-known/ai-catalog.json
```

Ingest peers' catalogs and front them through your own Trust Firewall, where
[graded reachability](../docs/trust-firewall.md) applies: peers' servers start `unknown`
— reachable in observe mode, sandboxed, output quarantined, nothing binding —
and climb as you probe, pin or contract with them.

!!! danger "Ingesting a peer's catalog is not endorsing it"
    Federating discovery does **not** federate trust. A peer can list whatever it
    likes; your firewall still grades every server it names. Keep the SSRF guards
    on catalog ingestion enabled (`xcpsec.argfirewall`) — a catalog is untrusted
    input from another operator.

---

## Reference topology

```
   node-a.example                     node-b.example
   ┌────────────────┐   peer, verify  ┌────────────────┐
   │ gateway :8080  │◄───────────────►│ gateway :8080  │
   │ /.well-known/  │  each other's   │ /.well-known/  │
   │  xcp-node.json │  cert footprint │  xcp-node.json │
   │  ai-catalog    │                 │  ai-catalog    │
   └───────┬────────┘                 └───────┬────────┘
           │ attests c                        │
           ▼                                  ▼
   node-c.example  ◄── reached transitively, at decayed trust ──►

   no registry · no chain required · no vendor · no consensus
```

---

## Operating checklist

- Run `enforce`. `observe` is for onboarding a peer you haven't vetted.
- `XCP_SECURITY=1` for the argument firewall; `xcpsec.sandbox` for any tool that
  executes untrusted input.
- Keep credential TTLs in seconds — that's your revocation backstop.
- Serve `/.well-known/*` unauthenticated; gate everything else.
- Rotate certificates on your normal schedule; your `node_id` changes with the
  certificate, so **republish your node record and re-peer** when you rotate.
- Watch `mandate_denials_total` and `session_verifications_total{result}`.

---

## Optional: bonded federation and paid transport

Everything above works with **no chain at all**, and that stays true. This
section is a tier you opt into, not the floor.

### Why a chain earns its place here

Three things gossip cannot do:

| problem | why off-chain fails | what the chain adds |
|---|---|---|
| **Revocation** | only reaches you if a peer tells you; a compromised node whose peers stay quiet keeps working | one transaction, visible to every reader in a block, **unsuppressable** |
| **Sybil resistance** | transitive trust with decay does not survive *free* identities — a thousand fake nodes vouching for each other defeats decay alone | a **slashable bond** makes identity cost something, with no gatekeeper deciding who may join |
| **Paying strangers** | escrow needs a neutral holder | a contract is exactly that |

### The incentive: routing is a business, not a favour

An agent's workflow routes through your node; you supply transport, session
verification and mandate enforcement; **you get paid per routed call**.

```python
from federation import RoutingLedger, TransportReceipt, RouteClass, sign_receipt

led = RoutingLedger(node_id=my_node_id)
led.record(sign_receipt(payer_key, TransportReceipt(      # the PAYER signs
    route_id=rid, node_id=my_node_id, payer_agent=42001,
    route_class=RouteClass.A2T, price_minor=5)))
commitment = led.commit(epoch, bucket=100)               # the only public artifact
```

A billable receipt carries the **payer's** signature, not the node's. That is the
anti-fraud property: you cannot invent traffic somebody else has to sign.

### The public / private boundary

Paying per route means counting routes, and counting routes in public leaks the
topology. So a node publishes **one commitment per epoch** — a Merkle root plus
totals — and nothing else.

| on-chain (public) | off-chain (private) |
|---|---|
| node identity, bond, revocations | who routed to whom |
| per-epoch root, route count, total | individual receipts, scopes, timing |
| cluster **membership root** | the member roster |
| slashes and challenges | per-counterparty volumes |

Scope and counterparty are excluded from the signed payload itself, so even
someone who later obtains a leaf learns nothing about the workload — tested.

!!! warning "The residual leak, stated plainly"
    `route_count` is a volume signal over time. `bucket_count()` rounds it up
    before publishing — a node claiming *"between 900 and 1000 routes"* leaks far
    less than one claiming 947 — while the amount owed stays exact. It reduces
    the signal; it does not eliminate it.

### Private clusters: roots, never rosters

A cluster publishes a **membership Merkle root** and a policy hash. A member
proves inclusion with a Merkle proof; an outsider can verify *"this cluster
exists, is bonded, and this counterparty belongs to it"* **without learning who
else is in it**. Two clusters can interact cluster-to-cluster, neither exposing
its members.

A fully private deployment simply never publishes a root and federates
bilaterally, exactly as before.

### Claims are optimistic, challenges are checkable

A node posts a commitment, waits out a challenge window, then withdraws. Anyone
may challenge with a **proof rather than an accusation**:

- a receipt whose payer signature does not verify
- a leaf that is not under the claimed root
- a route id billed in two epochs
- totals that do not match the disclosed set

Each is mechanically checkable, which is what makes slashing defensible rather
than political. A challenger takes a share of the slash, because a challenger
with no payout has no reason to look.

### Bonds lift trust, but never past a peer you verified

`Federation.bond_weight()` is capped below `1.0` deliberately. Money buys a
hearing, never the standing of a direct relationship — otherwise a rich Sybil
outranks a peer you checked yourself.

!!! danger "Before you deploy this with value at stake"
    Staking is a **regulated activity** in most jurisdictions: slashing is
    arguably a penalty regime, bonds resemble deposits, and a native token would
    raise securities questions. The design is settlement-asset agnostic on
    purpose — it works with a stablecoin or an existing rail and needs no token.
    Get legal advice before it needs a contract.

    Also: "blockchain" is the worst possible framing for the enterprise security
    buyer this project needs. Lead with *verifiable, instantly revocable,
    vendor-neutral*. The chain is an implementation detail two questions in.

## Honest limits

This is a design and a working implementation, not a running network.

- **The network doesn't exist yet.** Federation code being correct is not the
  same as peers existing. The bootstrap problem is real and unsolved by software.
- **Web-of-trust models have a known history of not scaling socially** — PGP is
  the cautionary example. Decay and hop caps limit the damage but don't make the
  social problem go away.
- **None of this has had an independent security audit.** That goes double for
  the contract: `NodeRegistry.sol` has not been audited, formally verified, or
  deployed to any network.
- **Optimistic claiming assumes somebody challenges.** The fraud proofs are
  sound, but they only bite if a party with a stake actually checks. In a sparse
  federation that assumption is weak.
- XCP and ERC-8004x are **draft proposals originated in this project**. MCP, A2A,
  ERC-8004, ARD and the OWASP taxonomies are independent work by others.
