# Run a Node — the Agentic Internet

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

Your node's identity is the footprint of its certificate,
`keccak256(DER(cert))`, published on your own domain:

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
- a node listed in an [ARD catalog](discovery.md) you already crawl
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
[graded reachability](trust-firewall.md) applies: peers' servers start `unknown`
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

## Honest limits

This is a design and a working implementation, not a running network.

- **The network doesn't exist yet.** Federation code being correct is not the
  same as peers existing. The bootstrap problem is real and unsolved by software.
- **Web-of-trust models have a known history of not scaling socially** — PGP is
  the cautionary example. Decay and hop caps limit the damage but don't make the
  social problem go away.
- **Certificate rotation breaks peering** until records are republished. That is
  operational friction we haven't automated.
- **None of this has had an independent security audit.**
- XCP and ERC-8004x are **draft proposals originated in this project**. MCP, A2A,
  ERC-8004, ARD and the OWASP taxonomies are independent work by others.
