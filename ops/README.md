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

Measured, not estimated — see [performance](../bench/RESULTS.md).

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
