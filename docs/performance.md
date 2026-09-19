# Measured performance

Run it yourself: `make bench`. Numbers below are from a containerised CI-class
machine over loopback, Python reference implementation.

## End-to-end: what the trust layer costs

| | p50 | p95 | p99 |
|---|---:|---:|---:|
| baseline proxy, no trust layer | 1.91 ms | 2.11 ms | 2.36 ms |
| XCP gateway, enforce, all controls | 2.12 ms | 2.38 ms | 2.55 ms |
| **overhead** | **+0.211 ms** | **+0.269 ms** | |

**0.21 ms** to verify identity, gate the mandate, meter the caller and
route — about **0.7% of a single 30 ms cross-region RTT**.

A rejected call costs 0.59 ms, and is metered pre-auth so an
unauthenticated flood stays bounded.

## Two regressions measurement found

Both cost roughly two orders of magnitude and neither was visible in unit tests.

**No upstream connection pooling.** The gateway created an `httpx.AsyncClient`
per request, paying a fresh TCP connect every call: **24.2 ms overhead, 12.9x
baseline**. Pooled, the same measurement is 0.21 ms. The trust layer was never
the cost.

**Pure-Python ECDSA.** `eth-keys` names its pure-Python implementation
`NativeECCBackend`, which reads like native code. Without `coincurve`:

| | pure Python | libsecp256k1 |
|---|---:|---:|
| credential mint | 6015 µs | **363 µs** |
| credential verify | 6576 µs | **185 µs** |

A deployment missing that dependency pays a **35x penalty on every call** and
nothing tells it. `coincurve` is now pinned with the reason, the gateway warns at
startup, and `/health` reports `cryptoBackend` and `cryptoFastPath`.

## Primitives

| operation | p50 µs | p95 µs | note |
|---|---:|---:|---|
| `keccak256 (small payload)` | 11.2 | 14.3 |  |
| `scope_for (headers only, no body parse)` | 0.3 | 0.3 | the header-speed authorization path |
| `bind_digest (call binding)` | 17.9 | 22.1 |  |
| `credential mint (EIP-712 sign)` | 362.9 | 421.7 | client-side, once per call |
| `credential verify (signature recover)` | 185.2 | 223.8 | gateway-side, once per call — the dominant cost |
| `credential parse from header` | 8.8 | 10.1 |  |
| `trust lattice resolve` | 6.1 | 7.0 |  |
| `trust firewall decide (full)` | 224.7 | 271.5 | includes credential verification |
| `rate limiter check` | 2.6 | 3.1 | runs on every request, pre- and post-auth |
| `call chain append` | 43.4 | 71.7 | O(1) per call — rides on existing audit |
| `call chain verify (50 records)` | 1289.1 | 1636.8 |  |
| `receipt build + sign` | 1947.5 | 2363.5 |  |
| `sealed credential seal (X25519+AESGCM)` | 87.8 | 113.4 |  |
| `sealed credential unseal` | 83.7 | 104.1 | per call, only for hosted wrappers |
| `cert binding verify` | 312.5 | 353.4 | once per peer fetch, not per call |
| `crypto-shred seal (per record)` | 15.9 | 23.6 | only if personal data is recorded |

## Reading these honestly

- **Loopback removes network latency**, which makes the relative overhead look
  larger than in production. A real call pays 1–50 ms of RTT that dwarfs all of
  this.
- **Python is the reference, not the fast path.** A Go or Rust gateway would
  move the CPU-bound numbers; the protocol's inherent cost is lower than
  measured.
- Single machine, no contention, no GC pressure from a real workload.
- Signature verification dominates. Everything else — scope derivation, the
  lattice, the rate limiter — is single-digit microseconds.
