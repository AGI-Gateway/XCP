# XCP Verifier

The session + mandate verifier the [gateway](../gateway/README.md) calls when
you set `XCP_VERIFY_URL`. It does the real cryptographic checks against the
Session Registry.

```bash
pip install -r requirements.txt
uvicorn xcp_verifier:app --host 0.0.0.0 --port 8500
```

## What's real

- **Merkle inclusion** — sorted-pair keccak against the session's mandate root
- **EIP-712 recovery** — sponsor signature over the mandate (via eth-account)
- **Scope coverage** — `mcp:tools/research.*` covers `mcp:tools/research.fetch`
- **Expiry + revocation** with a short-TTL cache

## On-chain vs in-memory

Set `CHAIN_RPC` + `SESSION_REGISTRY` to read bindings from a deployed
[SessionRegistry](../contracts/README.md) over web3. Otherwise an in-memory
registry stands in (seed it via `/admin/bind`) so the verifier runs offline and
in CI. Production is a two-env-var swap.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/verify` `{footprint}` | session binding check |
| POST | `/mandate` `{mandateRoot, scope, proof}` | mandate gate |
| POST | `/admin/revoke/{footprint}` | kill switch |
| POST | `/admin/bind` | seed an in-memory binding (dev/CI) |
| GET | `/health` | mode + crypto availability |
