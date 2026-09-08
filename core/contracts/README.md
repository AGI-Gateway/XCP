# ERC-8004x Session Registry

The on-chain registry that binds a live mTLS session to an agent identity — the
fourth registry extending ERC-8004's Identity / Reputation / Validation
registries.

## Files

- `SessionRegistry.sol` — the contract (source of truth). Binds
  `keccak256(DER(cert))` → agent, with mandate root, rails bitmap, ≤7-day TTL,
  and on-chain revocation. `verifySession(footprint)` is the hot-path read.
- `SessionRegistry.abi.json` — ABI the verifier loads.
- `deploy_mock_registry.py` — deploys a byte-compatible mock to an **in-process
  EVM** (eth-tester) so the verifier's on-chain read path can be tested without
  solc or an external RPC. The bytecode is hand-assembled with a small,
  auditable assembler.

## Compile (when you have solc)

```bash
pip install py-solc-x
python -c "import solcx; solcx.install_solc('0.8.24')"
python -c "import solcx, json; \
  out=solcx.compile_files(['contracts/SessionRegistry.sol'], \
  output_values=['abi','bin'], solc_version='0.8.24'); \
  print('compiled', list(out.keys()))"
```

## Test the read path (no solc needed)

```bash
pip install web3 eth-tester py-evm eth-utils
python contracts/deploy_mock_registry.py
# deploys the mock, sets a binding, reads it back via verifySession
```

## The binding record

| Field | Meaning |
|-------|---------|
| `agentId` | ERC-8004 Identity Registry token id |
| `certFootprint` | `keccak256(DER(cert))` — the session key |
| `notAfter` | ≤ `notBefore` + 7 days |
| `mandateRoot` | Merkle root of the agent's active mandates |
| `railsBitmap` | enabled payment rails (bit0=x402, 1=AP2, 2=MPP, 3=ACP) |
| `revoked` | on-chain kill switch |
