# XCP Python Client

The reference client and the only one that also **signs** mandates (sponsor
side). Small and dependency-light.

```bash
pip install -r requirements.txt   # httpx, eth-account, eth-utils, cryptography
```

## API

- `AgentIdentity(agent_id, chain_id, private_key, cert_path, key_path, ca_path)`
- `XCPClient(gateway_url, identity).connect() -> Session`
- `.call_tool(server, tool, arguments, mandate)` — A2T
- `.delegate(peer_did, task, mandate)` — A2A
- `.chain_tools(src, dst, payload, mandate)` — T2T
- `sign_mandate(private_key, mandate_id, delegator, scope, not_after)` — EIP-712
- `cert_footprint(cert_pem) -> "0x…"` — keccak256(DER(cert))

Raises `XCPError` on session rejection (401) or mandate denial (403).

Use as a context manager to auto-close:

```python
with XCPClient(url, identity) as client:
    client.call_tool("research", "echo", {"text": "hi"}, mandate=m)
```
