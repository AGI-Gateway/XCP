#!/usr/bin/env python3
"""
deploy-contracts.py — deploy the registries to a network.

Defaults to an in-process EVM so the deployment path itself is exercised in CI.
Point it at a real RPC to deploy for real.

    python scripts/deploy-contracts.py                          # in-process
    RPC_URL=https://sepolia.base.org DEPLOYER_KEY=0x... \\
        python scripts/deploy-contracts.py --network base-sepolia

The key is read from the environment and never written anywhere. Deploy to a
testnet first: NodeRegistry has not been independently audited, and the findings
in tests/test_contracts.py were all discovered the first time it was executed.
"""
import json, os, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILD = ROOT / "core" / "contracts" / "build"
CONTRACTS = ["SessionRegistry", "NodeRegistry"]


def main() -> int:
    try:
        from web3 import Web3
    except ImportError:
        print("web3 is required: pip install web3", file=sys.stderr)
        return 2

    rpc = os.environ.get("RPC_URL", "")
    key = os.environ.get("DEPLOYER_KEY", "")
    if rpc:
        w3 = Web3(Web3.HTTPProvider(rpc))
        if not key:
            print("DEPLOYER_KEY is required when RPC_URL is set", file=sys.stderr)
            return 2
        acct = w3.eth.account.from_key(key)
        sender = acct.address
        print(f"network: {rpc}  chainId {w3.eth.chain_id}  deployer {sender}")
    else:
        from web3 import EthereumTesterProvider
        w3 = Web3(EthereumTesterProvider())
        acct, sender = None, w3.eth.accounts[0]
        print("network: in-process EVM (dry run)")

    out = {}
    for name in CONTRACTS:
        art = json.loads((BUILD / f"{name}.json").read_text())
        C = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
        if acct is None:
            tx = C.constructor().transact({"from": sender})
        else:
            built = C.constructor().build_transaction({
                "from": sender, "nonce": w3.eth.get_transaction_count(sender),
                "gas": 3_000_000, "gasPrice": w3.eth.gas_price})
            signed = w3.eth.account.sign_transaction(built, key)
            tx = w3.eth.send_raw_transaction(signed.raw_transaction)
        rcpt = w3.eth.wait_for_transaction_receipt(tx)
        out[name] = rcpt.contractAddress
        print(f"  {name}: {rcpt.contractAddress}  gas {rcpt.gasUsed}")

    print("\nWire these into your deployment:")
    print(f"  SESSION_REGISTRY={out['SessionRegistry']}")
    print(f"  NODE_REGISTRY={out['NodeRegistry']}")
    print("\nUnaudited. Testnet first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
