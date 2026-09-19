#!/usr/bin/env python3
"""
deploy_mock_registry.py — deploy a minimal SessionRegistry to an in-process
EVM (eth-tester) so the verifier's ON-CHAIN read path can be tested without
solc or an external RPC.

We cannot run solc here (binaries.soliditylang.org is firewalled), so this
hand-assembles compact EVM runtime bytecode implementing exactly the two
functions the verifier and tests exercise:

  setBinding(bytes32 footprint, uint256 agentId, bytes32 mandateRoot,
             bytes32 railsBitmap, bool valid)         [test-only setter]
  verifySession(bytes32 footprint)
        -> (bool valid, uint256 agentId, bytes32 mandateRoot, bytes32 railsBitmap)

Storage layout (per footprint, 4 slots at keccak256(footprint . base)):
  slot+0: valid (0/1)        slot+1: agentId
  slot+2: mandateRoot        slot+3: railsBitmap

The real contract is contracts/SessionRegistry.sol; this mock is byte-compatible
at the verifySession ABI boundary, which is all the verifier reads. The Solidity
file remains the source of truth for production (compile with solc).

The bytecode is built with a tiny assembler below so it's auditable, not a
magic hex blob.
"""

from __future__ import annotations

# ── tiny EVM assembler ──────────────────────────────────────────────────────
OPS = {
    "STOP": 0x00, "ADD": 0x01, "MUL": 0x02, "SUB": 0x03, "DIV": 0x04,
    "EQ": 0x14, "ISZERO": 0x15, "AND": 0x16,
    "CALLDATALOAD": 0x35, "CALLDATASIZE": 0x36,
    "SHR": 0x1c, "POP": 0x50, "MLOAD": 0x51, "MSTORE": 0x52,
    "SLOAD": 0x54, "SSTORE": 0x55, "JUMP": 0x56, "JUMPI": 0x57,
    "JUMPDEST": 0x5b, "SHA3": 0x20,
    "DUP1": 0x80, "DUP2": 0x81, "DUP3": 0x82, "DUP4": 0x83, "DUP5": 0x84,
    "DUP6": 0x85,
    "SWAP1": 0x90, "SWAP2": 0x91, "SWAP3": 0x92, "SWAP4": 0x93,
    "RETURN": 0xf3, "REVERT": 0xfd, "CODECOPY": 0x39,
}


def selector(sig: str) -> int:
    from eth_utils import keccak
    return int.from_bytes(keccak(text=sig)[:4], "big")


def build_runtime() -> bytes:
    """
    Build runtime bytecode with explicit jump targets resolved manually.
    Layout:
      [dispatch]
      ... if selector == verifySession -> JUMP verify
      ... if selector == setBinding    -> JUMP setb
      REVERT
      verify: JUMPDEST ... RETURN(128 bytes)
      setb:   JUMPDEST ... STOP
    """
    sel_verify = selector("verifySession(bytes32)")
    sel_set = selector("setBinding(bytes32,uint256,bytes32,bytes32,bool)")

    # We compute storage slot = keccak256(footprint) for the 0th field, then
    # +1,+2,+3 for the others. Memory[0..31] is used as the SHA3 input scratch.

    # --- assemble with manual offsets ---
    # First pass: build segments, then compute jumpdests.
    # To keep this tractable we write the program, note label positions, and
    # patch the PUSH2 targets afterwards.

    code = bytearray()
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str]] = []   # (offset_of_push2_operand, label)

    def emit(b: bytes):
        code.extend(b)

    def push(v: int):
        bb = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        code.append(0x60 + len(bb) - 1)
        code.extend(bb)

    def push2_label(label: str):
        code.append(0x61)                # PUSH2
        fixups.append((len(code), label))
        code.extend(b"\x00\x00")

    def op(name: str):
        code.append(OPS[name])

    def mark(label: str):
        labels[label] = len(code)
        op("JUMPDEST")

    # ---- dispatch: load selector = calldata[0] >> 224 ----
    push(0); op("CALLDATALOAD"); push(224); op("SHR")   # [sel]
    op("DUP1"); push(sel_verify); op("EQ")              # [sel, sel==verify]
    push2_label("verify"); op("JUMPI")                  # [sel]
    op("DUP1"); push(sel_set); op("EQ")
    push2_label("setb"); op("JUMPI")
    push(0); push(0); op("REVERT")

    # ---- verify: footprint = calldata[4:36] ----
    mark("verify")
    # compute base slot = keccak256(footprint): store fp at mem[0], SHA3(0,32)
    push(4); op("CALLDATALOAD")        # [fp]
    push(0); op("MSTORE")              # mem[0]=fp
    push(32); push(0); op("SHA3")      # [base]
    # load 4 fields into memory at 0,32,64,96
    op("DUP1"); op("SLOAD"); push(0); op("MSTORE")            # valid -> mem[0]
    op("DUP1"); push(1); op("ADD"); op("SLOAD"); push(32); op("MSTORE")   # agentId
    op("DUP1"); push(2); op("ADD"); op("SLOAD"); push(64); op("MSTORE")   # mandateRoot
    push(3); op("ADD"); op("SLOAD"); push(96); op("MSTORE")               # railsBitmap
    push(128); push(0); op("RETURN")

    # ---- setBinding: args fp, agentId, mandateRoot, railsBitmap, valid ----
    mark("setb")
    # calldata layout: [4]=fp [36]=agentId [68]=mandateRoot [100]=railsBitmap [132]=valid
    push(4); op("CALLDATALOAD")        # [fp]
    push(0); op("MSTORE")
    push(32); push(0); op("SHA3")      # [base]
    # base+0 = valid
    op("DUP1"); push(132); op("CALLDATALOAD"); op("SWAP1"); op("SSTORE")
    # base+1 = agentId
    op("DUP1"); push(1); op("ADD"); push(36); op("CALLDATALOAD"); op("SWAP1"); op("SSTORE")
    # base+2 = mandateRoot
    op("DUP1"); push(2); op("ADD"); push(68); op("CALLDATALOAD"); op("SWAP1"); op("SSTORE")
    # base+3 = railsBitmap
    push(3); op("ADD"); push(100); op("CALLDATALOAD"); op("SWAP1"); op("SSTORE")
    op("STOP")

    # ---- resolve fixups ----
    for off, label in fixups:
        target = labels[label]
        code[off] = (target >> 8) & 0xFF
        code[off + 1] = target & 0xFF

    return bytes(code)


def deployment_bytecode() -> bytes:
    """Wrap runtime in a constructor that returns it (CODECOPY then RETURN)."""
    runtime = build_runtime()
    rlen = len(runtime)
    # constructor: PUSH rlen, DUP1, PUSH offset, PUSH 0, CODECOPY, PUSH 0, RETURN
    ctor = bytearray()

    def push(v):
        bb = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        ctor.append(0x60 + len(bb) - 1)
        ctor.extend(bb)

    # We need the offset where runtime begins = len(ctor after we know it).
    # Build ctor with a placeholder, then fix offset.
    # ctor: PUSH2 rlen; DUP1; PUSH2 <off>; PUSH1 0; CODECOPY; PUSH1 0; RETURN
    ctor.append(0x61); ctor.extend(rlen.to_bytes(2, "big"))    # PUSH2 rlen
    ctor.append(0x80)                                          # DUP1
    off_pos = len(ctor) + 1
    ctor.append(0x61); ctor.extend(b"\x00\x00")               # PUSH2 off (patch)
    ctor.append(0x60); ctor.append(0x00)                      # PUSH1 0
    ctor.append(0x39)                                         # CODECOPY
    ctor.append(0x60); ctor.append(0x00)                      # PUSH1 0
    ctor.append(0xf3)                                         # RETURN
    off = len(ctor)
    ctor[off_pos] = (off >> 8) & 0xFF
    ctor[off_pos + 1] = off & 0xFF
    return bytes(ctor) + runtime


def deploy(w3, deployer: str) -> str:
    """Deploy the mock and return its address."""
    tx = {"from": deployer, "data": "0x" + deployment_bytecode().hex(),
          "gas": 1_000_000}
    txh = w3.eth.send_transaction(tx)
    rcpt = w3.eth.wait_for_transaction_receipt(txh)
    return rcpt["contractAddress"]


if __name__ == "__main__":
    from web3 import Web3, EthereumTesterProvider
    w3 = Web3(EthereumTesterProvider())
    addr = deploy(w3, w3.eth.accounts[0])
    print("deployed mock SessionRegistry at", addr)
    print("runtime bytes:", len(build_runtime()))
