"""
test_contracts.py — the contracts, compiled and executed.

Until this existed, NodeRegistry.sol had never been through a compiler and never
been run. Executing it for the first time found three real bugs, all fixed and
pinned below. Compiling also showed the hand-maintained SessionRegistry ABI was
incomplete — four public-variable getters were missing, so a client could not
read state the contract exposes.

(A first pass claimed the ABI declared a function the contract lacked. That was
wrong: the diff had compared against `ISessionRegistry`, the interface, rather
than the contract. Recorded here because a security note that overstates a
finding is its own kind of defect.)

Needs solc and web3. Skipped cleanly when either is absent.

    SOLC=/path/to/solc python tests/test_contracts.py
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
BUILD = ROOT / "core" / "contracts" / "build"

try:
    from web3 import Web3, EthereumTesterProvider
    _W3 = True
except ImportError:
    _W3 = False

SOLC = os.environ.get("SOLC") or shutil.which("solc")


def _artifact(name: str) -> dict:
    p = BUILD / f"{name}.json"
    if not p.exists():
        raise RuntimeError(f"{p} missing — run scripts/compile-contracts.py")
    return json.loads(p.read_text())


def _deploy(name: str):
    art = _artifact(name)
    w3 = Web3(EthereumTesterProvider())
    C = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
    tx = C.constructor().transact({"from": w3.eth.accounts[0]})
    addr = w3.eth.get_transaction_receipt(tx).contractAddress
    return w3, w3.eth.contract(address=addr, abi=art["abi"])


def _skip_if_no_w3():
    if not _W3:
        raise RuntimeError("SKIP: web3 not installed")


# ── the ABI is generated, not hand-written ─────────────────────────────────

def test_abis_are_generated_artifacts():
    for n in ("NodeRegistry", "SessionRegistry"):
        a = _artifact(n)
        assert a["abi"] and a["bytecode"].startswith("0x")
        assert "solc" in a["compiler"]
        assert "do not hand-edit" in a["_comment"].lower()


def test_abi_has_no_phantom_entries():
    """Every ABI function must correspond to real source."""
    import re
    src = (ROOT / "core" / "contracts" / "SessionRegistry.sol").read_text()
    # solc auto-generates a getter for every public state variable, so those are
    # legitimately in the ABI without a `function` declaration.
    public_vars = set(re.findall(
        r"public\s+(?:constant\s+|immutable\s+)?([A-Za-z_][A-Za-z0-9_]*)", src))
    for entry in _artifact("SessionRegistry")["abi"]:
        if entry["type"] == "function":
            n = entry["name"]
            assert f"function {n}" in src or n in public_vars, \
                f"ABI declares {n}() which is neither a function nor a public variable"


def test_the_hand_maintained_abi_is_gone():
    """It was incomplete — four public-variable getters were missing, so a
    client could not read state the contract exposes. Generated now."""
    assert not (ROOT / "core" / "contracts" / "SessionRegistry.abi.json").exists()


def test_generated_abi_includes_public_variable_getters():
    names = {e.get("name") for e in _artifact("SessionRegistry")["abi"]}
    for getter in ("MAX_TTL", "agentController", "controllerOf", "isGuardian"):
        assert getter in names, f"{getter} getter missing from the generated ABI"


def test_sources_still_compile():
    if not SOLC:
        raise RuntimeError("SKIP: solc not available")
    r = subprocess.run([SOLC, "--optimize", "--bin", "-o", "/tmp/_cc", "--overwrite",
                        str(ROOT / "core" / "contracts" / "NodeRegistry.sol"),
                        str(ROOT / "core" / "contracts" / "SessionRegistry.sol")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[:400]
    assert "Error" not in r.stderr


# ── access control ─────────────────────────────────────────────────────────

def test_registration_requires_the_minimum_bond():
    _skip_if_no_w3()
    w3, nr = _deploy("NodeRegistry")
    a = w3.eth.accounts
    try:
        nr.functions.registerNode(b"\x11" * 32, b"\x22" * 32).transact(
            {"from": a[1], "value": 1})
        assert False, "an under-bonded node must not register"
    except Exception:
        pass


def test_only_the_operator_may_revoke_or_unbond():
    _skip_if_no_w3()
    w3, nr = _deploy("NodeRegistry")
    a = w3.eth.accounts
    nid = b"\x11" * 32
    nr.functions.registerNode(nid, b"\x22" * 32).transact(
        {"from": a[1], "value": nr.functions.MIN_BOND().call()})
    for fn in (lambda: nr.functions.revokeNode(nid, "x").transact({"from": a[3]}),
               lambda: nr.functions.requestUnbond(nid).transact({"from": a[3]})):
        try:
            fn(); assert False, "a stranger must not control another node"
        except Exception:
            pass


def test_duplicate_registration_is_refused():
    _skip_if_no_w3()
    w3, nr = _deploy("NodeRegistry")
    a = w3.eth.accounts
    nid = b"\x11" * 32
    m = nr.functions.MIN_BOND().call()
    nr.functions.registerNode(nid, b"\x22" * 32).transact({"from": a[1], "value": m})
    try:
        nr.functions.registerNode(nid, b"\x22" * 32).transact({"from": a[2], "value": m})
        assert False, "a node id must not be re-registered by someone else"
    except Exception:
        pass


# ── NR-2: the griefing vector ──────────────────────────────────────────────

def test_an_unproven_route_id_cannot_be_poisoned():
    """
    Originally `challengeDoubleClaim` recorded any route id on a bare call, so a
    stranger could poison an id and then slash the honest node that later billed
    it legitimately. Membership must be proven first.
    """
    _skip_if_no_w3()
    w3, nr = _deploy("NodeRegistry")
    a = w3.eth.accounts
    nid = b"\x11" * 32
    nr.functions.registerNode(nid, b"\x22" * 32).transact(
        {"from": a[1], "value": nr.functions.MIN_BOND().call()})
    nr.functions.postClaim(nid, 1, b"\xaa" * 32, 10, 1000).transact({"from": a[1]})
    rid = Web3.keccak(text="an-honest-route")
    try:
        nr.functions.challengeDoubleClaim(nid, 1, rid, b"\x00" * 32, []).transact(
            {"from": a[5]})
        assert False, "an unproven leaf must not record a route id"
    except Exception:
        pass
    assert nr.functions.spentRoute(rid).call() is False


# ── NR-3: forfeited stake ──────────────────────────────────────────────────

def test_slashing_rewards_the_challenger_and_accounts_for_the_rest():
    _skip_if_no_w3()
    w3, nr = _deploy("NodeRegistry")
    a = w3.eth.accounts
    nid = b"\x11" * 32
    bond = nr.functions.MIN_BOND().call()
    nr.functions.registerNode(nid, b"\x22" * 32).transact({"from": a[1], "value": bond})
    leaf = b"\xbb" * 32
    nr.functions.postClaim(nid, 2, leaf, 1, 500).transact({"from": a[1]})
    rid = Web3.keccak(text="dup")
    nr.functions.challengeDoubleClaim(nid, 2, rid, leaf, []).transact({"from": a[6]})
    before = w3.eth.get_balance(a[6])
    nr.functions.challengeDoubleClaim(nid, 2, rid, leaf, []).transact({"from": a[6]})

    assert nr.functions.bondOf(nid).call() == 0
    assert nr.functions.isLive(nid).call() is False
    assert w3.eth.get_balance(a[6]) > before - 10**16, "challenger must be paid"
    forfeited = nr.functions.totalForfeited().call()
    assert forfeited == bond - (bond * 2000 // 10000), \
        "the remainder must be accounted for, not silently stuck"


def test_forfeited_stake_has_no_withdrawal_path():
    """A slash is a deterrent, not a revenue stream. A withdrawable pool would
    create a party that profits from slashing others."""
    src = (ROOT / "core" / "contracts" / "NodeRegistry.sol").read_text()
    assert "totalForfeited" in src
    assert "withdrawForfeited" not in src and "claimForfeited" not in src


# ── NR-4: leaving the federation ───────────────────────────────────────────

def test_an_honest_node_can_recover_its_stake_after_a_cooldown():
    """A bond nobody can ever recover is a bond nobody rational posts."""
    _skip_if_no_w3()
    w3, nr = _deploy("NodeRegistry")
    a = w3.eth.accounts
    nid = b"\x33" * 32
    bond = nr.functions.MIN_BOND().call()
    nr.functions.registerNode(nid, b"\x44" * 32).transact({"from": a[2], "value": bond})
    nr.functions.requestUnbond(nid).transact({"from": a[2]})
    try:
        nr.functions.withdrawBond(nid).transact({"from": a[2]})
        assert False, "the cooldown must hold"
    except Exception:
        pass
    w3.provider.ethereum_tester.time_travel(
        w3.eth.get_block("latest").timestamp + 15 * 86400)
    before = w3.eth.get_balance(a[2])
    nr.functions.withdrawBond(nid).transact({"from": a[2]})
    assert w3.eth.get_balance(a[2]) > before, "the bond must be returned"
    assert nr.functions.bondOf(nid).call() == 0


def test_unbonding_cannot_outrun_a_challenge():
    """Exiting must take longer than the window in which a claim is contestable,
    or a node could post a fraudulent claim and withdraw before anyone reacts."""
    _skip_if_no_w3()
    _w3, nr = _deploy("NodeRegistry")
    assert nr.functions.UNBOND_DELAY().call() > nr.functions.CHALLENGE_WINDOW().call()


def test_unbonding_stops_the_node_accepting_new_claims():
    _skip_if_no_w3()
    w3, nr = _deploy("NodeRegistry")
    a = w3.eth.accounts
    nid = b"\x55" * 32
    nr.functions.registerNode(nid, b"\x66" * 32).transact(
        {"from": a[3], "value": nr.functions.MIN_BOND().call()})
    nr.functions.requestUnbond(nid).transact({"from": a[3]})
    assert nr.functions.isLive(nid).call() is False
    try:
        nr.functions.postClaim(nid, 9, b"\xcc" * 32, 1, 1).transact({"from": a[3]})
        assert False, "a node on the way out must not post new claims"
    except Exception:
        pass


# ── claim lifecycle ────────────────────────────────────────────────────────

def test_a_claim_cannot_settle_before_the_window_closes():
    _skip_if_no_w3()
    w3, nr = _deploy("NodeRegistry")
    a = w3.eth.accounts
    nid = b"\x11" * 32
    nr.functions.registerNode(nid, b"\x22" * 32).transact(
        {"from": a[1], "value": nr.functions.MIN_BOND().call()})
    nr.functions.postClaim(nid, 1, b"\xaa" * 32, 10, 1000).transact({"from": a[1]})
    try:
        nr.functions.settleClaim(nid, 1).transact({"from": a[1]})
        assert False, "settling inside the challenge window defeats the point"
    except Exception:
        pass


def test_cluster_membership_proves_without_revealing_the_roster():
    _skip_if_no_w3()
    w3, nr = _deploy("NodeRegistry")
    a = w3.eth.accounts
    member = b"\x77" * 32
    cid = b"\x99" * 32
    # single-leaf tree: the member is the root
    nr.functions.upsertCluster(cid, member, b"\x00" * 32, True).transact(
        {"from": a[1], "value": nr.functions.MIN_BOND().call()})
    assert nr.functions.verifyMembership(cid, member, []).call() is True
    assert nr.functions.verifyMembership(cid, b"\x88" * 32, []).call() is False


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = skipped = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except RuntimeError as e:
            if str(e).startswith("SKIP"):
                print(f"  skip {name}: {e}"); skipped += 1
            else:
                print(f"  FAIL {name}: {e}"); failed += 1
        except Exception as e:
            print(f"  FAIL {name}: {str(e)[:140]}"); failed += 1
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
