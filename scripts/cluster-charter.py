#!/usr/bin/env python3
"""
cluster-charter.py — the cluster authority's side of a private federation.

A private federation's member set is committed to by a Merkle root and signed
by the organisation's own authority key. This script is what the authority
runs: it holds the member list, publishes a charter that reveals only a root,
and hands each node its own proof.

    # once: create the authority key. BACK IT UP — losing it means every node
    # has to be reconfigured with a new one.
    python scripts/cluster-charter.py init --name acme-internal

    # whenever the member set changes, including the first time
    XCP_CLUSTER_AUTHORITY_KEY=0x... python scripts/cluster-charter.py issue \\
        --name acme-internal --epoch 1 \\
        --member 0x<dc1-node-id> --member 0x<dc2-node-id> \\
        --out ./cluster/

Distribute from `--out`:
  · charter.json              to EVERY node        (XCP_CLUSTER_CHARTER)
  · membership-<nodeid>.json  to THAT node only    (XCP_CLUSTER_MEMBERSHIP)
  · members.json              keep on the authority — this one IS the roster

REMOVING A NODE is re-issuing at a higher epoch without it. The removed node
keeps a proof that is still perfectly valid and no longer verifies against the
root its former peers now hold. There is no revocation list to distribute and
nothing to wait out: peers refuse it from the moment they load the new charter.

Anchoring on-chain later is optional and changes nothing here. The root this
script computes is the one `NodeRegistry.upsertCluster` takes, and proofs it
issues verify under `verifyMembership` unchanged.
"""
import argparse
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from federation.cluster import (ClusterCharter, ClusterError,  # noqa: E402
                                MemberSet, build_member_set,
                                cluster_id_from_name, digest, issue_claim,
                                sign_charter, verify_charter, verify_member)

KEY_ENV = "XCP_CLUSTER_AUTHORITY_KEY"


def _authority_key() -> str:
    key = os.getenv(KEY_ENV, "").strip()
    if not key:
        sys.exit(f"{KEY_ENV} is not set. This is the cluster authority's "
                 f"signing key; run `init` if you do not have one yet.")
    return key


def cmd_init(args) -> int:
    from eth_account import Account
    acct = Account.create()
    cid = cluster_id_from_name(args.name)
    print(f"""
Cluster authority created.

  cluster name     {args.name}
  cluster id       {cid}
  authority        {acct.address}
  authority key    {acct.key.hex()}

BACK THE KEY UP OFFLINE NOW. Every node is configured with the authority
ADDRESS and refuses a charter signed by anything else, so losing the key means
reconfiguring every node in the cluster.

Next, on this machine:

  export {KEY_ENV}={acct.key.hex()}
  python scripts/cluster-charter.py issue --name {args.name} --epoch 1 \\
      --member 0x<node-id> --member 0x<node-id> --out ./cluster/

And on every node:

  XCP_CLUSTER_AUTHORITY={acct.address}
""".rstrip())
    return 0


def cmd_issue(args) -> int:
    key = _authority_key()
    cid = cluster_id_from_name(args.name)
    members = [m.strip().lower() for m in args.member]

    prior = None
    if args.members_in:
        prior = MemberSet.from_dict(json.loads(
            pathlib.Path(args.members_in).read_text(encoding="utf-8")))
        if prior.cluster_id.lower() != cid.lower():
            sys.exit(f"{args.members_in} is for a different cluster")

    try:
        ms = build_member_set(cid, members)
    except ClusterError as e:
        sys.exit(str(e))
    # Carry the previous pads forward so an unchanged member set produces an
    # unchanged root. Without this, re-issuing to bump a policy hash would
    # rebuild the tree with fresh pads, change the root, and invalidate every
    # member's proof for no reason anyone asked for.
    if prior and prior.pads and len(members) < 2:
        ms = MemberSet(cluster_id=cid, node_ids=ms.node_ids, pads=prior.pads)

    policy_hash = args.policy_hash
    if args.policy:
        policy_hash = digest(pathlib.Path(args.policy).read_bytes())

    charter = sign_charter(key, ms, policy_hash=policy_hash, epoch=args.epoch,
                           open=args.open, ttl=args.ttl)
    problems = verify_charter(charter, expected_cluster_id=cid,
                              expected_authority=charter.authority)
    if problems:
        sys.exit(f"the charter this script just signed does not verify: "
                 f"{problems[0]}")

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "charter.json").write_text(charter.to_json(), encoding="utf-8")
    (out / "members.json").write_text(
        json.dumps(ms.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    for node_id in ms.node_ids:
        claim = issue_claim(ms, node_id, epoch=args.epoch)
        own = verify_member(charter, claim, expected_node_id=node_id)
        if own:
            sys.exit(f"the proof for {node_id} does not verify: {own[0]}")
        (out / f"membership-{node_id[2:14]}.json").write_text(
            json.dumps(claim.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8")

    print(f"cluster     {args.name}")
    print(f"  id        {cid}")
    print(f"  root      {ms.root}")
    print(f"  epoch     {args.epoch}")
    print(f"  members   {len(ms.node_ids)}"
          + (f" (+{len(ms.pads)} pad leaf)" if ms.pads else ""))
    print(f"  mode      {'open — membership advisory' if args.open else 'closed — members only'}")
    print(f"  authority {charter.authority}")
    print(f"\nwritten to {out}/")
    print(f"  charter.json                 -> every node, as XCP_CLUSTER_CHARTER")
    for node_id in ms.node_ids:
        print(f"  membership-{node_id[2:14]}.json   -> {node_id[:18]}…, "
              f"as XCP_CLUSTER_MEMBERSHIP")
    print(f"  members.json                 -> KEEP HERE. This is the roster the "
          f"charter exists not to publish.")
    if not ms.pads:
        print()
    else:
        print(f"\nThe pad leaf keeps the root from being a member's node id, "
              f"which it would be\nfor a single-member cluster. Keep "
              f"members.json: re-issuing without it would\nmint a new pad and "
              f"change the root for no reason.")
    return 0


def cmd_verify(args) -> int:
    charter = ClusterCharter.from_dict(json.loads(
        pathlib.Path(args.charter).read_text(encoding="utf-8")))
    problems = verify_charter(charter,
                              expected_authority=args.authority or "",
                              min_epoch=args.min_epoch)
    print(f"cluster   {charter.cluster_id}")
    print(f"  epoch   {charter.epoch}")
    print(f"  root    {charter.membership_root}")
    print(f"  mode    {'open' if charter.open else 'closed'}")
    print(f"  signer  {charter.authority}")
    if args.membership:
        from federation.cluster import MembershipClaim
        claim = MembershipClaim.from_dict(json.loads(
            pathlib.Path(args.membership).read_text(encoding="utf-8")))
        problems += [f"membership: {p}"
                     for p in verify_member(charter, claim)]
        print(f"  member  {claim.node_id}")
    if problems:
        print("\nPROBLEMS")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nverifies")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a cluster authority key")
    p.add_argument("--name", required=True, help="cluster name, e.g. acme-internal")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("issue", help="sign a charter and issue member proofs")
    p.add_argument("--name", required=True)
    p.add_argument("--member", action="append", required=True,
                   help="a member node id (0x + 32 bytes); repeat per member")
    p.add_argument("--epoch", type=int, required=True,
                   help="monotonic. Raise it to make a removal take effect.")
    p.add_argument("--out", default="./cluster",
                   help="directory to write charter and proofs into")
    p.add_argument("--members-in", default="",
                   help="a previous members.json, so an unchanged member set "
                        "keeps its root")
    p.add_argument("--policy", default="",
                   help="path to the cluster policy document; its digest is "
                        "committed in the charter")
    p.add_argument("--policy-hash", default="0x" + "00" * 32)
    p.add_argument("--open", action="store_true",
                   help="membership advisory rather than required")
    p.add_argument("--ttl", type=int, default=180 * 86400)
    p.set_defaults(fn=cmd_issue)

    p = sub.add_parser("verify", help="check a charter, and optionally a claim")
    p.add_argument("--charter", required=True)
    p.add_argument("--membership", default="")
    p.add_argument("--authority", default="")
    p.add_argument("--min-epoch", type=int, default=0)
    p.set_defaults(fn=cmd_verify)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
