#!/usr/bin/env python3
"""
rotate-cert.py — republish a node record after a certificate renewal.

Designed to run unattended as a certbot deploy hook. Because node identity is a
long-lived key rather than the certificate, a renewal is a new signed *binding*,
not a new node: peers keep their trust, attestations others issued still apply,
and revocations keyed to the node id still bite.

    # one-off: create the node's permanent identity
    python scripts/rotate-cert.py --init

    # every renewal (certbot deploy hook)
    XCP_NODE_KEY=... python scripts/rotate-cert.py \\
        --cert /etc/letsencrypt/live/node.example/fullchain.pem \\
        --domain node.example \\
        --record /var/www/.well-known/xcp-node.json

Install as a hook:
    /etc/letsencrypt/renewal-hooks/deploy/xcp-rotate.sh
"""
import argparse, json, os, pathlib, sys, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--init", action="store_true",
                    help="generate the node's permanent identity and exit")
    ap.add_argument("--cert", help="PEM certificate that is now being served")
    ap.add_argument("--domain")
    ap.add_argument("--record", default="well-known/xcp-node.json")
    ap.add_argument("--gateway-url")
    ap.add_argument("--ttl-days", type=int, default=90)
    args = ap.parse_args()

    from federation.identity import NodeIdentity, BindingSet, rotate
    from federation.node import NodeRecord

    if args.init:
        ident = NodeIdentity.generate()
        print("Node identity created. Store the key in your secret backend —")
        print("losing it means losing this node's identity and every")
        print("attestation any peer has made about it.\n")
        print(f"  XCP_NODE_KEY={ident.private_key}")
        print(f"  node_id={ident.node_id}")
        return 0

    key = os.environ.get("XCP_NODE_KEY", "")
    if not key:
        print("XCP_NODE_KEY is not set. Run --init once, then store it.",
              file=sys.stderr)
        return 2
    if not (args.cert and args.domain):
        print("--cert and --domain are required", file=sys.stderr)
        return 2

    ident = NodeIdentity.from_key(key)
    from security.xcpsec.mtls import cert_footprint_pem
    footprint = cert_footprint_pem(pathlib.Path(args.cert).read_bytes())

    rec_path = pathlib.Path(args.record)
    existing_bs, existing_rec = None, {}
    if rec_path.is_file():
        try:
            existing_rec = json.loads(rec_path.read_text())
            if existing_rec.get("bindings"):
                existing_bs = BindingSet.from_dict(existing_rec["bindings"])
        except Exception as e:
            print(f"warning: could not read the existing record ({e}); "
                  "starting a new binding chain", file=sys.stderr)

    if existing_bs and existing_bs.current.cert_footprint.lower() == footprint.lower():
        print(f"certificate unchanged ({footprint[:18]}…) — nothing to do")
        return 0

    bs = rotate(ident, footprint, domain=args.domain, existing=existing_bs,
                ttl=args.ttl_days * 86400)

    rec = NodeRecord(
        domain=args.domain, node_id=ident.node_id,
        gateway_url=args.gateway_url or existing_rec.get("gateway_url")
                    or f"https://{args.domain}",
        operator=existing_rec.get("operator", "anonymous"),
        seed_peers=existing_rec.get("seed_peers", []),
        published_at=int(time.time()),
        bindings=bs.to_dict(), cert_footprint=footprint)
    problems = rec.validate()
    if problems:
        print("refusing to publish an invalid record: " + "; ".join(problems),
              file=sys.stderr)
        return 1

    rec_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = rec_path.with_suffix(".tmp")
    tmp.write_text(rec.to_json())
    tmp.replace(rec_path)                  # atomic: peers never read a half file

    print(f"rotated to {footprint[:18]}…  sequence {bs.sequence}")
    print(f"  node_id unchanged: {ident.node_id[:18]}…")
    print(f"  wrote {rec_path}")
    print("  peers pick this up on their next fetch; no re-peering needed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
