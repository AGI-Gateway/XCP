"""
federation — a web of XCP nodes with no central authority.

    from federation import Federation, NodeRecord, verify_node_record

A node proves itself with a domain and a TLS certificate. Peers verify it
directly. Trust travels transitively with decay. No registry, no chain, no
vendor — see federation/README.md for what IS still depended on.
"""
from .node import (NodeRecord, Peer, Attestation, Federation, PeerTrust,
                   build_node_record, verify_node_record, digest, canonical,
                   FederationError, NODE_RECORD_PATH, NODE_SPEC_VERSION,
                   DECAY_PER_HOP, MAX_HOPS)

from .transport import (TransportReceipt, EpochCommitment, RoutingLedger,
                        RouteClass, sign_receipt, verify_receipt, merkle_root,
                        merkle_proof, verify_proof, bucket_count,
                        prove_bad_signature, prove_not_in_tree,
                        prove_double_claim, prove_total_mismatch,
                        TransportError, EPOCH_SECONDS, CHALLENGE_WINDOW)

__all__ = ["TransportReceipt", "EpochCommitment", "RoutingLedger", "RouteClass",
           "sign_receipt", "verify_receipt", "merkle_root", "merkle_proof",
           "verify_proof", "bucket_count", "prove_bad_signature",
           "prove_not_in_tree", "prove_double_claim", "prove_total_mismatch",
           "TransportError", "EPOCH_SECONDS", "CHALLENGE_WINDOW",
           "NodeRecord", "Peer", "Attestation", "Federation", "PeerTrust",
           "build_node_record", "verify_node_record", "digest", "canonical",
           "FederationError", "NODE_RECORD_PATH", "NODE_SPEC_VERSION",
           "DECAY_PER_HOP", "MAX_HOPS"]
