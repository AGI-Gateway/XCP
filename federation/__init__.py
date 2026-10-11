"""
federation — a web of XCP nodes with no central authority.

    from federation import Federation, NodeRecord, verify_node_record

A node proves itself with a domain and a TLS certificate. Peers verify it
directly. Trust travels transitively with decay. No registry, no chain, no
vendor — see federation/README.md for what IS still depended on.
"""
from .node import (protocol_incompatible, NodeRecord, Peer, Attestation, Federation, PeerTrust,
                   build_node_record, verify_node_record, digest, canonical,
                   FederationError, NODE_RECORD_PATH, NODE_SPEC_VERSION,
                   DECAY_PER_HOP, MAX_HOPS)

from .identity import (sign_revocation, verify_revocation, NodeIdentity, CertBinding, BindingSet, IdentityError,
                       sign_binding, verify_binding, rotate, accept,
                       node_id_from_address, ROTATION_GRACE)
from .transport import (TransportReceipt, EpochCommitment, RoutingLedger,
                        RouteClass, sign_receipt, verify_receipt, merkle_root,
                        merkle_proof, verify_proof, bucket_count,
                        prove_bad_signature, prove_not_in_tree,
                        prove_double_claim, prove_total_mismatch,
                        TransportError, EPOCH_SECONDS, CHALLENGE_WINDOW)

__all__ = ["sign_revocation", "verify_revocation", "NodeIdentity", "CertBinding", "BindingSet", "IdentityError",
           "sign_binding", "verify_binding", "rotate", "accept",
           "node_id_from_address", "ROTATION_GRACE",
           "TransportReceipt", "EpochCommitment", "RoutingLedger", "RouteClass",
           "sign_receipt", "verify_receipt", "merkle_root", "merkle_proof",
           "verify_proof", "bucket_count", "prove_bad_signature",
           "prove_not_in_tree", "prove_double_claim", "prove_total_mismatch",
           "TransportError", "EPOCH_SECONDS", "CHALLENGE_WINDOW",
           "NodeRecord", "Peer", "Attestation", "Federation", "PeerTrust",
           "build_node_record", "verify_node_record", "digest", "canonical",
           "FederationError", "NODE_RECORD_PATH", "NODE_SPEC_VERSION",
           "DECAY_PER_HOP", "MAX_HOPS"]

from .routing import (Effect, PeerMetrics, Policy, Candidate, select,
                      admissible, score, concentration, RoutingError)
__all__ = list(globals().get("__all__", [])) + [
    "Effect", "PeerMetrics", "Policy", "Candidate", "select", "admissible",
    "score", "concentration", "RoutingError"]

from .delegation import (DELEGATION_SPEC_VERSION, DEFAULT_MAX_HOPS,
                         DEFAULT_TICKET_TTL, Admission, DelegationError,
                         DelegationHop, DelegationTicket, admit,
                         canonical_tier, extend, format_tier, narrow_tier,
                         parse_tier, task_digest)
from .delegation import mint as mint_ticket
from .delegation import widens as tier_widens
__all__ = list(globals().get("__all__", [])) + [
    "DELEGATION_SPEC_VERSION", "DEFAULT_MAX_HOPS", "DEFAULT_TICKET_TTL",
    "Admission", "DelegationError", "DelegationHop", "DelegationTicket",
    "admit", "canonical_tier", "extend", "format_tier", "narrow_tier",
    "parse_tier", "task_digest", "mint_ticket", "tier_widens"]

from .cluster import (CLUSTER_SPEC_VERSION, ClusterCharter, ClusterError,
                      ClusterPosture, MemberSet, MembershipClaim,
                      build_member_set, cluster_id_from_name, issue_claim,
                      load_posture, membership_proof, membership_root,
                      sign_charter, verify_charter, verify_member,
                      verify_membership_proof)
__all__ = list(globals().get("__all__", [])) + [
    "CLUSTER_SPEC_VERSION", "ClusterCharter", "ClusterError", "ClusterPosture",
    "MemberSet", "MembershipClaim", "build_member_set", "cluster_id_from_name",
    "issue_claim", "load_posture", "membership_proof", "membership_root",
    "sign_charter", "verify_charter", "verify_member",
    "verify_membership_proof"]

from .peerfetch import (CA_BUNDLE_ENV, FetchedRecord, PeerFetchError,
                        PeerTrustConfigError, fetch_node_record,
                        peer_ca_bundle, peer_certificate_der, peer_ssl_context,
                        peer_verify, trust_summary)
from .peerfetch import validate_config as validate_peer_trust
__all__ = list(globals().get("__all__", [])) + [
    "CA_BUNDLE_ENV", "FetchedRecord", "PeerFetchError", "PeerTrustConfigError",
    "fetch_node_record", "peer_ca_bundle", "peer_certificate_der",
    "peer_ssl_context", "peer_verify", "trust_summary", "validate_peer_trust"]
