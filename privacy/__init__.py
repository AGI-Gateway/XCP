"""
privacy — retention, erasure, and the tension between them.

    from privacy import KeyRing, seal, unseal, erase, data_map

XCP deliberately holds personal data: the trust lattice is built on knowing
which human an agent acts for. Erasure is handled by destroying a per-subject
key rather than deleting records, so audit chains keep verifying while their
contents become unreadable. See privacy/retention.py for what is held and why.
"""
from .retention import (DataClass, Basis, Subject, CLASSES, classify, erasable,
                        due_for_expiry, data_map, RetentionError, DAY, YEAR)
from .shredding import (KeyRing, SealedPayload, seal, unseal,
                        commitment_survives, pseudonymise, ShredError)
from .erasure import erase, ErasureReport, Retained, pending_expiry

__all__ = ["DataClass", "Basis", "Subject", "CLASSES", "classify", "erasable",
           "due_for_expiry", "data_map", "RetentionError", "DAY", "YEAR",
           "KeyRing", "SealedPayload", "seal", "unseal", "commitment_survives",
           "pseudonymise", "ShredError",
           "erase", "ErasureReport", "Retained", "pending_expiry"]
