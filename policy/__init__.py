"""
policy — institutional intent, executable and checkable.

    from policy import parse_text, evaluate, Request, Reversibility

The document that is published is the document that runs, and its digest goes in
the audit record — so "which policy approved this?" has an answer that cannot be
revised afterwards.
"""
from .language import (Reversibility, FLOOR, Rule, Policy, Request, Decision,
                       Effect, evaluate, parse_text, explain, PolicyError,
                       tier_meets, tier_rank)

__all__ = ["Reversibility", "FLOOR", "Rule", "Policy", "Request", "Decision",
           "Effect", "evaluate", "parse_text", "explain", "PolicyError",
           "tier_meets", "tier_rank"]
