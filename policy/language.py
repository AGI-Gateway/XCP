"""
policy.language — institutional intent that a machine can enforce and a
regulator can check.

WHY A LANGUAGE AND NOT A CONFIG FILE
------------------------------------
Until now this project could map controls to regulations and print policy as
illustrative pseudo-syntax. Neither is executable, which leaves the gap that
matters: an organisation can *state* a rule and enforce something else, and no
outside party can tell. A regulator does not want a description of your
controls; they want to verify that the policy you published is the policy that
ran.

So a policy here is a document with three properties:

  · **executable** — the same artifact that is published is the one evaluated
  · **explainable** — every decision names the rule that produced it, so an
    action is contestable rather than merely logged
  · **hashable** — the document digest goes in the audit record, so "which
    policy approved this?" has an answer that cannot be revised afterwards

REVERSIBILITY IS A FIRST-CLASS DIMENSION
----------------------------------------
A setpoint change, a door unlock and an emergency shutdown are not the same kind
of act, and approval logic that treats them alike is wrong in the direction that
hurts. Zhu's Internet of Agentic Things makes the point sharply: once agents
close loops into physical environments, a reasoning failure becomes a physical
action.

Every rule therefore carries a reversibility class, and the engine enforces a
monotonic requirement: the less reversible the act, the more authority and
confirmation it demands. An agent authorised for REVERSIBLE work does not
inherit IRREVERSIBLE authority by being trusted.

    REVERSIBLE    undo is complete and cheap        read, draft, simulate
    RECOVERABLE   undo costs something real         write, schedule, refund
    COSTLY        undo is partial at best           payment, deploy, publish
    IRREVERSIBLE  there is no undo                  delete, unlock, actuate

Status: XCP is a draft proposal.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Iterable, Optional


class Reversibility(IntEnum):
    """How much of the act can be taken back. Ordered, and the order matters."""
    REVERSIBLE = 0
    RECOVERABLE = 1
    COSTLY = 2
    IRREVERSIBLE = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @staticmethod
    def parse(s: str) -> "Reversibility":
        try:
            return Reversibility[str(s).strip().upper()]
        except KeyError:
            raise PolicyError(f"unknown reversibility class {s!r}")


#: Minimum agent/human tier per reversibility class, and whether a second human
#: confirmation is required. Deliberately conservative at the top: an
#: irreversible act should be hard to reach by accident.
FLOOR: dict[Reversibility, tuple[str, bool]] = {
    Reversibility.REVERSIBLE:   ("A0xH0", False),
    Reversibility.RECOVERABLE:  ("A1xH1", False),
    Reversibility.COSTLY:       ("A2xH1", False),
    Reversibility.IRREVERSIBLE: ("A2xH2", True),
}

_TIER_RE = re.compile(r"^A([0-2])xH([0-2])$")


def tier_rank(tier: str) -> tuple[int, int]:
    m = _TIER_RE.match((tier or "").strip())
    if not m:
        return (-1, -1)
    return (int(m.group(1)), int(m.group(2)))


def tier_meets(actual: str, required: str) -> bool:
    a, r = tier_rank(actual), tier_rank(required)
    return a[0] >= r[0] and a[1] >= r[1]


class PolicyError(Exception):
    pass


class Effect(str):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class Rule:
    """
    One statement of intent. Written to be read aloud in a review meeting:

        FinanceAgent MAY transfer up to 10000 USD  [recoverable]
        FinanceAgent MUST NOT delete_ledger        [irreversible]
    """
    id: str
    subject: str                       # agent role, or "*"
    action: str                        # capability or scope, glob-matchable
    effect: str = Effect.ALLOW
    reversibility: Reversibility = Reversibility.REVERSIBLE
    max_amount_minor: Optional[int] = None
    currency: str = ""
    min_tier: str = ""                 # blank = derive from reversibility floor
    requires_human: bool = False
    domains: tuple[str, ...] = ()      # trust domains this may leave to
    note: str = ""

    def effective_min_tier(self) -> str:
        floor, _ = FLOOR[self.reversibility]
        if not self.min_tier:
            return floor
        # A rule may raise the floor but never lower it: a policy author should
        # not be able to make an irreversible act cheap by writing a laxer tier.
        return self.min_tier if tier_meets(self.min_tier, floor) else floor

    def effective_requires_human(self) -> bool:
        return self.requires_human or FLOOR[self.reversibility][1]

    def matches(self, subject: str, action: str) -> bool:
        return (_glob(self.subject, subject) and _glob(self.action, action))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["reversibility"] = self.reversibility.label
        d["domains"] = list(self.domains)
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Rule":
        return Rule(
            id=str(d["id"]), subject=str(d.get("subject", "*")),
            action=str(d["action"]), effect=str(d.get("effect", Effect.ALLOW)),
            reversibility=Reversibility.parse(d.get("reversibility", "reversible")),
            max_amount_minor=d.get("maxAmountMinor"),
            currency=str(d.get("currency", "")),
            min_tier=str(d.get("minTier", "")),
            requires_human=bool(d.get("requiresHuman", False)),
            domains=tuple(d.get("domains", ())),
            note=str(d.get("note", "")))


#: Words an author reaches for when they mean "everyone". Treating these as
#: literal subject names makes a prohibition silently inert — it still denies,
#: because the default is deny, but the author believes they banned something
#: for everyone and they have not.
_ANY = {"*", "", "any", "anyone", "all", "anyagent", "any_agent",
        "everyone", "every", "agent"}


def _glob(pattern: str, value: str) -> bool:
    if pattern.strip().lower() in _ANY:
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


@dataclass
class Decision:
    allowed: bool
    effect: str
    rule_id: str
    reason: str
    reversibility: Reversibility = Reversibility.REVERSIBLE
    requires_human: bool = False
    policy_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "effect": self.effect,
                "ruleId": self.rule_id, "reason": self.reason,
                "reversibility": self.reversibility.label,
                "requiresHuman": self.requires_human,
                "policyDigest": self.policy_digest}


@dataclass
class Policy:
    """
    A set of rules with a stable identity. The digest is what goes in an audit
    record: it is how a later reviewer establishes which policy actually ran,
    rather than which policy is in the repository today.
    """
    name: str
    version: str
    rules: list[Rule] = field(default_factory=list)
    default_effect: str = Effect.DENY      # deny by default, always

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version,
                "defaultEffect": self.default_effect,
                "rules": [r.to_dict() for r in self.rules], "digest": self.digest}

    @property
    def digest(self) -> str:
        """
        Computed over the rules directly, never via to_dict(), which now
        publishes the digest — routing it back through to_dict() recurses
        until the stack gives out.
        """
        blob = json.dumps(
            {"name": self.name, "version": self.version,
             "defaultEffect": self.default_effect,
             "rules": [r.to_dict() for r in self.rules]},
            sort_keys=True, separators=(",", ":")).encode()
        return "0x" + hashlib.sha256(blob).hexdigest()

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Policy":
        p = Policy(name=str(d.get("name", "unnamed")),
                   version=str(d.get("version", "0")),
                   default_effect=str(d.get("defaultEffect", Effect.DENY)))
        if p.default_effect != Effect.DENY:
            raise PolicyError(
                "defaultEffect must be deny: a policy that permits what it does "
                "not mention cannot be reasoned about")
        seen = set()
        for rd in d.get("rules", []):
            r = Rule.from_dict(rd)
            if r.id in seen:
                raise PolicyError(f"duplicate rule id {r.id!r}")
            seen.add(r.id)
            p.rules.append(r)
        return p

    def shadowed(self) -> list[tuple[str, str]]:
        """
        Permits that can never fire because a broader prohibition already covers
        them. These are the dangerous kind of dead rule: the author reads the
        document, sees the permission, and believes the capability is available.
        Returns (shadowed_rule_id, shadowing_rule_id) pairs.
        """
        def covers(broad: str, narrow: str) -> bool:
            if broad == "*":
                return True
            if broad.endswith("*"):
                return narrow.startswith(broad[:-1])
            return broad.lower() == narrow.lower()

        out: list[tuple[str, str]] = []
        for i, r in enumerate(self.rules):
            if str(r.effect) != str(Effect.ALLOW):
                continue
            for other in self.rules[:i]:
                if (str(other.effect) == str(Effect.DENY)
                        and covers(other.subject, r.subject)
                        and covers(other.action, r.action)):
                    out.append((r.id, other.id))
                    break
        return out

    def validate(self) -> list[str]:
        _shadow = [f"rule {a} can never fire: {b} already prohibits it"
                   for a, b in self.shadowed()]
        problems: list[str] = list(_shadow)
        for r in self.rules:
            if r.effect not in (Effect.ALLOW, Effect.DENY, Effect.REQUIRE_APPROVAL):
                problems.append(f"{r.id}: unknown effect {r.effect!r}")
            if r.max_amount_minor is not None and not r.currency:
                problems.append(f"{r.id}: an amount limit needs a currency")
            if r.min_tier and tier_rank(r.min_tier) == (-1, -1):
                problems.append(f"{r.id}: malformed tier {r.min_tier!r}")
            if (r.min_tier and not tier_meets(r.min_tier,
                                              FLOOR[r.reversibility][0])):
                problems.append(
                    f"{r.id}: minTier {r.min_tier} is below the floor for "
                    f"{r.reversibility.label} acts; the floor will be applied "
                    "instead, but say what you mean")
            if (r.effect == Effect.DENY
                    and r.subject.strip().lower() not in _ANY
                    and r.subject.lower().startswith(("any", "all", "every"))):
                problems.append(
                    f"{r.id}: subject {r.subject!r} reads like a wildcard but is "
                    "not one; write '*' if the prohibition is meant for everyone")
        return problems


@dataclass
class Request:
    subject: str
    action: str
    tier: str = ""
    amount_minor: Optional[int] = None
    currency: str = ""
    target_domain: str = ""
    human_approved: bool = False


def evaluate(policy: Policy, req: Request) -> Decision:
    """
    Decide, and say which rule decided. Deny-by-default, most specific match
    wins, and an explicit DENY always beats an ALLOW at the same specificity.
    """
    dg = policy.digest
    candidates = [r for r in policy.rules if r.matches(req.subject, req.action)]
    if not candidates:
        return Decision(False, Effect.DENY, "", 
                        "no rule permits this; policy denies by default",
                        policy_digest=dg)

    # An explicit prohibition is never overridden by a permission.
    denies = [r for r in candidates if r.effect == Effect.DENY]
    if denies:
        r = denies[0]
        return Decision(False, Effect.DENY, r.id,
                        r.note or f"prohibited by {r.id}",
                        r.reversibility, r.effective_requires_human(), dg)

    # Prefer the most specific rule: exact action over prefix over wildcard.
    def specificity(r: Rule) -> tuple[int, int]:
        return (0 if r.action in ("*", "") else 1 if r.action.endswith("*") else 2,
                0 if r.subject in ("*", "") else 1)
    r = max(candidates, key=specificity)

    need = r.effective_min_tier()
    if not tier_meets(req.tier, need):
        return Decision(False, Effect.DENY, r.id,
                        f"{r.reversibility.label} action requires tier {need}; "
                        f"caller presented {req.tier or 'none'}",
                        r.reversibility, r.effective_requires_human(), dg)

    if r.max_amount_minor is not None and req.amount_minor is not None:
        if r.currency and req.currency and r.currency != req.currency:
            return Decision(False, Effect.DENY, r.id,
                            f"limit is denominated in {r.currency}, request in "
                            f"{req.currency}", r.reversibility,
                            r.effective_requires_human(), dg)
        if req.amount_minor > r.max_amount_minor:
            return Decision(False, Effect.DENY, r.id,
                            f"amount {req.amount_minor} exceeds the limit "
                            f"{r.max_amount_minor} set by {r.id}",
                            r.reversibility, r.effective_requires_human(), dg)

    if r.domains and req.target_domain and req.target_domain not in r.domains:
        return Decision(False, Effect.DENY, r.id,
                        f"{r.id} does not permit leaving to "
                        f"{req.target_domain}", r.reversibility,
                        r.effective_requires_human(), dg)

    if r.effective_requires_human() and not req.human_approved:
        return Decision(False, Effect.REQUIRE_APPROVAL, r.id,
                        f"{r.reversibility.label} action requires human "
                        "approval before it proceeds",
                        r.reversibility, True, dg)

    return Decision(True, Effect.ALLOW, r.id, r.note or f"permitted by {r.id}",
                    r.reversibility, r.effective_requires_human(), dg)


# ── a readable surface, because policy gets reviewed by non-engineers ──────

_STMT = re.compile(
    r"^(?P<subj>[\w*.-]+)\s+(?P<mod>MAY NOT|MUST NOT|MAY|MUST)\s+"
    r"(?P<action>[\w*:/.-]+)"
    r"(?:\s+up\s+to\s+(?P<amt>\d+)\s+(?P<cur>[A-Z]{3,6}))?"
    r"(?:\s+\[(?P<rev>\w+)\])?\s*$", re.I)


def parse_text(text: str, name: str = "policy", version: str = "1") -> Policy:
    """
    Parse the statement form used in reviews and documentation:

        FinanceAgent MAY transfer up to 10000 USD [recoverable]
        FinanceAgent MUST NOT delete_ledger [irreversible]
        ResearchAgent MAY mcp:tools/* [reversible]

    Deliberately small. A policy language people cannot read in a meeting gets
    approved without being understood, which defeats the point of writing it.
    """
    pol = Policy(name=name, version=version)
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _STMT.match(line)
        if not m:
            raise PolicyError(f"line {n}: cannot parse {line!r}")
        mod = m.group("mod").upper()
        rev = Reversibility.parse(m.group("rev") or "reversible")
        pol.rules.append(Rule(
            id=f"r{n}", subject=m.group("subj"), action=m.group("action"),
            effect=Effect.DENY if "NOT" in mod else Effect.ALLOW,
            reversibility=rev,
            max_amount_minor=int(m.group("amt")) if m.group("amt") else None,
            currency=(m.group("cur") or "").upper(),
            requires_human=(mod == "MUST"),
            note=line))
    return pol


def explain(policy: Policy) -> str:
    """Render a policy back as statements, for review and for publication."""
    out = [f"# {policy.name} v{policy.version}",
           f"# digest {policy.digest}",
           f"# default: {policy.default_effect}", ""]
    for r in policy.rules:
        mod = "MUST NOT" if r.effect == Effect.DENY else (
            "MUST" if r.effective_requires_human() else "MAY")
        amt = (f" up to {r.max_amount_minor} {r.currency}"
               if r.max_amount_minor is not None else "")
        out.append(f"{r.subject} {mod} {r.action}{amt} "
                   f"[{r.reversibility.label}]  # tier >= {r.effective_min_tier()}")
    return "\n".join(out)


__all__ = ["Reversibility", "FLOOR", "Rule", "Policy", "Request", "Decision",
           "Effect", "evaluate", "parse_text", "explain", "PolicyError",
           "tier_meets", "tier_rank"]
