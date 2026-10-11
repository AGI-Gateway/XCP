"""
ops.profiles — deployment profiles, validated against the settings registry.

WHY THESE ARE CODE AND NOT A FOLDER OF .env FILES
-------------------------------------------------
A hand-written example config is wrong the moment a setting is renamed, and it
is wrong silently: the file still parses, the node still boots, and the setting
the operator believed they set is simply absent. This project has already been
bitten twice by the same shape of drift -- the README's catalogue figures, and a
config-drift scanner that only matched string literals and let
`XCP_PEER_CA_BUNDLE` through by luck.

So profiles are declared here, as data, and validated against `ops.config
.SETTINGS` by a test. A profile naming a setting that does not exist fails the
build rather than shipping as a file nobody diffs.

WHAT A PROFILE MAY AND MAY NOT DO
---------------------------------
Three rules, each of which exists because the alternative is a plausible
accident:

  1. **Every key must be a real setting.** Catches the rename and the typo.
     `XCP_POSTURE` vs `XCP_POSTURE_MODE` is not a visible failure at runtime;
     the second is ignored and the first keeps its default, which is the
     opposite of what the operator intended in exactly the cases that matter.

  2. **An unsafe setting must be acknowledged with a reason.** Nine settings in
     the registry weaken a control when set. A profile may still set one -- the
     evaluation profile deliberately runs in `observe` -- but it must say why
     in `acknowledged_unsafe`, and that reason is rendered into the generated
     file as a comment. An operator who copies a profile should be told what
     they are accepting, in the file they copied.

  3. **No profile carries a secret value.** Eleven settings are secrets. A
     profile may name one to document that it is required, with an empty value;
     it may never contain the value. A profile is a committed file, and a
     committed secret is a leaked secret regardless of the repository's
     visibility today.

THE PROFILES THEMSELVES
-----------------------
Three, in increasing order of what they turn on, matching the four deployment
shapes in the architecture documentation. Each is a floor rather than a
recommendation: `enforce` is what a production single-site node needs at
minimum, not everything it should have.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .config import SETTINGS, Setting, get


class ProfileError(Exception):
    """A profile that contradicts the settings registry."""


@dataclass(frozen=True)
class Profile:
    name: str
    purpose: str
    #: setting name -> value. Order is preserved for the generated file.
    settings: dict[str, str] = field(default_factory=dict)
    #: setting name -> why weakening this control is acceptable HERE. Any
    #: unsafe setting in `settings` must appear here or validation fails.
    acknowledged_unsafe: dict[str, str] = field(default_factory=dict)
    #: Settings an operator must supply themselves, with a note on each. These
    #: are rendered with empty values so the file documents the requirement
    #: without pretending to satisfy it.
    operator_supplied: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        """Raise ProfileError on any of the three rules in the module docstring."""
        for name in list(self.settings) + list(self.operator_supplied):
            if get(name) is None:
                raise ProfileError(
                    f"profile {self.name!r} names {name!r}, which is not in "
                    f"ops.config.SETTINGS. Either the setting was renamed and "
                    f"this profile silently stopped applying it, or it is a "
                    f"typo that would be ignored at runtime.")

        for name in self.settings:
            s = get(name)
            assert s is not None                      # checked above
            # The registry flags a SETTING as unsafe, not a value, and every
            # unsafe setting's default is its safe value (asserted by
            # tests/test_config_profiles.py, because an unsafe setting with an
            # unsafe default would quietly defeat this rule). So what needs
            # acknowledging is MOVING one off its default -- restating the
            # safe default is a no-op, and demanding a justification for it
            # would train operators to write boilerplate past the one marker
            # that matters.
            if s.unsafe and self.settings[name] != s.default \
                    and name not in self.acknowledged_unsafe:
                raise ProfileError(
                    f"profile {self.name!r} sets {name!r} to "
                    f"{self.settings[name]!r}, away from its safe default "
                    f"{s.default!r}, without a reason in acknowledged_unsafe. "
                    f"An operator copying this profile should be told what "
                    f"they are accepting.")
            if s.secret and self.settings[name]:
                raise ProfileError(
                    f"profile {self.name!r} gives {name!r} a value, and it is "
                    f"a secret. Name it in operator_supplied instead; a "
                    f"committed secret is a leaked secret.")

        for name in self.acknowledged_unsafe:
            s = get(name)
            if name not in self.settings:
                raise ProfileError(
                    f"profile {self.name!r} acknowledges {name!r} but does not "
                    f"set it. A stale acknowledgement reads as approval of "
                    f"something that is not happening.")
            if s is not None and self.settings[name] == s.default:
                raise ProfileError(
                    f"profile {self.name!r} acknowledges {name!r}, but sets it "
                    f"to its safe default {s.default!r}. Acknowledging a "
                    f"control that is not actually weakened makes the "
                    f"acknowledgement list useless as a thing to read.")

    def to_env(self) -> str:
        """Render as a .env file, with every setting's own description inline."""
        out = [f"# XCP deployment profile: {self.name}",
               "#", f"# {self.purpose}", "#",
               "# Generated by scripts/generate-config-profiles.py from",
               "# ops/profiles.py. Do not edit: a hand-edited profile is a",
               "# profile that has drifted from the settings registry.", ""]

        if self.acknowledged_unsafe:
            out += ["# " + "-" * 68,
                    "# THIS PROFILE DELIBERATELY WEAKENS CONTROLS",
                    "# " + "-" * 68]
            for name, why in self.acknowledged_unsafe.items():
                out.append(f"#   {name}: {why}")
            out.append("")

        for name, value in self.settings.items():
            s = get(name)
            assert s is not None
            marker = "  [WEAKENS A CONTROL]" if s.unsafe else ""
            out.append(f"# {s.description}{marker}")
            out.append(f"{name}={value}")
            out.append("")

        if self.operator_supplied:
            out += ["# " + "-" * 68,
                    "# YOU MUST SUPPLY THESE. Empty here on purpose.",
                    "# " + "-" * 68, ""]
            for name, note in self.operator_supplied.items():
                s = get(name)
                assert s is not None
                out.append(f"# {s.description}")
                out.append(f"#   {note}")
                out.append(f"{name}=")
                out.append("")

        return "\n".join(out).rstrip() + "\n"


# ── the profiles ───────────────────────────────────────────────────────────

EVALUATION = Profile(
    name="evaluation",
    purpose=("A single node for trying XCP against endpoints you have not "
             "vetted. Audits every decision and blocks none, so you can see "
             "what enforcement WOULD do before it does it. Not a steady "
             "state: a node left here refuses nothing."),
    settings={
        "XCP_POSTURE": "observe",
        "XCP_SECURITY": "0",
        "XCP_RATE_LIMIT": "1",
        "XCP_GATEWAY_ID": "gw-eval",
    },
    acknowledged_unsafe={
        "XCP_POSTURE": ("observe is the entire point of this profile -- it "
                        "logs the decision a mandate gate would have made "
                        "without making it. Every node running this profile "
                        "is an open relay with a very good audit trail."),
    },
)

ENFORCE = Profile(
    name="enforce",
    purpose=("A production single-site node. The full decision path: mandates "
             "gate scopes, the argument firewall inspects tool arguments, and "
             "abuse controls are on. No federation."),
    settings={
        "XCP_POSTURE": "enforce",
        "XCP_SECURITY": "1",
        "XCP_RATE_LIMIT": "1",
        "XCP_LIMIT_FAIL_OPEN": "0",
        "XCP_PROFILE": "production",
        # Pinned at their safe defaults on purpose. coverage() reports an
        # unsafe setting no profile mentions, because that is a setting an
        # operator meets for the first time during an incident. Restating the
        # default costs nothing and needs no acknowledgement.
        "REQUIRE_VERIFIED": "1",
        "XCP_SEAL_EPHEMERAL": "0",
        "XCP_OTEL_DETAIL": "scrubbed",
    },
    operator_supplied={
        "XCP_UPSTREAMS": ('JSON map of server name to MCP URL, e.g. '
                          '{"research":"https://mcp.internal/mcp"}'),
        "XCP_VERIFY_URL": "URL of your verifier, e.g. http://verifier:8500",
        "XCP_ADMIN_TOKEN": ("required to reach /admin/revoke. Keep it in a "
                            "secret backend, never in this file or an image."),
    },
)

PRIVATE_FEDERATION = Profile(
    name="private-federation",
    purpose=("Independent nodes across datacentres in one trust domain. Adds "
             "declared peer ranges, an internal CA that REPLACES the public "
             "trust store, a signed cluster charter, and site locality with "
             "data residency."),
    settings={
        "XCP_POSTURE": "enforce",
        "XCP_SECURITY": "1",
        "XCP_RATE_LIMIT": "1",
        "XCP_LIMIT_FAIL_OPEN": "0",
        "XCP_PROFILE": "production",
        "XCP_A2A_ACCEPT": "1",
        "XCP_A2A_MAX_HOPS": "3",
        "XCP_TOOL_RELAY": "1",
        "XCP_TOOL_FALLBACK": "0",
        "XCP_NODE_RECORD_PUBLIC": "0",
        "REQUIRE_VERIFIED": "1",
        "XCP_SEAL_EPHEMERAL": "0",
        "XCP_OTEL_DETAIL": "scrubbed",
    },
    operator_supplied={
        "XCP_PRIVATE_PEER_CIDRS": (
            "comma-separated internal ranges that may hold peers, e.g. "
            "10.20.0.0/16,10.30.0.0/16. Narrower than allowing all private "
            "space; an undeclared range is still refused, and no declaration "
            "can re-admit link-local or cloud metadata."),
        "XCP_PEER_CA_BUNDLE": (
            "path to your internal CA. This REPLACES the public trust store "
            "for peer connections rather than adding to it -- that is the "
            "point, and it is why peering still refuses plain HTTP."),
        "XCP_CLUSTER_CHARTER": "path to the signed charter for this cluster",
        "XCP_CLUSTER_MEMBERSHIP": "path to this node's membership claim",
        "XCP_NODE_SITE": (
            "this node's site, e.g. eu-west. A peer elsewhere is priced at "
            "CROSS_SITE_COST and can still win on cost."),
        "XCP_RESIDENCY_SITES": (
            "sites data may reach. Unlike locality this is a CONSTRAINT: a "
            "site outside this set is inadmissible at any price."),
        "XCP_UPSTREAMS": "JSON map of server name to MCP URL",
        "XCP_VERIFY_URL": "URL of your verifier",
        "XCP_ADMIN_TOKEN": "keep it in a secret backend",
    },
)

PROFILES: tuple[Profile, ...] = (EVALUATION, ENFORCE, PRIVATE_FEDERATION)

_BY_NAME = {p.name: p for p in PROFILES}


def get_profile(name: str) -> Optional[Profile]:
    return _BY_NAME.get(name.strip().lower())


def validate_all() -> None:
    for p in PROFILES:
        p.validate()


#: Unsafe settings no profile may mention, and why. `XCP_ALLOW_INSECURE_PEERS`
#: permits plain HTTP and ANY private or loopback address; it exists for local
#: development and there is no deployment profile in which it is defensible.
#: Shipping a profile that named it -- even set to 0 -- would put the string
#: into files operators copy and edit, and the edit is a one-character change.
#: So it is deliberately absent rather than pinned, and this constant is what
#: keeps "absent" distinguishable from "forgotten".
NEVER_IN_A_PROFILE: dict[str, str] = {
    "XCP_ALLOW_INSECURE_PEERS":
        "development only; declare XCP_PRIVATE_PEER_CIDRS instead, which is "
        "narrower and cannot re-admit link-local or cloud metadata",
}


def coverage() -> dict[str, object]:
    """
    Which settings no profile mentions.

    Not a defect on its own -- most settings are sensibly left at their
    default -- but an unsafe setting that no profile mentions is one an
    operator will meet for the first time in an incident.
    """
    mentioned = {n for p in PROFILES
                 for n in list(p.settings) + list(p.operator_supplied)}
    unsafe_unmentioned = sorted(
        s.name for s in SETTINGS
        if s.unsafe and s.name not in mentioned
        and s.name not in NEVER_IN_A_PROFILE)
    return {
        "settings": len(SETTINGS),
        "mentioned": len(mentioned),
        "profiles": len(PROFILES),
        #: Unsafe settings that are neither pinned by a profile nor
        #: deliberately excluded. Should be empty: anything here is a control
        #: an operator will meet for the first time in an incident.
        "unsafeUnmentioned": unsafe_unmentioned,
        "deliberatelyExcluded": sorted(NEVER_IN_A_PROFILE),
    }


__all__ = ["Profile", "ProfileError", "PROFILES", "EVALUATION", "ENFORCE",
           "PRIVATE_FEDERATION", "get_profile", "validate_all", "coverage"]
