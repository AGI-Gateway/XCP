"""
ops.config — every setting, in one place, with the dangerous ones marked.

Configuration was spread across nine modules and two thirds of it was
undocumented, including settings that turn security controls off. An operator
cannot make a safe decision about a variable they do not know exists.

This registry is the single source of truth. A test fails if the code reads an
environment variable that is not declared here, so the table cannot drift again.

    xcp config            # the reference
    xcp config --unsafe   # only the settings that weaken a control
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class Role(str, Enum):
    GATEWAY = "gateway"
    SERVER = "server"
    VERIFIER = "verifier"
    NODE = "node"            # federation identity
    WRAPPER = "wrapper"      # generated API wrappers
    TELEMETRY = "telemetry"
    TOOLING = "tooling"      # scripts and CLI, not the running service


@dataclass(frozen=True)
class Setting:
    name: str
    role: Role
    default: str
    description: str
    #: True when setting this WEAKENS a control. These are the ones an operator
    #: needs to find deliberately rather than stumble onto.
    unsafe: bool = False
    secret: bool = False
    required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "role": self.role.value,
                "default": self.default, "description": self.description,
                "unsafe": self.unsafe, "secret": self.secret,
                "required": self.required}


R = Role

SETTINGS: tuple[Setting, ...] = (
    # ── gateway ──
    Setting("XCP_POSTURE", R.GATEWAY, "enforce",
            "enforce | observe. Observe logs decisions without blocking them — "
            "for onboarding an endpoint you have not vetted, never a steady "
            "state.", unsafe=True),
    Setting("XCP_GATEWAY_ID", R.GATEWAY, "gw-local",
            "Identifier stamped on audit records and forwarded downstream as "
            "XCP-Verified-By."),
    Setting("XCP_UPSTREAMS", R.GATEWAY, "{}",
            'JSON map of name to MCP url, e.g. {"research":"https://.../mcp"}. '
            "Empty means every a2t call 404s.", required=True),
    Setting("XCP_VERIFY_URL", R.GATEWAY, "",
            "External verifier. Unset uses in-memory bindings, which is fine "
            "for one node and insufficient for a federation."),
    Setting("XCP_CACHE_TTL", R.GATEWAY, "30",
            "Seconds to cache a verification result. Longer means a revocation "
            "takes longer to bite."),
    Setting("XCP_SECURITY", R.GATEWAY, "0",
            "Enable the xcpsec argument firewall. The gateway REFUSES TO START "
            "if this is 1 and xcpsec is unavailable, rather than running with a "
            "control you asked for silently absent."),
    Setting("XCP_ADMIN_TOKEN", R.GATEWAY, "",
            "Bearer token for /admin/* and the full peer list. When unset the "
            "administrative endpoints are DISABLED rather than open — an admin "
            "surface that defaults to open is worse than one that does not "
            "exist. Compared in constant time.", secret=True),
    Setting("XCP_ALLOW_INSECURE_PEERS", R.NODE, "0",
            "Permit peering over plain HTTP and to ANY private or loopback "
            "address. This disables the SSRF guard on the peer-record fetch "
            "and is for local development only; on a reachable node it lets a "
            "caller make the gateway fetch internal services. The production "
            "profile refuses to start with it set. For a private federation "
            "use XCP_PRIVATE_PEER_CIDRS, which is the scoped half of this and "
            "does not waive TLS.", unsafe=True),
    Setting("XCP_PRIVATE_PEER_CIDRS", R.NODE, "",
            "Comma-separated internal ranges that may hold federation peers, "
            'e.g. "10.40.0.0/16,fd00:dc1::/48". Without this a peer on a '
            "private address is unreachable, which made a private federation "
            "across datacentres impossible to run under the production "
            "profile. Narrower than XCP_ALLOW_INSECURE_PEERS in two ways: a "
            "host that resolves outside every declared range is still refused, "
            "and loopback, link-local and cloud-metadata addresses stay "
            "refused even when a declaration contains them. TLS is still "
            "required. Declarations broader than /8 (IPv4) or /7 (IPv6) are "
            "refused as a disguised bypass, and a malformed entry stops the "
            "node starting rather than silently narrowing what you declared.",
            unsafe=True),
    Setting("XCP_CLUSTER_CHARTER", R.NODE, "",
            "Path to the signed cluster charter this node federates under. The "
            "charter commits to the member set with a Merkle root and carries "
            "no roster, so it can be distributed to every node without "
            "publishing who is in the cluster. A closed cluster refuses any "
            "peer whose membership proof does not verify against THIS "
            "charter's root — never against one the peer supplied. Unset means "
            "no cluster, and peering is bilateral. A charter that does not "
            "verify stops the node: starting without it would leave a closed "
            "cluster accepting any peer, which is what it exists to prevent."),
    Setting("XCP_CLUSTER_MEMBERSHIP", R.NODE, "",
            "Path to THIS node's own membership proof, issued by the cluster "
            "authority. Published in the node record so peers can verify this "
            "node against their own charter. The node refuses to start if the "
            "proof does not verify, or if it is a proof for a different node — "
            "which catches a membership file copied from another datacentre."),
    Setting("XCP_CLUSTER_AUTHORITY", R.NODE, "",
            "Address of the key allowed to sign this cluster's charters. "
            "Without it a node accepts any correctly-signed charter naming its "
            "cluster id, so anyone could mint one. Set it on every node."),
    Setting("XCP_CLUSTER_MIN_EPOCH", R.NODE, "0",
            "Refuse a charter below this epoch. Raising the epoch is how a "
            "member removal takes effect, so an operator pinning the floor "
            "stops a rolled-back charter file re-admitting a node that was "
            "removed. Set it to the epoch you currently expect."),
    Setting("XCP_A2A_ACCEPT", R.GATEWAY, "0",
            "Accept delegated tasks from peer gateways at /v1/a2a/accept. OFF "
            "by default: a node that accepts them is executing work on another "
            "datacentre's say-so, which an operator should decide deliberately "
            "rather than inherit from an upgrade. A ticket is still only "
            "admitted from a verified peer, in this node's cluster, naming "
            "this node, within its expiry, for the exact task committed to."),
    Setting("XCP_A2A_TIER_CEILING", R.GATEWAY, "A2xH2",
            "The most authority a cross-boundary delegation may carry HERE, "
            "whatever the originating gateway asserted. The asserted tier is "
            "narrowed leg by leg against this, so authority can only shrink at "
            "a boundary. The default is the top of the lattice, meaning "
            "'whatever the origin verified'; an operator who wants delegated "
            "work capped lower sets e.g. A1xH1. The gateway refuses to start "
            "on a value it cannot parse, because a ceiling nobody can read is "
            "a ceiling that does not apply."),
    Setting("XCP_A2A_MAX_HOPS", R.GATEWAY, "3",
            "How many boundaries one delegation may cross. Matches the "
            "federation's transitive-trust cap, for the same reason: beyond it "
            "nobody in the chain can reason about what they are part of. The "
            "originator sets the budget in the ticket and no hop can raise it."),
    Setting("XCP_NODE_RECORD_PUBLIC", R.NODE, "0",
            "Serve the FULL node record to anyone, even in a closed cluster. A "
            "closed cluster gates its record by default — publishing the "
            "topology of a federation only members may join is incoherent, and "
            "gating also means a removed member loses discovery and not just "
            "peering. Set this for a node that must stay publicly "
            "discoverable: a public-facing gateway inside a private "
            "organisation, or one under external monitoring. It publishes this "
            "node's id, gateway URL, operator and seed peers.", unsafe=True),
    Setting("XCP_CLUSTER_AUTHORITY_KEY", R.TOOLING, "",
            "The cluster authority's signing key, read by "
            "scripts/cluster-charter.py. Belongs on the authority's machine "
            "only, never on a node: a node needs the address, not the key. "
            "UNRECOVERABLE if lost — every node is configured with the "
            "matching address and would need reconfiguring.", secret=True),
    Setting("XCP_PEER_CA_BUNDLE", R.NODE, "",
            "PEM bundle of the certificate authorities that sign THIS "
            "federation's peers. When set it REPLACES the public trust store "
            "for peer-record fetches and certificate-footprint retrieval — and "
            "for those only, so upstream tool calls keep public trust. Needed "
            "for a private federation using an internal CA: chain validation "
            "ran against the system store and failed before the footprint "
            "binding was reached. A mixed deployment concatenates the public "
            "roots it needs into the same file, which keeps the trust decision "
            "in one auditable place. An unreadable or empty bundle stops the "
            "node starting; falling back to the public store would leave the "
            "operator believing peers are verified against their own CA."),

    Setting("XCP_POLICY", R.GATEWAY, "",
            "Path to a policy document. When set, every governed call is "
            "evaluated against it and the gateway REFUSES TO START if the "
            "document cannot be loaded — a policy you asked for and did not get "
            "is a control you believe you have.", ),
    Setting("XCP_POLICY_APPROVED_DIGEST", R.GATEWAY, "",
            "Digest of the policy an auditor approved. The gateway compares it "
            "against the policy it is actually enforcing and warns on "
            "divergence, which is what gives the policy adjudicative standing "
            "rather than resting on the operator's word."),

    Setting("XCP_PROFILE", R.GATEWAY, "development",
            "development | production. The production profile refuses to start "
            "unless enforce posture, an external verifier, hardening, rate "
            "limiting, an admin token and secure peering are all in place — a "
            "profile that is claimed and not enforced is worse than one never "
            "claimed."),
    Setting("XCP_MAX_UPSTREAM_CREDENTIAL", R.GATEWAY, "8192",
            "Maximum bytes the gateway will relay in XCP-Upstream-Credential. "
            "The value is never read, logged or stored; this bounds what the "
            "pass-through will carry."),

    # ── abuse controls ──
    Setting("XCP_RATE_LIMIT", R.GATEWAY, "1",
            "Abuse controls. Setting 0 on a node reachable by strangers makes "
            "it an open relay.", unsafe=True),
    Setting("XCP_GLOBAL_RATE", R.GATEWAY, "120000",
            "Node-wide cost units per minute, independent of any caller's tier."),
    Setting("XCP_GLOBAL_CONCURRENCY", R.GATEWAY, "256",
            "Node-wide in-flight request cap."),
    Setting("XCP_LIMIT_FAIL_OPEN", R.GATEWAY, "0",
            "Serve traffic if the limiter itself fails. Turns any limiter bug "
            "into an abuse bypass; only for private deployments behind another "
            "limiter.", unsafe=True),
    # ── server ──
    Setting("REQUIRE_VERIFIED", R.SERVER, "1",
            "Refuse calls that did not arrive through a gateway. Setting 0 lets "
            "anyone reach the tools directly, bypassing every control.",
            unsafe=True),
    Setting("XCP_SERVER_NAME", R.SERVER, "research",
            "Name this server answers to in XCP_UPSTREAMS."),
    # ── verifier / chain ──
    Setting("CHAIN_RPC", R.VERIFIER, "",
            "EVM RPC endpoint. Unset means in-memory verification."),
    Setting("CHAIN_ID", R.VERIFIER, "8453",
            "Chain id bound into EIP-712 domains. A signature is only valid for "
            "the chain it was signed against, so a mismatch here rejects every "
            "mandate with an unhelpful error."),
    Setting("SESSION_REGISTRY", R.VERIFIER, "",
            "Deployed SessionRegistry address. Required with CHAIN_RPC."),
    Setting("SESSION_REGISTRY_ABI", R.VERIFIER, "",
            "Path to an ABI override. Defaults to the generated artifact."),
    # ── node identity / federation ──
    Setting("XCP_NODE_KEY", R.NODE, "",
            "Long-lived node identity key. LOSING THIS IS UNRECOVERABLE: the "
            "node loses its identity and every attestation any peer made about "
            "it. Back it up offline before first use.", secret=True),
    Setting("XCP_NODE_DOMAIN", R.NODE, "",
            "Domain this node claims. Must match where the record is served."),
    Setting("XCP_NODE_URL", R.NODE, "",
            "Public gateway URL published to peers."),
    Setting("XCP_NODE_CERT_FOOTPRINT", R.NODE, "",
            "keccak256(DER(cert)) of the certificate currently served. "
            "scripts/rotate-cert.py maintains this."),
    Setting("XCP_NODE_OPERATOR", R.NODE, "anonymous",
            "Operator name published in the node record."),
    # ── wrappers ──
    Setting("XCP_SEAL_PRIVATE", R.WRAPPER, "",
            "X25519 private key for sealed credentials. Without it a sealed "
            "wrapper refuses to start, because regenerating silently "
            "invalidates every credential already sealed to it.", secret=True),
    Setting("XCP_SEAL_PREVIOUS", R.WRAPPER, "",
            "Comma-separated previous sealing keys, accepted during a rotation "
            "so in-flight requests do not break.", secret=True),
    Setting("XCP_SEAL_EPHEMERAL", R.WRAPPER, "0",
            "Accept a throwaway sealing key. Every restart invalidates every "
            "sealed credential; local testing only.", unsafe=True),
    Setting("UPSTREAM_CREDENTIAL", R.WRAPPER, "",
            "Fallback upstream credential when no vault backend is configured. "
            "Prefer a vault:// reference.", secret=True),
    # ── telemetry ──
    Setting("XCP_OTEL", R.TELEMETRY, "0",
            "Enable OpenTelemetry. Off by default; without it every "
            "instrumentation call is a no-op and the node behaves identically, "
            "so enabling it is a deliberate act rather than a default."),
    Setting("XCP_OTEL_DETAIL", R.TELEMETRY, "scrubbed",
            "scrubbed | hosts | full. `full` exports raw agent ids, scopes and "
            "hostnames — self-hosted collectors only. Sending it to a vendor is "
            "a new processor and usually an international transfer.",
            unsafe=True),
    Setting("OTEL_EXPORTER_OTLP_ENDPOINT", R.TELEMETRY, "",
            "Collector endpoint. Enabled with no endpoint sends spans to the "
            "console, which is work nobody collects."),
    Setting("OTEL_SERVICE_NAME", R.TELEMETRY, "xcp-gateway",
            "Service name on exported telemetry."),
    Setting("XCP_SECRET_*", R.GATEWAY, "",
            "Prefix for the env secret backend, e.g. "
            "XCP_SECRET_CONNECTORS_GITHUB_CLIENT_ID. Development only.",
            secret=True),
    # ── tooling ──
    Setting("GH_TOKEN", R.TOOLING, "",
            "GitHub token for catalog harvesting and contract artifacts. Never "
            "needed by a running node.", secret=True),
    Setting("GITHUB_TOKEN", R.TOOLING, "",
            "Alias for GH_TOKEN, checked second. Present because CI runners set "
            "this name by convention; a running node never needs either.",
            secret=True),
    Setting("SOLC", R.TOOLING, "", "Path to solc for contract compilation."),
    Setting("RPC_URL", R.TOOLING, "", "RPC endpoint for contract deployment."),
    Setting("DEPLOYER_KEY", R.TOOLING, "",
            "Deployment key. Read from the environment and never written "
            "anywhere.", secret=True),
    Setting("NO_COLOR", R.TOOLING, "",
            "Disable ANSI colour in CLI output. Honours the no-color.org "
            "convention, so setting it to any value suppresses escape codes — "
            "useful when piping triage output into an incident ticket."),
)

_BY_NAME = {s.name: s for s in SETTINGS}


def get(name: str) -> Optional[Setting]:
    if name in _BY_NAME:
        return _BY_NAME[name]
    for s in SETTINGS:                      # prefix forms like XCP_SECRET_*
        if s.name.endswith("*") and name.startswith(s.name[:-1]):
            return s
    return None


def for_role(role: Role) -> list[Setting]:
    return [s for s in SETTINGS if s.role is role]


def unsafe() -> list[Setting]:
    return [s for s in SETTINGS if s.unsafe]


def secrets() -> list[Setting]:
    return [s for s in SETTINGS if s.secret]


def table(role: Optional[Role] = None, only_unsafe: bool = False) -> str:
    items = for_role(role) if role else list(SETTINGS)
    if only_unsafe:
        items = [s for s in items if s.unsafe]
    lines = [f"  {'setting':<32}{'role':<11}{'default':<14}"]
    for s in items:
        mark = "!" if s.unsafe else ("#" if s.secret else " ")
        lines.append(f" {mark}{s.name:<32}{s.role.value:<11}"
                     f"{(s.default or '—'):<14}{s.description[:58]}")
    lines.append("\n  ! weakens a control    # secret, never commit")
    return "\n".join(lines)


__all__ = ["Setting", "Role", "SETTINGS", "get", "for_role", "unsafe",
           "secrets", "table"]
