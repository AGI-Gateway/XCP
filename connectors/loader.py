"""
connectors.loader — load, validate and register SaaS MCP endpoints.

Each external SaaS gets one declarative file in `connectors/catalog/`. The file
says where the MCP endpoint is, how to authenticate to it, which trust class it
sits in, and which scopes it exposes. It never contains a credential: every
secret is a `vault://` reference resolved at runtime.

The loader enforces that. A catalog entry containing anything that looks like a
live credential fails to load — so the mistake is caught at startup and in CI,
not after it has been committed to a public repository and mirrored forever.

    from connectors import load_catalog, register_all
    entries = load_catalog()                 # validates every file
    register_all(firewall=fw)                # into providers/ + trustfirewall

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

CATALOG_DIR = pathlib.Path(__file__).resolve().parent / "catalog"

VALID_AUTH = {
    "oauth2_auth_code", "oauth2_client_creds", "oauth2_device", "oidc",
    "api_key", "jwt_bearer", "hmac", "mtls", "none",
}
VALID_TRUST = {"unknown", "probed", "attested", "contracted"}
VALID_TRANSPORT = {"streamable_http", "stdio", "websocket", "http_sse"}
VALID_VERIFICATION = {"confirmed", "community", "unconfirmed", "self_hosted"}

# Verification status CAPS the trust class. In a catalog that agents route
# traffic from, an unverified URL is worse than a missing one — so an endpoint
# nobody has confirmed can never be promoted past `unknown`, which the Trust
# Firewall treats as observe-only, sandboxed, and never binding.
MAX_TRUST_FOR_STATUS = {
    "confirmed":   "contracted",   # a verified vendor endpoint may be promoted
    "community":   "probed",       # community-run: probe it, never contract it
    "unconfirmed": "unknown",      # URL unverified: observe only
    "self_hosted": "unknown",      # operator must supply and verify the host
}
_TRUST_ORDER = ["unknown", "probed", "attested", "contracted"]


class CatalogError(Exception):
    pass


@dataclass
class ConnectorEntry:
    """One SaaS MCP endpoint."""
    id: str
    name: str
    endpoint_url: str
    auth_method: str
    trust_class: str = "unknown"
    vendor: str = ""
    homepage: str = ""
    description: str = ""
    transport: str = "streamable_http"
    mcp_spec: str = "2026-07-28"
    scopes: list[str] = field(default_factory=list)
    secret_refs: dict[str, str] = field(default_factory=dict)
    token_url: str = ""
    authorize_url: str = ""
    resource_indicator: str = ""
    refresh: bool = False
    verification_status: str = "unconfirmed"
    verification_source: str = ""
    verification_checked: str = ""
    min_tier: str = "A0xH0"
    min_write_tier: str = "A1xH1"
    scopes_exposed: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    maintainer: str = "anonymous"
    notes: str = ""
    source_file: str = ""
    category: str = "other"

    def validate(self) -> list[str]:
        from vault.refs import scan_for_secrets, SecretRef, VaultError
        p: list[str] = []
        if not self.id or " " in self.id:
            p.append("id must be non-empty with no spaces")
        if not self.endpoint_url.startswith(("https://", "stdio://")):
            p.append("endpoint.url must be https (or stdio for local)")
        if self.auth_method not in VALID_AUTH:
            p.append(f"unknown auth method '{self.auth_method}'")
        if self.trust_class not in VALID_TRUST:
            p.append(f"unknown trust class '{self.trust_class}'")
        if self.transport not in VALID_TRANSPORT:
            p.append(f"unknown transport '{self.transport}'")
        if self.transport == "http_sse":
            p.append("http_sse is deprecated in MCP 2026-07-28")

        # THE important check: no literal credentials, anywhere in the entry.
        for k, v in self.secret_refs.items():
            found = scan_for_secrets(str(v))
            if found:
                p.append(f"secret '{k}' looks like a literal {found[0]} — "
                         "catalog entries hold vault:// references only")
            elif not str(v).startswith("vault://"):
                p.append(f"secret '{k}' must be a vault:// reference, got {v!r}")
            else:
                try:
                    SecretRef.parse(str(v))
                except VaultError as e:
                    p.append(f"secret '{k}': {e}")

        blob = " ".join([self.notes, self.description, self.endpoint_url,
                         self.token_url, self.authorize_url])
        for found in scan_for_secrets(blob):
            p.append(f"entry text contains what looks like a {found}")

        # verification: the rule that makes this catalog safe to route from
        if self.verification_status not in VALID_VERIFICATION:
            p.append(f"unknown verification status '{self.verification_status}'")
        else:
            cap = MAX_TRUST_FOR_STATUS[self.verification_status]
            if (_TRUST_ORDER.index(self.trust_class)
                    > _TRUST_ORDER.index(cap)):
                p.append(
                    f"trust class '{self.trust_class}' exceeds what a "
                    f"'{self.verification_status}' endpoint may claim (max '{cap}') — "
                    "verify the endpoint before promoting it")
            if self.verification_status == "confirmed" and not self.verification_source:
                p.append("a 'confirmed' endpoint must cite a source")
            if self.verification_status == "self_hosted" and "<" not in self.endpoint_url:
                p.append("a 'self_hosted' endpoint should use a <placeholder> host "
                         "so it cannot be routed to by accident")

        # money-moving connectors must not be reachable from a weak tier
        if any(t in ("payments", "financial") for t in self.tags):
            if not self.min_write_tier.startswith("A2"):
                p.append("a payments connector must require A2 for writes")
        return p

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "vendor": self.vendor,
            "endpoint": self.endpoint_url, "transport": self.transport,
            "auth": self.auth_method, "trustClass": self.trust_class,
            "verification": {"status": self.verification_status,
                             "source": self.verification_source,
                             "checked": self.verification_checked},
            "minTier": self.min_tier, "minWriteTier": self.min_write_tier,
            "scopesExposed": list(self.scopes_exposed),
            "secretRefs": dict(self.secret_refs),
            "tags": list(self.tags), "maintainer": self.maintainer,
        }


# ── parsing ────────────────────────────────────────────────────────────────

def _load_yaml(path: pathlib.Path) -> dict:
    try:
        import yaml
    except ImportError:
        raise CatalogError("PyYAML is required to read the connector catalog "
                           "(pip install pyyaml)")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise CatalogError(f"{path.name}: expected a mapping at the top level")
    return data


def parse_entry(data: dict, source: str = "") -> ConnectorEntry:
    ep = data.get("endpoint") or {}
    auth = data.get("auth") or {}
    trust = data.get("trust") or {}
    entry = ConnectorEntry(
        id=str(data.get("id", "")),
        name=str(data.get("name", "")),
        vendor=str(data.get("vendor", "")),
        homepage=str(data.get("homepage", "")),
        description=str(data.get("description", "")),
        endpoint_url=str(ep.get("url", "")),
        transport=str(ep.get("transport", "streamable_http")),
        mcp_spec=str(ep.get("mcp_spec", "2026-07-28")),
        auth_method=str(auth.get("method", "none")),
        scopes=list(auth.get("scopes") or []),
        secret_refs={k: str(v) for k, v in (auth.get("secrets") or {}).items()},
        token_url=str(auth.get("token_url", "")),
        authorize_url=str(auth.get("authorize_url", "")),
        resource_indicator=str(auth.get("resource_indicator", "")),
        refresh=bool(auth.get("refresh", False)),
        verification_status=str((data.get("verification") or {}).get("status", "unconfirmed")),
        verification_source=str((data.get("verification") or {}).get("source", "") or ""),
        verification_checked=str((data.get("verification") or {}).get("checked", "")),
        trust_class=str(trust.get("class", "unknown")),
        min_tier=str(trust.get("min_tier", "A0xH0")),
        min_write_tier=str(trust.get("min_write_tier", "A1xH1")),
        scopes_exposed=list(data.get("scopes_exposed") or []),
        tags=list(data.get("tags") or []),
        maintainer=str(data.get("maintainer", "anonymous")),
        notes=str(data.get("notes", "")),
        source_file=source,
    )
    entry.category = _categorise(entry)
    return entry


def _categorise(entry: "ConnectorEntry") -> str:
    """
    Curated descriptions are generated boilerplate, so classify on the id, the
    vendor name and the hand-written tags — the parts that actually carry signal.
    """
    from .taxonomy import classify
    return classify(f"{entry.id} {entry.name}", "", entry.tags)


def load_catalog(directory: Optional[pathlib.Path] = None,
                 include_template: bool = False) -> list[ConnectorEntry]:
    """Load and validate every catalog file. Raises on the first invalid entry."""
    d = directory or CATALOG_DIR
    if not d.is_dir():
        raise CatalogError(f"no catalog directory at {d}")
    out: list[ConnectorEntry] = []
    for path in sorted(d.glob("*.yaml")):
        if path.name.startswith("_") and not include_template:
            continue
        entry = parse_entry(_load_yaml(path), source=path.name)
        problems = entry.validate()
        if problems:
            raise CatalogError(f"{path.name}: " + "; ".join(problems))
        out.append(entry)
    ids = [e.id for e in out]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise CatalogError(f"duplicate connector ids: {sorted(dupes)}")
    return out


# ── registration into the rest of XCP ──────────────────────────────────────

def register_all(firewall: Any = None,
                 entries: Optional[Iterable[ConnectorEntry]] = None) -> int:
    """
    Push the catalog into `providers/` (so it is discoverable) and, if given,
    into a `TrustFirewall` (so graded reachability applies immediately).
    """
    from providers import MCPConnection, register_connection
    items = list(entries if entries is not None else load_catalog())
    for e in items:
        register_connection(MCPConnection(
            id=e.id, name=e.name, endpoint=e.endpoint_url,
            description=e.description, auth=_auth_label(e.auth_method),
            trust_class=e.trust_class, tags=list(e.tags),
            maintainer=e.maintainer, homepage=e.homepage), replace=True)
    if firewall is not None:
        from providers import apply_to_firewall
        apply_to_firewall(firewall)
    return len(items)


def _auth_label(method: str) -> str:
    if method == "mtls":
        return "xcp-mtls"
    if method == "none":
        return "none"
    return "oauth2" if method.startswith("oauth2") or method == "oidc" else method


def required_secrets(entries: Optional[Iterable[ConnectorEntry]] = None
                     ) -> dict[str, list[str]]:
    """
    Every secret an operator must provision before a deployment will work,
    grouped by connector. Use this to seed a secret backend.
    """
    items = list(entries if entries is not None else load_catalog())
    return {e.id: sorted(e.secret_refs.values()) for e in items if e.secret_refs}


__all__ = ["ConnectorEntry", "load_catalog", "parse_entry", "register_all",
           "required_secrets", "CatalogError", "CATALOG_DIR",
           "VALID_AUTH", "VALID_TRUST", "VALID_TRANSPORT",
           "VALID_VERIFICATION", "MAX_TRUST_FOR_STATUS"]
