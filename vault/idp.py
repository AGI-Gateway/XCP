"""
vault.idp — identity providers, public and private.

An XCP session carries two identities: the **agent** and the **human** whose
authority it acts under. This module covers the second one. Which provider
authenticated the human determines their tier in the trust lattice, and therefore
what the agent is allowed to do and spend:

    no login                        → H0 PUBLIC        no principal, no settlement
    consumer SSO (Google/MS/Meta)   → H1 GENERAL_SSO   a verified individual
    enterprise IdP + entitlements   → H2 ENTERPRISE    delegated corporate authority

That last step is the one that matters commercially: an enterprise IdP asserts
not just *who* someone is but what they are **entitled** to — group membership,
cost centre, approval limit. Those attributes flow into the mandate and can only
ever narrow it (see `trust.tiers.Entitlements`).

NO CREDENTIALS HERE
-------------------
Every provider below declares endpoints, scopes and claim mappings. Client
secrets are `SecretRef` pointers resolved at runtime from your secret backend.
Nothing in this file, or anywhere in this repository, holds a credential.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .refs import SecretRef, Backend, VaultError


class AuthMethod(str, Enum):
    """How a party proves identity. See vault/README.md for the full matrix."""
    OIDC = "oidc"                       # OpenID Connect (OAuth 2.0 + identity)
    OAUTH2_AUTH_CODE = "oauth2_auth_code"       # + PKCE, for user-present flows
    OAUTH2_CLIENT_CREDS = "oauth2_client_creds" # service-to-service
    OAUTH2_DEVICE = "oauth2_device"     # input-constrained devices
    SAML2 = "saml2"                     # enterprise federation
    LDAP = "ldap"                       # directory bind (on-prem AD)
    JWT_BEARER = "jwt_bearer"           # RFC 7523 assertion
    MTLS = "mtls"                       # XCP's native channel binding
    API_KEY = "api_key"                 # legacy; discouraged
    HMAC = "hmac"                       # signed request digests
    SCIM = "scim"                       # provisioning, not authentication


class ProviderKind(str, Enum):
    PUBLIC = "public"       # consumer identity — anyone can sign up
    PRIVATE = "private"     # an organisation's own directory


@dataclass
class IdentityProvider:
    """
    A declarative IdP definition. Endpoints and claim mappings live here; secrets
    are references.
    """
    id: str
    name: str
    kind: ProviderKind
    methods: list[AuthMethod] = field(default_factory=list)
    issuer: str = ""                        # OIDC issuer, for RFC 9207 checks
    discovery_url: str = ""                 # /.well-known/openid-configuration
    authorize_url: str = ""
    token_url: str = ""
    jwks_url: str = ""
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    # secrets, by reference only
    client_id_ref: Optional[SecretRef] = None
    client_secret_ref: Optional[SecretRef] = None
    # claim → meaning
    subject_claim: str = "sub"
    email_claim: str = "email"
    groups_claim: str = ""                  # enterprise: group membership
    # entitlement attributes an enterprise IdP may assert
    entitlement_claims: dict[str, str] = field(default_factory=dict)
    supports_entitlements: bool = False
    supports_scim: bool = False
    notes: str = ""

    # ---- tier mapping: the point of this whole module ----
    def human_tier(self) -> int:
        """
        Which trust-lattice human tier this provider can establish.

        A private IdP only reaches H2 if it actually asserts entitlements. A
        directory that proves identity but says nothing about authority gives you
        H1 — knowing *who* someone is does not tell you what they may spend.
        """
        if self.kind == ProviderKind.PRIVATE and self.supports_entitlements:
            return 2                                   # H2 ENTERPRISE
        return 1                                       # H1 GENERAL_SSO

    def validate(self) -> list[str]:
        p: list[str] = []
        if not self.id or " " in self.id:
            p.append("id must be non-empty with no spaces")
        if not self.methods:
            p.append("at least one auth method is required")
        for url in (self.discovery_url, self.authorize_url, self.token_url,
                    self.jwks_url):
            if url and not url.startswith("https://"):
                p.append(f"{url} must be https")
        if AuthMethod.OIDC in self.methods and not (self.discovery_url or self.issuer):
            p.append("OIDC providers need an issuer or a discovery URL")
        if self.supports_entitlements and not (self.groups_claim
                                               or self.entitlement_claims):
            p.append("supports_entitlements is set but no claims are mapped")
        if self.kind == ProviderKind.PUBLIC and self.supports_entitlements:
            p.append("a consumer provider cannot assert organisational entitlements")
        return p

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "kind": self.kind.value,
            "methods": [m.value for m in self.methods],
            "issuer": self.issuer, "scopes": list(self.scopes),
            "humanTier": f"H{self.human_tier()}",
            "supportsEntitlements": self.supports_entitlements,
            "supportsScim": self.supports_scim,
            "clientIdRef": self.client_id_ref.uri if self.client_id_ref else None,
            "clientSecretRef": self.client_secret_ref.uri if self.client_secret_ref else None,
            "notes": self.notes,
        }


def _ref(provider: str, key: str) -> SecretRef:
    return SecretRef(backend=Backend.ENV, path=f"idp/{provider}", key=key,
                     description=f"{provider} {key}")


# ── public providers: consumer identity → H1 ───────────────────────────────

PUBLIC_PROVIDERS: dict[str, IdentityProvider] = {
    "google": IdentityProvider(
        id="google", name="Google", kind=ProviderKind.PUBLIC,
        methods=[AuthMethod.OIDC, AuthMethod.OAUTH2_AUTH_CODE, AuthMethod.OAUTH2_DEVICE],
        issuer="https://accounts.google.com",
        discovery_url="https://accounts.google.com/.well-known/openid-configuration",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        jwks_url="https://www.googleapis.com/oauth2/v3/certs",
        client_id_ref=_ref("google", "client_id"),
        client_secret_ref=_ref("google", "client_secret"),
        notes="Use PKCE. Google Workspace tenants can assert `hd` (hosted domain) "
              "but that is a tenancy hint, not an entitlement."),
    "microsoft": IdentityProvider(
        id="microsoft", name="Microsoft Account", kind=ProviderKind.PUBLIC,
        methods=[AuthMethod.OIDC, AuthMethod.OAUTH2_AUTH_CODE, AuthMethod.OAUTH2_DEVICE],
        issuer="https://login.microsoftonline.com/consumers/v2.0",
        discovery_url="https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration",
        authorize_url="https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
        token_url="https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        client_id_ref=_ref("microsoft", "client_id"),
        client_secret_ref=_ref("microsoft", "client_secret"),
        notes="Consumer MSA. For organisational identity use the entra-id "
              "provider instead — different issuer, different guarantees."),
    "meta": IdentityProvider(
        id="meta", name="Meta Account", kind=ProviderKind.PUBLIC,
        methods=[AuthMethod.OIDC, AuthMethod.OAUTH2_AUTH_CODE],
        issuer="https://www.facebook.com",
        authorize_url="https://www.facebook.com/v19.0/dialog/oauth",
        token_url="https://graph.facebook.com/v19.0/oauth/access_token",
        jwks_url="https://www.facebook.com/.well-known/oauth/openid/jwks/",
        client_id_ref=_ref("meta", "client_id"),
        client_secret_ref=_ref("meta", "client_secret"),
        notes="Limited OIDC support; email is not guaranteed to be present or "
              "verified. Treat as a weak H1."),
    "apple": IdentityProvider(
        id="apple", name="Sign in with Apple", kind=ProviderKind.PUBLIC,
        methods=[AuthMethod.OIDC, AuthMethod.OAUTH2_AUTH_CODE, AuthMethod.JWT_BEARER],
        issuer="https://appleid.apple.com",
        discovery_url="https://appleid.apple.com/.well-known/openid-configuration",
        token_url="https://appleid.apple.com/auth/token",
        jwks_url="https://appleid.apple.com/auth/keys",
        client_id_ref=_ref("apple", "client_id"),
        client_secret_ref=_ref("apple", "client_secret"),
        notes="Client secret is a short-lived ES256 JWT you mint, not a static "
              "string. Private relay emails are common."),
    "github": IdentityProvider(
        id="github", name="GitHub", kind=ProviderKind.PUBLIC,
        methods=[AuthMethod.OAUTH2_AUTH_CODE, AuthMethod.OAUTH2_DEVICE],
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        client_id_ref=_ref("github", "client_id"),
        client_secret_ref=_ref("github", "client_secret"),
        scopes=["read:user", "user:email"],
        notes="OAuth 2.0 only — not an OIDC provider. No id_token; identity comes "
              "from an API call."),
}


# ── private providers: organisational identity → H2 when entitlements flow ──

_ENT = {"department": "department", "costCenter": "cost_center",
        "approvalLimit": "approval_limit", "employeeId": "employee_id"}

PRIVATE_PROVIDERS: dict[str, IdentityProvider] = {
    "entra-id": IdentityProvider(
        id="entra-id", name="Microsoft Entra ID", kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.OIDC, AuthMethod.SAML2, AuthMethod.OAUTH2_AUTH_CODE,
                 AuthMethod.OAUTH2_CLIENT_CREDS, AuthMethod.SCIM],
        issuer="https://login.microsoftonline.com/{tenant}/v2.0",
        discovery_url="https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
        authorize_url="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        token_url="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        groups_claim="groups", entitlement_claims=dict(_ENT),
        supports_entitlements=True, supports_scim=True,
        client_id_ref=_ref("entra-id", "client_id"),
        client_secret_ref=_ref("entra-id", "client_secret"),
        notes="Replace {tenant} with your tenant id. Prefer group claims over "
              "roles when you need fine-grained entitlements; watch the groups "
              "overage claim on large directories."),
    "okta": IdentityProvider(
        id="okta", name="Okta", kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.OIDC, AuthMethod.SAML2, AuthMethod.OAUTH2_AUTH_CODE,
                 AuthMethod.OAUTH2_CLIENT_CREDS, AuthMethod.SCIM],
        issuer="https://{org}.okta.com/oauth2/default",
        discovery_url="https://{org}.okta.com/oauth2/default/.well-known/openid-configuration",
        groups_claim="groups", entitlement_claims=dict(_ENT),
        supports_entitlements=True, supports_scim=True,
        client_id_ref=_ref("okta", "client_id"),
        client_secret_ref=_ref("okta", "client_secret"),
        notes="Configure a custom authorization server so entitlement claims are "
              "actually emitted in the access token."),
    "active-directory": IdentityProvider(
        id="active-directory", name="Active Directory (on-premises)",
        kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.LDAP, AuthMethod.SAML2],
        groups_claim="memberOf", entitlement_claims=dict(_ENT),
        supports_entitlements=True,
        client_id_ref=_ref("active-directory", "bind_dn"),
        client_secret_ref=_ref("active-directory", "bind_password"),
        notes="LDAP bind against a domain controller, or ADFS for SAML. Always "
              "LDAPS — a plaintext bind sends the password in the clear."),
    "auth0": IdentityProvider(
        id="auth0", name="Auth0", kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.OIDC, AuthMethod.OAUTH2_AUTH_CODE,
                 AuthMethod.OAUTH2_CLIENT_CREDS, AuthMethod.SAML2],
        issuer="https://{domain}/",
        discovery_url="https://{domain}/.well-known/openid-configuration",
        groups_claim="https://xcp/groups", entitlement_claims=dict(_ENT),
        supports_entitlements=True, supports_scim=True,
        client_id_ref=_ref("auth0", "client_id"),
        client_secret_ref=_ref("auth0", "client_secret"),
        notes="Custom claims must be namespaced with a URI or Auth0 strips them."),
    "keycloak": IdentityProvider(
        id="keycloak", name="Keycloak (self-hosted)", kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.OIDC, AuthMethod.SAML2, AuthMethod.OAUTH2_AUTH_CODE,
                 AuthMethod.OAUTH2_CLIENT_CREDS],
        issuer="https://{host}/realms/{realm}",
        discovery_url="https://{host}/realms/{realm}/.well-known/openid-configuration",
        groups_claim="groups", entitlement_claims=dict(_ENT),
        supports_entitlements=True, supports_scim=True,
        client_id_ref=_ref("keycloak", "client_id"),
        client_secret_ref=_ref("keycloak", "client_secret"),
        notes="Fully self-hostable, so an organisation can reach H2 without "
              "depending on any external identity vendor."),
    "ping": IdentityProvider(
        id="ping", name="Ping Identity", kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.OIDC, AuthMethod.SAML2, AuthMethod.OAUTH2_AUTH_CODE],
        issuer="https://auth.pingone.com/{env}/as",
        groups_claim="group", entitlement_claims=dict(_ENT),
        supports_entitlements=True, supports_scim=True,
        client_id_ref=_ref("ping", "client_id"),
        client_secret_ref=_ref("ping", "client_secret")),
    "onelogin": IdentityProvider(
        id="onelogin", name="OneLogin", kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.OIDC, AuthMethod.SAML2, AuthMethod.OAUTH2_AUTH_CODE],
        issuer="https://{subdomain}.onelogin.com/oidc/2",
        groups_claim="groups", entitlement_claims=dict(_ENT),
        supports_entitlements=True, supports_scim=True,
        client_id_ref=_ref("onelogin", "client_id"),
        client_secret_ref=_ref("onelogin", "client_secret")),
    "jumpcloud": IdentityProvider(
        id="jumpcloud", name="JumpCloud", kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.OIDC, AuthMethod.SAML2, AuthMethod.LDAP],
        issuer="https://oauth.id.jumpcloud.com/",
        groups_claim="groups", entitlement_claims=dict(_ENT),
        supports_entitlements=True, supports_scim=True,
        client_id_ref=_ref("jumpcloud", "client_id"),
        client_secret_ref=_ref("jumpcloud", "client_secret")),
    "generic-oidc": IdentityProvider(
        id="generic-oidc", name="Any OIDC provider (template)",
        kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.OIDC, AuthMethod.OAUTH2_AUTH_CODE],
        issuer="https://{issuer-host}/",
        discovery_url="https://{issuer-host}/.well-known/openid-configuration",
        groups_claim="groups", entitlement_claims=dict(_ENT),
        supports_entitlements=True,
        client_id_ref=_ref("generic-oidc", "client_id"),
        client_secret_ref=_ref("generic-oidc", "client_secret"),
        notes="Copy this for any provider not listed. If it speaks OIDC and can "
              "emit group or entitlement claims, it reaches H2."),
    "generic-saml": IdentityProvider(
        id="generic-saml", name="Any SAML 2.0 provider (template)",
        kind=ProviderKind.PRIVATE,
        methods=[AuthMethod.SAML2],
        groups_claim="Groups", entitlement_claims=dict(_ENT),
        supports_entitlements=True,
        client_secret_ref=_ref("generic-saml", "sp_private_key"),
        notes="Assertion signing is mandatory; assertion encryption is strongly "
              "recommended. Validate Conditions/NotOnOrAfter and Audience."),
}


# ── registry ───────────────────────────────────────────────────────────────

_REGISTERED: dict[str, IdentityProvider] = {}


class IdPError(Exception):
    pass


def register_provider(p: IdentityProvider, *, replace: bool = False) -> IdentityProvider:
    problems = p.validate()
    if problems:
        raise IdPError(f"invalid provider '{p.id}': {'; '.join(problems)}")
    if p.id in _REGISTERED and not replace:
        raise IdPError(f"provider '{p.id}' already registered")
    _REGISTERED[p.id] = p
    return p


def load_builtin() -> int:
    for p in list(PUBLIC_PROVIDERS.values()) + list(PRIVATE_PROVIDERS.values()):
        _REGISTERED.setdefault(p.id, p)
    return len(_REGISTERED)


def providers(kind: Optional[ProviderKind] = None) -> list[IdentityProvider]:
    out = sorted(_REGISTERED.values(), key=lambda p: (p.kind.value, p.id))
    return [p for p in out if kind is None or p.kind == kind]


def get_provider(pid: str) -> Optional[IdentityProvider]:
    return _REGISTERED.get(pid)


def reset() -> None:
    _REGISTERED.clear()


def entitlements_from_claims(provider: IdentityProvider,
                             claims: dict[str, Any]) -> Any:
    """
    Translate IdP claims into a `trust.tiers.Entitlements`, which can only ever
    narrow the mandate the tier already allows.
    """
    from trust.tiers import Entitlements
    groups = claims.get(provider.groups_claim, []) if provider.groups_claim else []
    if isinstance(groups, str):
        groups = [groups]
    limit = None
    lim_claim = provider.entitlement_claims.get("approvalLimit")
    if lim_claim and lim_claim in claims:
        try:
            limit = int(claims[lim_claim])
        except (TypeError, ValueError):
            limit = None
    cc_claim = provider.entitlement_claims.get("costCenter", "")
    return Entitlements(groups=list(groups),
                        cost_center=str(claims.get(cc_claim, "")) if cc_claim else "",
                        approval_limit_minor=limit)


__all__ = [
    "IdentityProvider", "AuthMethod", "ProviderKind", "IdPError",
    "PUBLIC_PROVIDERS", "PRIVATE_PROVIDERS",
    "register_provider", "load_builtin", "providers", "get_provider", "reset",
    "entitlements_from_claims",
]
