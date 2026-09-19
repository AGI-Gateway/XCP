# Vault — credential references and identity providers

**This directory stores pointers to secrets. It never stores secrets.**

A `SecretRef` is an address:

```
vault://hashicorp/xcp/connectors/github#oauth_client_secret
└─────┘  └────────┘ └──────────────────┘ └────────────────┘
 scheme   backend         path                  key
```

It says *where* a credential lives and *who* may read it. It does not contain the
credential, cannot be resolved without a configured backend, and refuses to
serialise a resolved value back out.

!!! danger "Why it is built this way"
    A "folder for credentials" in a git repository — especially a public one — is
    how secrets leak. They get committed once, and then they live in the history
    forever, even after the file is deleted. So this is an **indirection layer
    over real secret managers**, not a place anything secret is written.

## Enforced, not just documented

| Control | Where |
|---|---|
| `SecretRef` has **no value field** — nowhere to put a secret | `refs.py` |
| `SecretRef` **rejects** a path that looks like a literal credential | `refs.py` |
| `Secret` refuses `repr`, `str`, `format`, JSON and iteration | `refs.py` |
| Catalog entries must use `vault://` references; literals fail to load | `connectors/loader.py` |
| **Repo-wide credential scan fails the build** | `tests/test_vault.py` |
| No `.key` / `.pem` / `.p12` / `.pfx` may be tracked | `tests/test_vault.py` |

Getting a secret out is deliberately verbose and greppable:

```python
secret.reveal()      # explicit. Anything less explicit is refused.
```

## Backends

XCP is **never the system of record** for your credentials. A trust layer that
also custodies every organisation's secrets is a far more attractive target than
one that does not.

| Backend | `vault://` | Production | Notes |
|---|---|---|---|
| Environment | `vault://env/...` | ✗ dev only | Prefixed `XCP_SECRET_` |
| File | `vault://file/...` | ✗ dev only | Absolute path **outside** the repo |
| HashiCorp Vault | `vault://hashicorp/...` | ✓ | KV v2 |
| AWS Secrets Manager | `vault://aws/...` | ✓ | |
| Azure Key Vault | `vault://azure/...` | ✓ | |
| GCP Secret Manager | `vault://gcp/...` | ✓ | |
| Kubernetes Secrets | `vault://k8s/...` | ✓ | Enable encryption at rest |
| 1Password Connect | `vault://1password/...` | ✓ | |
| Custom | `vault://custom/...` | ✓ | Register your own resolver |

`env` and `file` are implemented here because they need no third-party SDK. The
managed backends are wired in by the operator, so XCP does not carry an SDK
dependency for every cloud:

```python
from vault import Vault, VaultConfig, Backend, SecretRef

vault = Vault(VaultConfig(hashicorp_addr="https://vault.internal:8200"))
vault.register_resolver(Backend.HASHICORP, my_hashicorp_read)   # fn(path, key) -> str

secret = vault.resolve(SecretRef.parse("vault://hashicorp/xcp/connectors/github#token"))
headers = {"Authorization": f"Bearer {secret.reveal()}"}
```

`require_production_backend()` refuses `env` and `file` where real credentials
belong.

---

## Authentication methods

Everything XCP understands, what it is for, and what to watch.

| Method | Identifier | Use it for | Watch out for |
|---|---|---|---|
| **OpenID Connect** | `oidc` | Human sign-in with an identity claim | Validate `iss`, `aud`, `exp`, `nonce`. Verify against JWKS, never a pinned key |
| **OAuth 2.0 authorization code** | `oauth2_auth_code` | User-present delegated access | **PKCE is mandatory.** Exact redirect-URI matching |
| **OAuth 2.0 client credentials** | `oauth2_client_creds` | Service-to-service, no user | The secret is a bearer token — rotate it, scope it |
| **OAuth 2.0 device code** | `oauth2_device` | CLIs, TVs, input-constrained devices | Poll interval and expiry; phishable if the code is shared |
| **SAML 2.0** | `saml2` | Enterprise federation | Signature validation, `Conditions/NotOnOrAfter`, `Audience`. Encrypt assertions |
| **LDAP bind** | `ldap` | On-premises Active Directory | **LDAPS only** — a plaintext bind sends the password in the clear |
| **JWT bearer (RFC 7523)** | `jwt_bearer` | Signed assertion, no user interaction | The signing key is high-value; managed backend only |
| **mTLS** | `mtls` | XCP's native channel binding | The certificate footprint *is* the identity |
| **API key** | `api_key` | Legacy services | No expiry, no audience, no proof of possession. **Discouraged** |
| **HMAC signature** | `hmac` | Webhook and request verification | Include a timestamp and reject anything stale, or it replays |
| **SCIM** | `scim` | Provisioning and de-provisioning | Not authentication — it keeps entitlements current |

### What MCP 2026-07-28 tightened

- **Dynamic Client Registration is deprecated** (removal after summer 2027).
  Pre-register clients.
- **RFC 9207 issuer identification** — the authorization response carries `iss`,
  so a client can tell which server answered. Check it.
- **RFC 8707 resource indicators** — a token is minted for a specific resource
  and is useless elsewhere. Catalog entries carry `resource_indicator` for this.
- **Enterprise Managed Auth** — an IdP-based org-wide provisioning extension,
  which is a natural source for the `H2` entitlement attributes below.

### How this stacks with XCP

OAuth answers *"is this token valid for this server?"*. XCP answers *"which
agent, under whose authority, for what scope, with what spend cap?"* They are
complementary layers, not alternatives — an OAuth token gets you to the endpoint;
the XCP credential decides what you may do once there.

---

## Identity providers

Which provider authenticated the human determines their **human tier** in the
[trust lattice](../docs/trust-lattice.md), and therefore what the agent may do
and spend.

| | Tier | Meaning |
|---|---|---|
| No login | `H0` | No principal — nothing to bill or hold liable |
| Consumer SSO | `H1` | A verified individual |
| Enterprise IdP **with entitlements** | `H2` | Delegated corporate authority |

### Public providers → H1

`google` · `microsoft` · `meta` · `apple` · `github`

Each declares its issuer, endpoints, scopes and claim mappings. Notes worth
reading before you wire one up:

- **Google** — use PKCE. Workspace tenants emit `hd`, which is a tenancy hint,
  not an entitlement.
- **Microsoft Account** — consumer MSA. For organisational identity use
  `entra-id` instead; different issuer, different guarantees.
- **Meta** — limited OIDC support; email is not guaranteed present or verified.
  Treat as a weak `H1`.
- **Apple** — the client secret is a short-lived ES256 JWT you mint, not a static
  string. Private relay emails are common.
- **GitHub** — OAuth 2.0 only, **not** an OIDC provider. No `id_token`.

### Private providers → H2 when entitlements flow

`entra-id` · `okta` · `active-directory` · `auth0` · `keycloak` · `ping` ·
`onelogin` · `jumpcloud` · `generic-oidc` · `generic-saml`

!!! important "Identity is not authority"
    A directory that proves *who* someone is but asserts nothing about what they
    may do gives you `H1`, not `H2`. `human_tier()` returns 2 only when
    `supports_entitlements` is set **and** claims are actually mapped. Knowing
    someone's name does not tell you their spending limit.

`keycloak` is fully self-hostable, so an organisation can reach `H2` without
depending on any external identity vendor.

### Entitlements narrow, never widen

```python
from vault import get_provider, entitlements_from_claims
from trust.tiers import AgentTier, HumanTier, resolve

ent = entitlements_from_claims(get_provider("okta"), id_token_claims)
tpl = resolve(AgentTier.COMPANY, HumanTier.ENTERPRISE, ent)
tpl.spend_cap_minor      # narrowed by the IdP's approval_limit claim
```

An entitlement can only restrict the envelope the tier already allows. It can
never grant a scope the tier lacks — enforced and tested.

### Adding a provider

Copy `generic-oidc` or `generic-saml`. If it speaks OIDC and can emit group or
entitlement claims, it reaches `H2`. No approval step; validation is the only gate.

---

## Hosting a wrapper for other organisations

If you deploy a [generated wrapper](../connectors/README.md) on someone else's
behalf, the credential question decides whether that is defensible or a liability.

| mode | whose key | who can read it | use when |
|---|---|---|---|
| `operator` | yours, from your vault | you | you self-host an API you already pay for |
| `session` | the caller's, per request | you **and** the gateway operator | both parties already trust the gateway |
| `sealed` | the caller's, encrypted to the wrapper | **only the wrapper** | you host for others |

```
caller --seal(cred, wrapper_pubkey)--> gateway --opaque blob--> wrapper
                                       (cannot open it)         (unseals, uses
                                                                 once, discards)
```

`sealed` is what makes multi-tenant hosting safe: the gateway still verifies the
session, gates the mandate and routes — but the bytes it forwards are ciphertext
it has no key for. That preserves the property the whole system rests on, that
the gateway is a verifier and a router and **never a custodian**.

```bash
xcp wrap stripe --credentials sealed
curl https://your-wrapper/xcp/credential-key     # callers seal to this
```

Construction: ephemeral X25519 per message, HKDF-SHA256, AES-256-GCM. The
recipient key and an operation context are mixed into the AAD, so a blob sealed
for one wrapper cannot be replayed against another, and one sealed for
`tools/call:GetAccount` cannot be reused for `DeleteAccount`.

!!! warning "What this does not protect against"
    It does not protect you from a malicious **wrapper** operator — whoever runs
    the wrapper can read what it unseals, because it has to use the credential
    upstream. The guarantee is narrower and worth stating precisely: **the
    gateway operator is removed from the trust set.** If you do not trust the
    wrapper operator either, run the wrapper yourself — that is what `operator`
    mode is for.

## Provisioning a deployment

List every secret an operator must set before a deployment works:

```python
from connectors import required_secrets
required_secrets()
# {'github': ['vault://env/connectors/github#client_id', ...], ...}
```

Then set them **in your backend**, never in this repository:

```bash
# development
export XCP_SECRET_CONNECTORS_GITHUB_CLIENT_ID=...
export XCP_SECRET_CONNECTORS_GITHUB_CLIENT_SECRET=...

# production — e.g. HashiCorp
vault kv put secret/xcp/connectors/github client_id=... client_secret=...
```

## Operating notes

- Rotate on your normal schedule. Short-lived credentials beat rotation policy.
- Prefer per-user consent to domain-wide delegation; the blast radius differs
  enormously.
- Scope to read-only wherever the task allows.
- Money-moving connectors require `A2xH2` for writes — enforced by a test.
- Never log a `Secret`. The class fights you, but `reveal()` output is yours to
  mishandle.
