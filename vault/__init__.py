"""
vault — secret references and identity providers.

This package stores POINTERS to credentials, never credentials. See
vault/README.md for the rule and how it is enforced.
"""
from .refs import (SecretRef, Secret, Vault, VaultConfig, Backend,
                   VaultError, SecretNotFound, scan_for_secrets,
                   DEV_ONLY_BACKENDS, VAULT_SCHEME)
from .idp import (IdentityProvider, AuthMethod, ProviderKind, IdPError,
                  PUBLIC_PROVIDERS, PRIVATE_PROVIDERS, register_provider,
                  load_builtin, providers, get_provider, reset,
                  entitlements_from_claims)

__all__ = ["SecretRef", "Secret", "Vault", "VaultConfig", "Backend",
           "VaultError", "SecretNotFound", "scan_for_secrets",
           "DEV_ONLY_BACKENDS", "VAULT_SCHEME",
           "IdentityProvider", "AuthMethod", "ProviderKind", "IdPError",
           "PUBLIC_PROVIDERS", "PRIVATE_PROVIDERS", "register_provider",
           "load_builtin", "providers", "get_provider", "reset",
           "entitlements_from_claims"]
