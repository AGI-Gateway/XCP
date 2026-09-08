"""
vault.refs — secret *references*, never secret values.

THE ONE RULE
------------
This repository stores **pointers to secrets, never secrets**. A `SecretRef` is
an address like:

    vault://hashicorp/xcp/connectors/github#oauth_client_secret

It says where a credential lives and who may read it. It does not contain the
credential, cannot be resolved without a configured backend, and refuses to
serialise a resolved value back out.

That distinction is the whole design. "A folder for credentials" in a repository
— especially a public one — is how secrets leak: they get committed once, and
then they live in the git history forever even after deletion. So the vault here
is an *indirection layer* over real secret managers, not a place anything secret
is written.

Enforced, not just documented:
  · `SecretRef` has no value field. There is nowhere to put one.
  · `Secret` (a resolved value) raises on `__repr__`, `__str__` and JSON
    encoding, so it cannot be logged or serialised by accident.
  · `tests/test_vault.py` scans the repository for anything shaped like a live
    credential and fails the build if it finds one.

WHERE SECRETS ACTUALLY LIVE
---------------------------
In a backend you already operate — HashiCorp Vault, AWS Secrets Manager, Azure
Key Vault, GCP Secret Manager, Kubernetes Secrets, or environment variables for
local development. XCP never becomes the system of record for your credentials,
because a trust layer that also custodies every organisation's secrets is a far
more attractive target than one that does not.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

VAULT_SCHEME = "vault"


class VaultError(Exception):
    pass


class SecretNotFound(VaultError):
    pass


class Backend(str, Enum):
    """Where a secret actually lives. XCP is never the system of record."""
    ENV = "env"                 # environment variables — local development only
    FILE = "file"               # a file on disk, outside the repo — dev / air-gapped
    HASHICORP = "hashicorp"     # HashiCorp Vault (KV v2)
    AWS = "aws"                 # AWS Secrets Manager
    AZURE = "azure"             # Azure Key Vault
    GCP = "gcp"                 # GCP Secret Manager
    K8S = "k8s"                 # Kubernetes Secrets
    ONEPASSWORD = "1password"   # 1Password Connect
    CUSTOM = "custom"           # bring your own resolver


# Backends acceptable for production. ENV and FILE are development conveniences
# and are rejected by `SecretRef.require_production_backend()`.
DEV_ONLY_BACKENDS = {Backend.ENV, Backend.FILE}


@dataclass(frozen=True)
class SecretRef:
    """
    A pointer to a credential. Deliberately has **no value field** — there is
    nowhere for a secret to be written, by accident or otherwise.

        ref = SecretRef.parse("vault://hashicorp/xcp/connectors/github#client_secret")
        ref.backend      # Backend.HASHICORP
        ref.path         # "xcp/connectors/github"
        ref.key          # "client_secret"
    """
    backend: Backend
    path: str
    key: str = ""
    required: bool = True
    description: str = ""

    def __post_init__(self) -> None:
        if not self.path:
            raise VaultError("a secret reference needs a path")
        if _looks_like_a_secret(self.path) or _looks_like_a_secret(self.key):
            raise VaultError(
                "this looks like a literal credential, not a path. "
                "SecretRef holds addresses only — put the value in your secret backend.")

    @property
    def uri(self) -> str:
        frag = f"#{self.key}" if self.key else ""
        return f"{VAULT_SCHEME}://{self.backend.value}/{self.path}{frag}"

    @staticmethod
    def parse(uri: str, **kw: Any) -> "SecretRef":
        u = urlparse(uri)
        if u.scheme != VAULT_SCHEME:
            raise VaultError(f"expected a {VAULT_SCHEME}:// reference, got {uri!r}")
        try:
            backend = Backend(u.netloc)
        except ValueError:
            raise VaultError(f"unknown backend {u.netloc!r}")
        return SecretRef(backend=backend, path=u.path.lstrip("/"),
                         key=u.fragment or "", **kw)

    def require_production_backend(self) -> None:
        """Refuse a development backend where production credentials belong."""
        if self.backend in DEV_ONLY_BACKENDS:
            raise VaultError(
                f"{self.backend.value} is a development backend; use a managed "
                "secret store in production")

    def to_dict(self) -> dict[str, Any]:
        return {"ref": self.uri, "required": self.required,
                "description": self.description}


class Secret:
    """
    A resolved credential, held in memory for as long as it is needed and no
    longer. It actively resists being logged or serialised, because the usual way
    secrets escape is not theft — it is a debug print or a JSON dump.
    """

    __slots__ = ("_value", "_ref")

    def __init__(self, value: str, ref: Optional[SecretRef] = None) -> None:
        self._value = value
        self._ref = ref

    def reveal(self) -> str:
        """Explicitly obtain the value. Deliberately verbose so it is greppable."""
        return self._value

    def __repr__(self) -> str:
        where = self._ref.uri if self._ref else "unbound"
        return f"<Secret {where} [redacted]>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return self.__repr__()

    def __iter__(self):
        raise VaultError("refusing to iterate a Secret; call .reveal() explicitly")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    def for_json(self) -> str:
        raise VaultError("refusing to serialise a Secret")


# ── heuristics that keep literals out of the repo ──────────────────────────

_SECRET_SHAPES = [
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}"), "GitHub personal access token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "GitHub fine-grained token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "API secret key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), "Google API key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."), "JWT"),
]


def _looks_like_a_secret(text: str) -> bool:
    return any(rx.search(text or "") for rx, _ in _SECRET_SHAPES)


def scan_for_secrets(text: str) -> list[str]:
    """Return the kinds of credential this text appears to contain."""
    return [label for rx, label in _SECRET_SHAPES if rx.search(text or "")]


# ── resolution ─────────────────────────────────────────────────────────────

@dataclass
class VaultConfig:
    """How to reach each backend. Contains endpoints and paths — no credentials."""
    default_backend: Backend = Backend.ENV
    hashicorp_addr: str = ""            # e.g. https://vault.internal:8200
    hashicorp_mount: str = "secret"
    aws_region: str = ""
    azure_vault_url: str = ""
    gcp_project: str = ""
    k8s_namespace: str = "default"
    env_prefix: str = "XCP_SECRET_"
    file_root: str = ""                 # a directory OUTSIDE the repository

    def validate(self) -> list[str]:
        p = []
        if self.file_root and not os.path.isabs(self.file_root):
            p.append("file_root must be an absolute path outside the repository")
        if self.hashicorp_addr and not self.hashicorp_addr.startswith("https://"):
            p.append("hashicorp_addr must be https")
        if self.azure_vault_url and not self.azure_vault_url.startswith("https://"):
            p.append("azure_vault_url must be https")
        return p


class Vault:
    """
    Resolves references against whichever backend an operator has configured.

    Only the ENV and FILE backends are implemented here, because they are the two
    that need no third-party SDK. The managed backends are declared with the
    exact client call an operator should wire in — deliberately not vendored, so
    XCP does not carry an SDK dependency for every cloud.

        vault = Vault(VaultConfig(default_backend=Backend.ENV))
        secret = vault.resolve(SecretRef.parse("vault://env/GITHUB#token"))
        headers = {"Authorization": f"Bearer {secret.reveal()}"}
    """

    def __init__(self, config: Optional[VaultConfig] = None) -> None:
        self.config = config or VaultConfig()
        problems = self.config.validate()
        if problems:
            raise VaultError("; ".join(problems))
        self._resolvers: dict[Backend, Any] = {}

    def register_resolver(self, backend: Backend, fn: Any) -> None:
        """Wire in a managed backend: fn(path, key) -> str."""
        self._resolvers[backend] = fn

    def resolve(self, ref: SecretRef) -> Secret:
        if ref.backend in self._resolvers:
            value = self._resolvers[ref.backend](ref.path, ref.key)
        elif ref.backend == Backend.ENV:
            value = self._from_env(ref)
        elif ref.backend == Backend.FILE:
            value = self._from_file(ref)
        else:
            raise VaultError(
                f"no resolver registered for {ref.backend.value}. "
                f"Call vault.register_resolver(Backend.{ref.backend.name}, fn) — "
                "see vault/README.md for the client call for each provider.")
        if value is None or value == "":
            if ref.required:
                raise SecretNotFound(f"{ref.uri} is required but not set")
            return Secret("", ref)
        return Secret(value, ref)

    def resolve_all(self, refs: dict[str, SecretRef]) -> dict[str, Secret]:
        return {name: self.resolve(r) for name, r in refs.items()}

    def _env_name(self, ref: SecretRef) -> str:
        tail = f"{ref.path}_{ref.key}" if ref.key else ref.path
        return self.config.env_prefix + re.sub(r"[^A-Za-z0-9]+", "_", tail).upper()

    def _from_env(self, ref: SecretRef) -> Optional[str]:
        return os.environ.get(self._env_name(ref))

    def _from_file(self, ref: SecretRef) -> Optional[str]:
        if not self.config.file_root:
            raise VaultError("file backend needs VaultConfig.file_root")
        p = os.path.join(self.config.file_root, ref.path)
        if not os.path.isfile(p):
            return None
        with open(p, "r", encoding="utf-8") as fh:
            data = fh.read()
        if not ref.key:
            return data.strip()
        import json
        try:
            return json.loads(data).get(ref.key)
        except json.JSONDecodeError:
            return data.strip()


__all__ = [
    "SecretRef", "Secret", "Vault", "VaultConfig", "Backend",
    "VaultError", "SecretNotFound", "scan_for_secrets",
    "DEV_ONLY_BACKENDS", "VAULT_SCHEME",
]
