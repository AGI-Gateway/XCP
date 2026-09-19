# Deployment

## Container image

One image, three roles. Three separate images drifted once — the gateway build
shipped without the modules the gateway had grown to import, so abuse controls
and the argument firewall were silently absent in the only artifact anyone would
actually deploy. One image with a role selector cannot drift that way.

```bash
docker run -e ROLE=gateway  -p 8080:8080 ghcr.io/agi-gateway/xcp
docker run -e ROLE=server   -p 9001:9001 ghcr.io/agi-gateway/xcp
docker run -e ROLE=verifier -p 8500:8500 ghcr.io/agi-gateway/xcp
```

Images are multi-arch, run as UID 10001, carry an SBOM and build provenance, and
are **signed with cosign** using keyless OIDC:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/AGI-Gateway/XCP/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/agi-gateway/xcp@sha256:<digest>
```

Signing is not decoration here: this codebase refuses to load a connector whose
manifest is unsigned, so publishing unsigned images would be indefensible.

!!! tip "Pin the digest"
    A tag is mutable; a digest is not. Set `image.digest` in Helm for anything
    you care about — this chart deploys the component that polices everyone
    else's supply chain.

### The gateway refuses to start without its controls

If `XCP_RATE_LIMIT=1` (the default) and the limiter cannot load, the gateway
**fails to boot** rather than silently routing for strangers with no limits. Set
`XCP_RATE_LIMIT=0` to run unprotected deliberately. The release pipeline asserts
this: a build where the gateway starts without abuse controls is not published.

## Docker Compose

```bash
cd deploy && docker compose up --build
# gateway :8080 · verifier :8500 · server :9001
```

## Kubernetes (Helm)

```bash
helm install xcp ./deploy/helm \
  --set gateway.posture=enforce \
  --set gateway.security=1 \
  --set verifier.chainRpc=https://mainnet.base.org \
  --set verifier.sessionRegistry=0xYourRegistry
```

Defaults are safe-by-default: `enforce` posture, non-root, read-only root
filesystem, all capabilities dropped, `RuntimeDefault` seccomp.

### Because MCP is stateless

Since MCP 2026-07-28 removed protocol sessions, **no sticky sessions or shared
session store are required**. Scale the gateway horizontally behind a plain
round-robin load balancer; any instance can serve any request. The XCP request
credential is self-verifying, so gateway replicas need no shared state either.

## Certificates

```bash
./xcp certs --agent-id 42001     # local dev PKI — NEVER production
```

For production, issue from your own CA and mount as a secret
(`mtls.secretName`). The certificate footprint `keccak256(DER(cert))` is what
binds a credential to a caller.

!!! warning "TLS termination"
    If TLS terminates at an edge or load balancer, the MCP server behind it
    never sees the client certificate. That is why the **gateway** is the trust
    boundary: it terminates mTLS, computes the footprint, and forwards a
    verified identity downstream. Don't expect end-to-end mTLS to a serverless
    MCP server.

## Hardening checklist

- Run `enforce`. `observe` is for onboarding an endpoint you haven't vetted.
- `XCP_SECURITY=1` enables the argument firewall.
- Use `xcpsec.sandbox` for any tool that executes untrusted input.
- Keep credential TTLs in seconds; the firewall caps them at 300s.
- Serve `/.well-known/*` unauthenticated (RFC 8615); gate everything else.
- Watch `mandate_denials_total` and `session_verifications_total{result}`.
