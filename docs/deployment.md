# Deployment

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
