#!/usr/bin/env bash
# gen-certs.sh — generate a local mTLS PKI for XCP development.
#
# Creates a CA, a gateway server certificate, and a client (agent) certificate.
# The client cert can carry the agent's ERC-8004 id in a custom OID so the
# certificate footprint keccak256(DER(cert)) binds to a specific agent.
#
#   ./gen-certs.sh                 # writes CA, gateway, and one agent cert
#   AGENT_ID=42001 ./gen-certs.sh  # embed a specific agent id
#
# Output (in ./certs):
#   ca.crt ca.key
#   gateway.crt gateway.key
#   agent.crt agent.key
#
# These are for local development only. Use a real CA / cert manager in prod.

set -euo pipefail
cd "$(dirname "$0")/certs" 2>/dev/null || { mkdir -p certs && cd certs; }

AGENT_ID="${AGENT_ID:-42001}"
DAYS=7                                  # short-lived, matching the 7-day cap
GW_CN="${GW_CN:-localhost}"

# custom OID for the agent binding (private enterprise arc, example)
AGENT_OID="1.3.6.1.4.1.99999.1"

echo "▶ generating CA"
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/O=XCP Dev/CN=XCP Dev Root CA" -out ca.crt 2>/dev/null

echo "▶ generating gateway server cert (CN=${GW_CN})"
openssl genrsa -out gateway.key 2048 2>/dev/null
openssl req -new -key gateway.key -subj "/O=XCP Dev/CN=${GW_CN}" \
  -out gateway.csr 2>/dev/null
cat > gateway.ext <<EOF
subjectAltName = DNS:${GW_CN}, DNS:gateway, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
openssl x509 -req -in gateway.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days ${DAYS} -sha256 -extfile gateway.ext -out gateway.crt 2>/dev/null

echo "▶ generating agent client cert (agentId=${AGENT_ID})"
openssl genrsa -out agent.key 2048 2>/dev/null
openssl req -new -key agent.key -subj "/O=XCP Dev/CN=agent-${AGENT_ID}" \
  -out agent.csr 2>/dev/null
cat > agent.ext <<EOF
subjectAltName = URI:did:8004:8453:agent-${AGENT_ID}
extendedKeyUsage = clientAuth
${AGENT_OID} = ASN1:UTF8String:${AGENT_ID}
EOF
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days ${DAYS} -sha256 -extfile agent.ext -out agent.crt 2>/dev/null

rm -f gateway.csr agent.csr gateway.ext agent.ext ca.srl

echo "✓ certs written to $(pwd)"
echo "  footprint = keccak256(DER(agent.crt)) — the on-chain session key"
