#!/bin/sh
# Role selector. Fails loudly on an unknown role rather than defaulting to
# something the operator did not ask for.
set -eu

case "${ROLE:-gateway}" in
  gateway)
    exec uvicorn core.gateway.xcp_gateway:app \
         --host "${HOST:-0.0.0.0}" --port "${PORT:-8080}" \
         --workers "${WORKERS:-1}"
    ;;
  server)
    exec uvicorn core.server.xcp_server:app \
         --host "${HOST:-0.0.0.0}" --port "${PORT:-9001}"
    ;;
  verifier)
    exec uvicorn core.verifier.xcp_verifier:app \
         --host "${HOST:-0.0.0.0}" --port "${PORT:-8500}"
    ;;
  *)
    echo "unknown ROLE '${ROLE}' — expected gateway, server or verifier" >&2
    exit 2
    ;;
esac
