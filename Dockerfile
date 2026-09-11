# XCP — one image, three roles.
#
# Three separate images drifted: the gateway image shipped without the modules
# the gateway had grown to import, so abuse controls and the argument firewall
# were silently absent in the only build anyone would actually deploy. One image
# with a role selector cannot drift that way, and the surface it adds is a few
# hundred KB of Python.
#
#   docker run -e ROLE=gateway  -p 8080:8080 ghcr.io/agi-gateway/xcp
#   docker run -e ROLE=server   -p 9001:9001 ghcr.io/agi-gateway/xcp
#   docker run -e ROLE=verifier -p 8500:8500 ghcr.io/agi-gateway/xcp

FROM python:3.12-slim AS base

# Dependencies first so layer caching survives source edits.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm -rf /root/.cache

WORKDIR /app

# Everything the runtime actually imports. The gateway reaches into
# trustfirewall/ and security/, the verifier into core/contracts/, and the
# wrapper generator into vault/ — copying only the entrypoint is what broke
# before.
COPY core/            /app/core/
COPY trustfirewall/   /app/trustfirewall/
COPY security/        /app/security/
COPY vault/           /app/vault/
COPY trust/           /app/trust/
COPY federation/      /app/federation/
COPY connectors/      /app/connectors/
COPY receipts/        /app/receipts/
COPY providers/       /app/providers/
COPY discovery/       /app/discovery/
COPY entrypoint.sh    /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin xcp \
 && chown -R xcp:xcp /app
USER 10001

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ROLE=gateway

EXPOSE 8080 9001 8500

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request;p={'gateway':8080,'server':9001,'verifier':8500}[os.getenv('ROLE','gateway')];urllib.request.urlopen(f'http://127.0.0.1:{p}/health',timeout=2)"

ENTRYPOINT ["/app/entrypoint.sh"]
