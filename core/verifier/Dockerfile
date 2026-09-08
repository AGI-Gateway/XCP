# Build from the repo root so the contracts ABI is in context:
#   docker build -f verifier/Dockerfile -t xcp-verifier .
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" eth-account eth-utils
# web3 optional (on-chain mode): RUN pip install --no-cache-dir web3
COPY verifier/xcp_verifier.py /app/xcp_verifier.py
COPY contracts/SessionRegistry.abi.json /app/contracts/SessionRegistry.abi.json
EXPOSE 8500
CMD ["uvicorn", "xcp_verifier:app", "--host", "0.0.0.0", "--port", "8500"]
