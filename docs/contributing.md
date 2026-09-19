# Contributing to XCP

Thanks for your interest. XCP is a draft protocol and the reference
implementation is evolving, so contributions and critical review are both
welcome.

## Ground rules

- **The protocol is a draft.** If a change affects the wire format (headers,
  scopes, the session/mandate flow), open an issue describing the change against
  `draft-xcp-core-00` before sending a large PR.
- **Keep the honesty.** This project is careful to distinguish what's real
  (MCP, A2A, ERC-8004, the OWASP taxonomies) from what's proposed here (XCP,
  ERC-8004x). Don't describe draft mechanisms as shipped standards, and keep the
  security docs' "what XCP does not solve" section honest.
- **Every client shares one interface.** The Python, Go, Java, and browser
  clients target the same gateway API. A change to one client's surface should
  be reflected in the others (or explicitly noted as language-specific).

## Development

```bash
pip install -r requirements.txt
make demo                 # end-to-end run, no config needed
make test                 # core + self-serve + security + sandbox suites
```

For the on-chain path:

```bash
pip install web3 eth-tester py-evm
python core/contracts/deploy_mock_registry.py
```

## Before you open a PR

- Run `make test` — core, self-serve, security and sandbox suites all pass.
- `python -m py_compile` the files you touched.
- If you changed the proto, confirm it still compiles:
  `python -m grpc_tools.protoc -Icore/proto --python_out=/tmp --grpc_python_out=/tmp core/proto/xcp_streams.proto`
- Keep formatting consistent (`gofmt` for Go; PEP 8 for Python).
- Update the relevant README / docs.

## Security issues

Report privately to the maintainers rather than in a public issue. See
[docs/security.md](security.md).
