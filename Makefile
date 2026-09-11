# XCP — common tasks. `make help` lists everything.
.DEFAULT_GOAL := help
PY ?= python3

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## install python dependencies
	$(PY) -m pip install -r requirements.txt

demo: ## run the end-to-end demo (no setup needed)
	$(PY) examples/end_to_end.py

test: ## run every test suite
	@echo "── core protocol ──"      && $(PY) tests/test_e2e.py
	@echo "── self-serve layer ──"   && $(PY) tests/test_selfserve.py
	@echo "── providers ──"          && $(PY) tests/test_providers.py
	@echo "── federation ──"         && $(PY) tests/test_federation.py
	@echo "── paid transport ──"     && $(PY) tests/test_transport.py
	@echo "── vault + connectors ──" && $(PY) tests/test_vault.py
	@echo "── receipts ──"           && $(PY) tests/test_receipts.py
	@echo "── trust firewall ──"     && $(PY) tests/test_trustfirewall.py
	@echo "── security library ──"   && $(PY) security/tests/test_xcpsec.py
	@echo "── sandbox ──"            && $(PY) security/tests/test_sandbox.py

lint: ## byte-compile everything
	@find . -name '*.py' -not -path './.git/*' -exec $(PY) -m py_compile {} + && echo "ok"

certs: ## generate a local mTLS dev PKI
	bash deploy/gen-certs.sh

up: ## run the stack with docker compose
	docker compose -f deploy/docker-compose.yml up --build

publish: ## generate ARD catalog + MCP manifest from xcp.toml
	./xcp publish --introspect

docs-sync: ## mirror component READMEs into docs/
	$(PY) scripts/sync-docs.py

docs: docs-sync ## build the documentation site
	mkdocs build --strict

docs-serve: docs-sync ## preview the docs site locally
	mkdocs serve

clean: ## remove caches and build output
	@find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -delete 2>/dev/null || true
	@rm -rf dist site deploy/certs/*.crt deploy/certs/*.key deploy/certs/*.srl
	@echo "cleaned"

.PHONY: help install demo test lint certs up publish docs docs-sync docs-serve clean
