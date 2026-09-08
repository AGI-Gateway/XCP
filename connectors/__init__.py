"""
connectors — one MCP endpoint definition per external SaaS.

    from connectors import load_catalog, register_all, required_secrets

Catalog files live in connectors/catalog/. They hold vault:// references,
never credentials — enforced at load time and in CI.
"""
from .loader import (ConnectorEntry, load_catalog, parse_entry, register_all,
                     required_secrets, CatalogError, CATALOG_DIR,
                     VALID_AUTH, VALID_TRUST, VALID_TRANSPORT)

__all__ = ["ConnectorEntry", "load_catalog", "parse_entry", "register_all",
           "required_secrets", "CatalogError", "CATALOG_DIR",
           "VALID_AUTH", "VALID_TRUST", "VALID_TRANSPORT"]
