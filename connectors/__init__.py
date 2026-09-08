"""
connectors — MCP endpoints, curated and discovered.

    catalog/*.yaml   verified core, promotable      — dozens
    sources.py       crawled from upstream + peers  — thousands

Catalog files hold vault:// references, never credentials. Ingested entries
arrive unverified and untrusted; promotion is always a local decision.
"""
from .loader import (ConnectorEntry, load_catalog, parse_entry, register_all,
                     required_secrets, CatalogError, CATALOG_DIR,
                     VALID_AUTH, VALID_TRUST, VALID_TRANSPORT,
                     VALID_VERIFICATION, MAX_TRUST_FOR_STATUS)
from .sources import (GlobalCatalog, Source, SourceKind, IngestedEntry,
                      IngestError, DEFAULT_SOURCES, normalise_mcp_registry,
                      normalise_ard_catalog, normalise_peer_catalog)

__all__ = ["ConnectorEntry", "load_catalog", "parse_entry", "register_all",
           "required_secrets", "CatalogError", "CATALOG_DIR",
           "VALID_AUTH", "VALID_TRUST", "VALID_TRANSPORT",
           "VALID_VERIFICATION", "MAX_TRUST_FOR_STATUS",
           "GlobalCatalog", "Source", "SourceKind", "IngestedEntry",
           "IngestError", "DEFAULT_SOURCES", "normalise_mcp_registry",
           "normalise_ard_catalog", "normalise_peer_catalog"]
