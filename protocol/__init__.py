"""
protocol — one source of truth for what this implementation speaks.

    from protocol import negotiate, CURRENT, advertisement, read_compat

Versions and capabilities are negotiated explicitly, and every rename carries a
replacement and a removal date. See protocol/version.py.
"""
from .version import (SUPPORTED, CURRENT, MINIMUM, Feature, IMPLEMENTED,
                      H_VERSION, H_ACCEPT, H_FEATURES, negotiate, Negotiated,
                      VersionError, is_supported, parse_accept,
                      request_headers, response_headers, Deprecation,
                      DEPRECATIONS, read_compat, deprecation_warnings,
                      advertisement, compatible_with)

__all__ = ["SUPPORTED", "CURRENT", "MINIMUM", "Feature", "IMPLEMENTED",
           "H_VERSION", "H_ACCEPT", "H_FEATURES", "negotiate", "Negotiated",
           "VersionError", "is_supported", "parse_accept", "request_headers",
           "response_headers", "Deprecation", "DEPRECATIONS", "read_compat",
           "deprecation_warnings", "advertisement", "compatible_with"]
