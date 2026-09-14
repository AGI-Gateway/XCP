"""
telemetry — OpenTelemetry logs, metrics and traces, scrubbed by default.

    from telemetry import init, call_span, record_decision

Optional: without the SDK, or without XCP_OTEL=1, every call is a no-op. Read
telemetry/attributes.py before raising the detail level — telemetry is a data
export path and is declared in the privacy data map as its own class.
"""
from .attributes import (Detail, detail_level, pseudonym, scrub_scope,
                         call_attributes, SENSITIVE_AT_FULL)
from .otel import (init, enabled, status, call_span, record_decision,
                   record_verify_ms, record_limit, record_peer_delta, log,
                   node_attributes)

__all__ = ["Detail", "detail_level", "pseudonym", "scrub_scope",
           "call_attributes", "SENSITIVE_AT_FULL", "init", "enabled", "status",
           "call_span", "record_decision", "record_verify_ms", "record_limit",
           "record_peer_delta", "log", "node_attributes"]
