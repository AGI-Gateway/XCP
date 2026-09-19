"""
telemetry.otel — logs, metrics and traces, or nothing at all.

OpenTelemetry is optional. Without the SDK installed every call here is a no-op
that costs a branch, so a node runs identically whether or not anyone is
collecting. That matters more than usual: this is infrastructure people will
deploy in places where adding an observability agent needs its own approval.

WHAT IS INSTRUMENTED
--------------------
The trust decision, not just the timing. A span for a governed call carries the
tier, the scope family, the decision and the reason it was refused — so a trace
answers "why was this denied", which is the question an operator has, rather
than only "how long did it take", which is the question a dashboard has.

Metrics are the four an operator pages on:

    xcp.calls            counter,   by stream and decision
    xcp.verify.duration  histogram, signature verification — the dominant cost
    xcp.limit.rejections counter,   by which limit fired
    xcp.peers            gauge,     federation reachability

CONFIGURATION
-------------
    XCP_OTEL=1                              enable
    OTEL_EXPORTER_OTLP_ENDPOINT=http://...  where to send
    OTEL_SERVICE_NAME=xcp-gateway           defaults to this
    XCP_OTEL_DETAIL=scrubbed|hosts|full     see telemetry.attributes

Read `telemetry/attributes.py` before setting `full`. Telemetry is a data-export
path, and it is declared in the privacy data map as a class with its own
retention and lawful basis for exactly that reason.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from .attributes import (call_attributes, detail_level, A_POSTURE, A_VERSION,
                         A_CRYPTO_FAST)

_ENABLED = False
_TRACER = None
_METERS: dict[str, Any] = {}
_LOGGER = None
_INIT_ERROR = ""

SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "xcp-gateway")


def enabled() -> bool:
    return _ENABLED


def init(service_name: str = "", resource_attributes: Optional[dict] = None) -> bool:
    """
    Bring up providers if OTel is available and requested. Returns whether
    telemetry is live. Safe to call more than once.

    Failure here is never fatal: a node that cannot export telemetry is a node
    with no telemetry, not a node that is down.
    """
    global _ENABLED, _TRACER, _METERS, _LOGGER, _INIT_ERROR
    if _ENABLED:
        return True
    if os.getenv("XCP_OTEL", "0") != "1":
        return False
    try:
        from opentelemetry import trace, metrics
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

        res = Resource.create({
            "service.name": service_name or SERVICE_NAME,
            "service.namespace": "xcp",
            **(resource_attributes or {})})

        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
        if endpoint:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter)
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                OTLPMetricExporter)
            span_exp: Any = OTLPSpanExporter()
            metric_reader = PeriodicExportingMetricReader(OTLPMetricExporter())
        else:
            # No endpoint: still produce spans so instrumentation can be
            # verified locally, rather than silently doing nothing.
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter
            from opentelemetry.sdk.metrics.export import ConsoleMetricExporter
            span_exp = ConsoleSpanExporter()
            metric_reader = PeriodicExportingMetricReader(
                ConsoleMetricExporter(), export_interval_millis=60000)

        tp = TracerProvider(resource=res)
        tp.add_span_processor(BatchSpanProcessor(span_exp))
        trace.set_tracer_provider(tp)
        metrics.set_meter_provider(MeterProvider(resource=res,
                                                 metric_readers=[metric_reader]))
        _TRACER = trace.get_tracer("xcp.gateway")
        meter = metrics.get_meter("xcp.gateway")
        _METERS = {
            "calls": meter.create_counter(
                "xcp.calls", unit="1",
                description="Governed calls by stream and decision"),
            "verify": meter.create_histogram(
                "xcp.verify.duration", unit="ms",
                description="Signature verification — the dominant per-call cost"),
            "limits": meter.create_counter(
                "xcp.limit.rejections", unit="1",
                description="Requests refused, by which limit fired"),
            "peers": meter.create_up_down_counter(
                "xcp.peers", unit="1", description="Federation peers"),
        }
        try:
            from opentelemetry._logs import set_logger_provider
            from opentelemetry.sdk._logs import LoggerProvider
            lp = LoggerProvider(resource=res)
            set_logger_provider(lp)
            _LOGGER = lp.get_logger("xcp.gateway")
        except Exception:
            _LOGGER = None          # logs are the least portable of the three
        _ENABLED = True
        return True
    except Exception as e:                       # never fatal
        _INIT_ERROR = f"{type(e).__name__}: {e}"
        return False


def status() -> dict[str, Any]:
    """What triage and /health report."""
    return {"enabled": _ENABLED, "detail": detail_level().value,
            "endpoint": os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "") or None,
            "service": SERVICE_NAME,
            "error": _INIT_ERROR or None}


@contextmanager
def call_span(name: str, **attrs: Any) -> Iterator[Any]:
    """
    Span around a governed call. A no-op context manager when disabled, so the
    call sites read the same either way.

        with call_span("a2t", stream="a2t", agent_id=..., scope=...) as span:
            ...
            record_decision(span, decision="deny", reason="out of scope")
    """
    if not _ENABLED or _TRACER is None:
        yield None
        return
    from opentelemetry.trace import SpanKind, Status, StatusCode
    with _TRACER.start_as_current_span(f"xcp.{name}", kind=SpanKind.SERVER) as span:
        for k, v in call_attributes(**attrs).items():
            span.set_attribute(k, v)
        try:
            yield span
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)[:200]))
            raise


def record_decision(span: Any, *, decision: str, reason: str = "",
                    stream: str = "", **extra: Any) -> None:
    """Attach the outcome, and count it. This is the useful half."""
    if span is not None:
        for k, v in call_attributes(decision=decision, reason=reason,
                                    **extra).items():
            span.set_attribute(k, v)
        if decision in ("deny", "block", "reject"):
            from opentelemetry.trace import Status, StatusCode
            # A refusal is a correct outcome, not a server fault — marking it
            # ERROR would make every dashboard look like an outage during an
            # attack that the gateway successfully repelled.
            span.set_attribute("xcp.refused", True)
            span.set_status(Status(StatusCode.OK))
    c = _METERS.get("calls")
    if c is not None:
        c.add(1, {"stream": stream or "unknown", "decision": decision})


def record_verify_ms(ms: float) -> None:
    h = _METERS.get("verify")
    if h is not None:
        h.record(ms)


def record_limit(kind: str) -> None:
    c = _METERS.get("limits")
    if c is not None:
        c.add(1, {"kind": kind})


def record_peer_delta(n: int) -> None:
    g = _METERS.get("peers")
    if g is not None:
        g.add(n)


def log(severity: str, body: str, **attrs: Any) -> None:
    """
    Emit a log correlated with the current trace, if logs are wired up.
    Falls back to nothing rather than to stdout, because a node that is not
    exporting should not suddenly start printing.
    """
    if not _ENABLED or _LOGGER is None:
        return
    try:
        from opentelemetry._logs import LogRecord, SeverityNumber
        from opentelemetry import trace as _t
        ctx = _t.get_current_span().get_span_context()
        sev = {"error": SeverityNumber.ERROR, "warn": SeverityNumber.WARN,
               "info": SeverityNumber.INFO}.get(severity, SeverityNumber.INFO)
        _LOGGER.emit(LogRecord(
            timestamp=int(time.time() * 1e9), body=body,
            severity_number=sev, severity_text=severity.upper(),
            attributes=call_attributes(**attrs),
            trace_id=ctx.trace_id, span_id=ctx.span_id,
            trace_flags=ctx.trace_flags))
    except Exception:
        pass


def node_attributes(posture: str = "", version: str = "",
                    crypto_fast: Optional[bool] = None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if posture:
        out[A_POSTURE] = posture
    if version:
        out[A_VERSION] = version
    if crypto_fast is not None:
        out[A_CRYPTO_FAST] = crypto_fast
    return out


__all__ = ["init", "enabled", "status", "call_span", "record_decision",
           "record_verify_ms", "record_limit", "record_peer_delta", "log",
           "node_attributes", "SERVICE_NAME"]
