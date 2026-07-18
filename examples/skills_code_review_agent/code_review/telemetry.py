"""OpenTelemetry helpers; no-op when no provider/exporter is configured."""
from __future__ import annotations

from contextlib import contextmanager

try:
    from opentelemetry import trace
except ImportError:  # pragma: no cover
    trace = None


@contextmanager
def span(name: str, **attributes):
    if trace is None:
        yield None
        return
    tracer = trace.get_tracer("trpc_agent.examples.code_review")
    with tracer.start_as_current_span(name) as current:
        for key, value in attributes.items():
            if value is not None:
                current.set_attribute(key, value)
        yield current
