import os

from prometheus_client import Counter, Histogram

TRIAGE_LATENCY = Histogram(
    "tf_triage_latency_seconds", "End-to-end triage time per alert", ["provider"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16, 32),
)
STAGE_LATENCY = Histogram(
    "tf_stage_latency_seconds", "Time per pipeline stage", ["stage"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 4, 16),
)
VERDICTS = Counter("tf_verdicts_total", "Verdicts issued", ["verdict", "source"])
GUARDRAIL_FLAGS = Counter("tf_guardrail_flags_total", "Guardrail interventions", ["flag"])
LLM_TOKENS = Counter("tf_llm_tokens_total", "LLM tokens", ["direction"])
LLM_COST = Counter("tf_llm_cost_usd_total", "LLM spend in USD")
ERRORS = Counter("tf_errors_total", "Triage failures", ["stage"])


def setup_tracing(app) -> None:
    """Send OpenTelemetry traces when an OTLP endpoint is configured and the otel extra is installed."""
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": "triage-forge"}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)
