"""OpenTelemetry tracing configuration for Danklas API with AWS X-Ray integration."""

import logging
import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.extension.aws.trace import AwsXRayIdGenerator
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

logger = logging.getLogger(__name__)


def configure_tracing():
    """Configure OpenTelemetry tracing with AWS X-Ray integration."""

    # Environment configuration
    service_name = os.getenv("OTEL_SERVICE_NAME", "danklas-api")
    service_version = os.getenv("OTEL_SERVICE_VERSION", "1.0.0")
    environment = os.getenv("DANKLAS_ENV", "prod")

    # Configure resource attributes
    resource = Resource.create(
        {
            SERVICE_NAME: service_name,
            SERVICE_VERSION: service_version,
            "environment": environment,
            "service.namespace": "danklas",
        }
    )

    # Configure TracerProvider with AWS X-Ray ID Generator
    tracer_provider = TracerProvider(
        resource=resource, id_generator=AwsXRayIdGenerator()
    )

    # Configure OTLP exporter (for AWS X-Ray via OTEL Collector)
    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

    # Skip OTLP exporter configuration in test environment
    if environment == "test":
        logger.info("Skipping OTLP exporter configuration in test environment")
    else:
        try:
            otlp_exporter = OTLPSpanExporter(
                endpoint=otlp_endpoint,
                insecure=os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").lower() == "true",
            )

            # Add batch span processor
            span_processor = BatchSpanProcessor(otlp_exporter)
            tracer_provider.add_span_processor(span_processor)

            logger.info(f"OTLP exporter configured with endpoint: {otlp_endpoint}")
        except Exception as e:
            logger.warning(
                f"Failed to configure OTLP exporter: {e}. Spans will not be exported."
            )

    # Set the global tracer provider
    trace.set_tracer_provider(tracer_provider)

    # Get tracer for the service
    tracer = trace.get_tracer(__name__)

    logger.info(f"OpenTelemetry tracing configured for service: {service_name}")
    return tracer


def instrument_fastapi(app):
    """Instrument FastAPI app with OpenTelemetry."""

    # Instrument FastAPI
    FastAPIInstrumentor.instrument_app(
        app, excluded_urls="/docs,/redoc,/openapi.json,/favicon.ico"
    )

    # Instrument requests library for outbound HTTP calls
    RequestsInstrumentor().instrument()

    logger.info("FastAPI and requests instrumentation enabled")


def get_tracer():
    """Get the configured tracer instance."""
    return trace.get_tracer(__name__)


def create_span(name: str, attributes: dict = None):
    """Create a new span with optional attributes."""
    tracer = get_tracer()
    span = tracer.start_span(name)
    if attributes:
        for key, value in attributes.items():
            span.set_attribute(key, value)
    return span
