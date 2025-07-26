# Danklas API

FastAPI project setup for multi-tenant Amazon Bedrock Knowledge Bases facade.

## FastAPI Project Setup

This project uses Poetry for dependency management and FastAPI for the web framework.

### Prerequisites
- Python 3.13 or higher
- Poetry

### Installation
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
poetry install

# Run the application
poetry run uvicorn app.main:app --reload
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DANKLAS_ENV` | Environment mode (dev/test/prod) | `prod` |
| `OKTA_ISSUER` | Okta OIDC issuer URL | Required |
| `OKTA_AUDIENCE` | Okta OIDC audience | `api://default` |
| `OTEL_SERVICE_NAME` | OpenTelemetry service name | `danklas-api` |
| `OTEL_SERVICE_VERSION` | OpenTelemetry service version | `1.0.0` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint for traces | `http://localhost:4317` |
| `OTEL_EXPORTER_OTLP_INSECURE` | Use insecure OTLP connection | `true` |

### OpenTelemetry Tracing

The application includes comprehensive distributed tracing with OpenTelemetry:

- **Automatic instrumentation** for FastAPI and HTTP requests
- **Custom spans** for knowledge base operations (query, status, refresh)
- **AWS X-Ray compatible** trace IDs for seamless AWS integration
- **Trace context correlation** in logs (trace_id, span_id)
- **OTLP export** to AWS X-Ray via OpenTelemetry Collector

#### Local Development

For local development without an OTEL collector, the application will log warnings about failed exports but continue to function normally. To run with tracing:

1. Install AWS OTEL Collector or use a local OTEL endpoint
2. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to your collector endpoint
3. Traces will be exported and can be viewed in AWS X-Ray console

### Testing
```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=app
```

## Project Structure

```
Danklas-API/
├── app/
│   ├── main.py          # FastAPI application and endpoints
│   └── tracing.py       # OpenTelemetry configuration
├── tests/
│   └── test_query_endpoint.py  # API endpoint tests
├── terraform/           # Infrastructure as Code
├── pyproject.toml      # Poetry dependencies
├── Dockerfile          # Multi-stage container build
└── README.md           # This file
```

## Features Implemented

### Epic 0 - Foundation ✅
- [x] DANK-0.1: FastAPI + Poetry + Docker + CI/CD
- [x] DANK-0.2: Terraform root module scaffold

### Epic 1 - Authentication & Authorization ✅  
- [x] DANK-1.1: Okta OIDC JWT validation
- [x] DANK-1.2: Environment-based auth bypass for development

### Epic 2 - Core KB Endpoints ✅
- [x] DANK-2.1: `/knowledge-bases/{id}/query` endpoint
- [x] DANK-2.2: `/knowledge-bases/{id}/status` endpoint  
- [x] DANK-2.3: `/knowledge-bases/{id}/refresh` endpoint

### Epic 3 - Observability ✅
- [x] DANK-3.1: Structured JSON logging
- [x] DANK-3.2: Audit log retention (400 days)
- [x] DANK-3.3: OpenTelemetry tracing with X-Ray integration 