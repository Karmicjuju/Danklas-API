# Danklas API

A simplified identity-based orchestrator for Amazon Bedrock Knowledge Bases that provides secure, tenant-isolated access with automatic metadata filtering and content guardrails.

## Overview

This API serves as a secure filtering layer between clients and Amazon Bedrock Knowledge Bases. It extracts identity information from JWT tokens and applies metadata filters to ensure users only access their organization's data, while applying content guardrails for safety.

## Key Features

- **🔐 Identity-Based Security**: Automatic tenant isolation via JWT token claims
- **🛡️ Metadata Filtering**: Role and department-based access control  
- **🚨 Content Guardrails**: Static Bedrock guardrail configuration for content safety
- **⚡ Simplified Architecture**: Single endpoint, minimal dependencies, focused functionality
- **🐳 Container Ready**: Multi-stage Docker build with distroless runtime

## Quick Start

### Prerequisites
- Python 3.10 or higher
- AWS credentials configured
- Bedrock Knowledge Base and Guardrail configured in AWS

### Installation
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run the application
uvicorn app.main:app --reload
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DANKLAS_ENV` | Environment mode (dev/test/prod) | `prod` |
| `OKTA_ISSUER` | Okta OIDC issuer URL | Required |
| `OKTA_AUDIENCE` | Okta OIDC audience | `api://default` |
| `BEDROCK_GUARDRAIL_ID` | Bedrock Guardrail ID to apply | Required |
| `BEDROCK_GUARDRAIL_VERSION` | Bedrock Guardrail version | `1` |
| `AWS_REGION` | AWS region for Bedrock client | `us-east-1` |

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_query_endpoint.py
```

## API Usage

### Authentication
Include a Bearer token in the Authorization header:
```bash
curl -H "Authorization: Bearer <jwt-token>" \
     -H "Content-Type: application/json" \
     -d '{"query": "What is machine learning?"}' \
     https://your-api/knowledge-bases/kb-your-org-docs/query
```

### Query Endpoint
**POST** `/knowledge-bases/{kb_id}/query`

```json
{
  "query": "What are the latest product features?",
  "metadata_filters": {
    "document_type": "product_docs"
  }
}
```

**Response:**
```json
{
  "answer": "Based on the latest product documentation...",
  "citations": [
    "s3://your-bucket/product-docs/features.pdf",
    "s3://your-bucket/product-docs/changelog.pdf"
  ]
}
```

## Architecture

### Simplified Design
- **276 lines** of core application code (vs 656 in original)  
- **8 dependencies** (vs 23 in original)
- **Single endpoint** focus on knowledge base queries
- **No complex infrastructure** dependencies (Redis, SSM, OpenTelemetry)

### Security Model
1. **JWT Token** → Extract `tenant_id`, `roles`, `department`
2. **Metadata Filters** → Automatic tenant isolation + role-based access
3. **Bedrock API** → Call with combined filters and static guardrails
4. **Response** → Clean answer and citations

### Project Structure
```
Danklas-API/
├── app/
│   └── main.py              # Single FastAPI application (276 lines)
├── tests/
│   └── test_query_endpoint.py  # Comprehensive test suite (261 lines)
├── terraform/
│   ├── main.tf              # Simplified AWS infrastructure
│   └── README.md            # Deployment guide
├── requirements.txt         # 8 core dependencies
├── Dockerfile              # Multi-stage container build
├── CLAUDE.md               # Development guidance
└── README.md               # This file
```

## Data Requirements

For metadata filtering to work, your Knowledge Base documents should include `.metadata.json` files:

**Example: `document.pdf.metadata.json`**
```json
{
  "tenant_id": "acme-corp",
  "access_level": "general",
  "department": "engineering",
  "document_type": "technical_spec",
  "created_date": "2024-01-15"
}
```

## Deployment

### Docker
```bash
docker build -t danklas-api .
docker run -p 8000:8000 \
  -e OKTA_ISSUER=https://your-okta.com/oauth2/default \
  -e BEDROCK_GUARDRAIL_ID=your-guardrail-id \
  danklas-api
```

### AWS ECS (Terraform)
```bash
cd terraform
terraform init
terraform plan
terraform apply
```

## Migration from v1.0

This v2.0 represents a major simplification:

### Removed Components
- ❌ Complex guardrails management (SSM Parameter Store)
- ❌ Redis-based rate limiting with usage tiers
- ❌ OpenTelemetry tracing and X-Ray integration
- ❌ Admin endpoints for guardrail management
- ❌ Multi-region deployment complexity
- ❌ VPC endpoints and complex networking

### Simplified Approach
- ✅ Static guardrail configuration via environment variables
- ✅ Identity-based security through metadata filtering
- ✅ Direct Bedrock API integration (no mocks)
- ✅ Minimal infrastructure requirements
- ✅ Container-first deployment model

## Contributing

1. **Code Formatting**: Use `black` and `isort`
2. **Testing**: All tests must pass with `pytest`
3. **Documentation**: Update CLAUDE.md for architecture changes

## License

Private project - see repository settings for access permissions.