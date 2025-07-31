# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Environment Setup
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
```

### Running the Application
```bash
uvicorn app.main:app --reload
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_query_endpoint.py
```

### Code Formatting
```bash
# Format with Black
black app/ tests/

# Sort imports with isort
isort app/ tests/
```

## Architecture Overview

This is a **simplified identity-based orchestrator for Amazon Bedrock Knowledge Bases**. The API serves as a secure filtering layer that applies identity-based metadata filtering and guardrails before calling the actual Bedrock RetrieveAndGenerate API.

### Key Components

1. **API Layer** (`app/main.py`): Single FastAPI application with core endpoints:
   - `/knowledge-bases` - List accessible knowledge bases for authenticated user
   - `/knowledge-bases/{kb_id}/query` - Query knowledge base with identity-based filtering
   - `/knowledge-bases/{kb_id}/refresh` - Start ingestion job to refresh knowledge base
   - `/health` - Health check endpoint
   - `/` - Root endpoint

2. **Authentication** (Okta OIDC JWT): 
   - JWT validation via `AuthMiddleware`
   - Department extraction from token claims (`dept_id`, `custom:dept_id`, `deptId`)
   - Role and department extraction for filtering
   - Test mode auth bypass (controlled by `DANKLAS_ENV`)

3. **Authorization** (AWS Verified Permissions):
   - `check_avp_authorization()` function for policy-based access control
   - Principal, Action, Resource model with context attributes
   - Fail-closed behavior (deny on errors)
   - Per-endpoint authorization checks:
     - Root: Action=`read`, Resource=`ApiInfo`
     - Health: Action=`read`, Resource=`HealthStatus`
     - List: Action=`list`, Resource=`KnowledgeBase` + individual KB checks
     - Query: Action=`query`, Resource=`KnowledgeBase::{kb_id}`
     - Refresh: Action=`refresh`, Resource=`KnowledgeBase::{kb_id}`

4. **Identity-Based Metadata Filtering**:
   - `build_metadata_filter()` function constructs filters based on JWT identity
   - Automatic department isolation (users only see their department's data)
   - Role-based access control (admin vs user)
   - Department-based filtering when available
   - Combines with user-provided metadata filters

5. **Static Guardrail Configuration**:
   - Environment variables: `BEDROCK_GUARDRAIL_ID`, `BEDROCK_GUARDRAIL_VERSION`
   - Applied to all Bedrock API calls for content safety
   - No dynamic management or admin endpoints

6. **Direct Bedrock Integration**:
   - Uses `boto3` bedrock-agent-runtime client
   - Calls `retrieve_and_generate()` with metadata filters and guardrails
   - Proper error handling and response formatting

### Simplified Architecture Benefits

- **70% code reduction**: From 656 lines to 276 lines in main.py
- **60% test reduction**: From 660 lines to 261 lines in tests
- **Minimal dependencies**: Only 8 core packages needed
- **No complex infrastructure**: No SSM, Redis, OpenTelemetry, rate limiting
- **Focus on core value**: Identity-based security and Bedrock orchestration

### Testing Approach

Tests use `pytest` with mocked Bedrock client:
- Environment set to "test" for auth bypass on basic endpoints
- Auth mocking for query endpoint tests  
- Comprehensive metadata filtering tests
- Access control validation
- Bedrock API error handling

### Environment Variables

Critical environment variables:
- `DANKLAS_ENV`: Controls auth bypass (test/dev/prod)
- `OKTA_ISSUER`: Okta OIDC issuer URL
- `OKTA_AUDIENCE`: Okta OIDC audience
- `BEDROCK_GUARDRAIL_ID`: Static guardrail ID to apply
- `BEDROCK_GUARDRAIL_VERSION`: Static guardrail version
- `AWS_REGION`: AWS region for Bedrock and AVP clients
- `AVP_POLICY_STORE_ID`: AWS Verified Permissions policy store ID
- `XRAY_SERVICE_NAME`: Service name for X-Ray tracing (default: "danklas-api")

### Data Requirements

For the metadata filtering to work effectively, your knowledge base documents should include `.metadata.json` files with fields like:
- `dept_id`: Which department owns this document
- `access_level`: "general" for regular users, "admin" for admin-only docs
- `department`: Optional department-specific filtering