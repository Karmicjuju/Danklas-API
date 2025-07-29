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

## Detailed Setup Guide

This section provides step-by-step instructions for setting up all required components.

### 1. AWS Bedrock Setup

#### Create a Knowledge Base

1. **Navigate to Amazon Bedrock Console**
   - Go to AWS Console → Amazon Bedrock → Knowledge bases
   
2. **Create Knowledge Base**
   ```bash
   # Knowledge Base naming convention for tenant isolation:
   # kb-{tenant-id}-{purpose}
   # Examples:
   # - kb-acme-corp-docs
   # - kb-acme-corp-policies
   # - kb-shared-public-docs (for shared content)
   ```

3. **Configure Data Source**
   - Choose S3 as your data source
   - Set up your S3 bucket with proper folder structure:
   ```
   your-bucket/
   ├── acme-corp/
   │   ├── documents/
   │   │   ├── policy.pdf
   │   │   ├── policy.pdf.metadata.json
   │   │   ├── technical-spec.pdf
   │   │   └── technical-spec.pdf.metadata.json
   │   └── department-specific/
   │       ├── engineering/
   │       └── sales/
   └── shared/
       └── public-docs/
   ```

4. **Create Document Metadata Files**
   
   For each document, create a corresponding `.metadata.json` file:
   
   **Example: `policy.pdf.metadata.json`**
   ```json
   {
     "tenant_id": "acme-corp",
     "access_level": "general",
     "department": "all",
     "document_type": "policy",
     "created_date": "2024-01-15",
     "tags": ["hr", "company-policy"]
   }
   ```
   
   **Example: `executive-report.pdf.metadata.json`** (Admin-only)
   ```json
   {
     "tenant_id": "acme-corp", 
     "access_level": "admin",
     "department": "executive",
     "document_type": "financial_report",
     "created_date": "2024-01-15",
     "tags": ["confidential", "quarterly-report"]
   }
   ```

5. **Note Your Knowledge Base ID**
   - After creation, note the Knowledge Base ID (starts with `kb-`)
   - This will be used in your API calls and should follow the naming convention

#### Create Bedrock Guardrails

1. **Navigate to Guardrails**
   - Go to AWS Console → Amazon Bedrock → Guardrails

2. **Create New Guardrail**
   - Name: `danklas-content-filter`
   - Configure content filters for:
     - Hate speech: High
     - Insults: Medium
     - Sexual content: High
     - Violence: Medium
     - Misconduct: High

3. **Create Version**
   - Create a version (usually version "1")
   - Note the Guardrail ID and Version

### 2. Okta OIDC Setup

#### Create Okta Application

1. **Access Okta Admin Console**
   - Log into your Okta organization as an administrator

2. **Create New Application**
   - Applications → Create App Integration
   - Choose "API Services" (machine-to-machine)
   - Name: "Danklas API"

3. **Configure Application**
   ```json
   {
     "name": "Danklas API",
     "type": "service",
     "grant_types": ["client_credentials"],
     "response_types": ["token"],
     "token_endpoint_auth_method": "client_secret_basic"
   }
   ```

4. **Set Up Custom Claims**
   
   Create custom claims in your authorization server:
   
   **Tenant ID Claim:**
   ```json
   {
     "name": "tenant_id",
     "value": "appuser.tenant_id",
     "include_in_token_type": "Access Token"
   }
   ```
   
   **Roles Claim:**
   ```json
   {
     "name": "roles", 
     "value": "appuser.roles",
     "include_in_token_type": "Access Token"
   }
   ```
   
   **Department Claim (Optional):**
   ```json
   {
     "name": "department",
     "value": "appuser.department", 
     "include_in_token_type": "Access Token"
   }
   ```

5. **Configure User Profiles**
   
   Ensure your users have these custom attributes:
   - `tenant_id`: Their organization identifier
   - `roles`: Array of roles like `["user"]` or `["admin"]`
   - `department`: Their department (optional)

6. **Test Token Generation**
   ```bash
   curl -X POST "https://your-okta-domain.com/oauth2/default/v1/token" \
        -H "Accept: application/json" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&scope=api://default" \
        -u "client_id:client_secret"
   ```

### 3. AWS Credentials Configuration

Choose one of these methods:

#### Option A: AWS CLI (Recommended for development)
```bash
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure
# AWS Access Key ID: your-access-key
# AWS Secret Access Key: your-secret-key  
# Default region: us-east-1
# Default output format: json
```

#### Option B: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_REGION=us-east-1
```

#### Option C: IAM Roles (Recommended for production)
- Attach IAM role to your EC2/ECS/Lambda with these permissions:
  - `bedrock:InvokeModel`
  - `bedrock:RetrieveAndGenerate`
  - `bedrock:ApplyGuardrail`

### 4. Local Development Setup

1. **Clone and Setup Project**
   ```bash
   git clone your-repo
   cd danklas-api
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt -r requirements-dev.txt
   ```

2. **Create Environment File**
   ```bash
   cp .env.example .env
   # Edit .env with your actual values
   ```

3. **Verify Setup**
   ```bash
   # Run tests to verify everything works
   pytest
   
   # Start development server
   uvicorn app.main:app --reload
   
   # Test health endpoint
   curl http://localhost:8000/health
   ```

4. **Test Authentication Flow**
   ```bash
   # Get a JWT token from Okta
   TOKEN=$(curl -s -X POST "https://your-okta.com/oauth2/default/v1/token" \
               -H "Content-Type: application/x-www-form-urlencoded" \
               -d "grant_type=client_credentials&scope=api://default" \
               -u "client_id:client_secret" | jq -r '.access_token')
   
   # Test API call
   curl -X POST "http://localhost:8000/knowledge-bases/kb-your-tenant-docs/query" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"query": "What is our company policy?"}'
   ```

### 5. Production Deployment Checklist

- [ ] Knowledge bases created with proper naming convention
- [ ] Document metadata files created for all documents  
- [ ] Bedrock guardrails configured and tested
- [ ] Okta OIDC application configured with custom claims
- [ ] AWS credentials configured (preferably IAM roles)
- [ ] Environment variables set in production environment
- [ ] Health checks configured (`/health` endpoint)
- [ ] Monitoring and logging configured
- [ ] SSL/TLS certificates configured
- [ ] Rate limiting configured (if needed)

## API Usage

### Authentication

The API requires JWT Bearer token authentication with specific claims:

```bash
curl -H "Authorization: Bearer <your-jwt-token>" \
     -H "Content-Type: application/json" \
     -d '{"query": "What is machine learning?"}' \
     https://your-api/knowledge-bases/kb-your-org-docs/query
```

#### Required JWT Claims

Your JWT token must include these claims:

```json
{
  "sub": "user123",
  "tenant_id": "acme-corp",
  "roles": ["user"],
  "department": "engineering",
  "exp": 1234567890,
  "aud": "api://default", 
  "iss": "https://your-company.okta.com/oauth2/default"
}
```

| Claim | Description | Example | Required |
|-------|-------------|---------|----------|
| `tenant_id` | Organization identifier (also accepts `custom:tenant_id`, `tenantId`) | `"acme-corp"` | ✅ |
| `roles` | User roles array (also accepts `custom:roles`, `groups`) | `["user"]`, `["admin"]` | ✅ |
| `department` | Department for filtering | `"engineering"` | ❌ |
| `sub` | User identifier | `"user123"` | ✅ |
| `exp` | Token expiration | `1234567890` | ✅ |
| `aud` | Token audience | `"api://default"` | ✅ |
| `iss` | Token issuer | `"https://your-okta.com/oauth2/default"` | ✅ |

### Query Endpoint

**POST** `/knowledge-bases/{kb_id}/query`

#### Basic Query

```bash
curl -X POST "https://your-api/knowledge-bases/kb-acme-corp-docs/query" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "query": "What are the latest product features?"
     }'
```

#### Query with Metadata Filters

```bash
curl -X POST "https://your-api/knowledge-bases/kb-acme-corp-docs/query" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "query": "What are the security best practices?",
       "metadata_filters": {
         "document_type": "security_docs",
         "created_date": {"gte": "2024-01-01"}
       }
     }'
```

#### Request Schema

```json
{
  "query": "string (required, 1-2000 characters)",
  "metadata_filters": {
    "key": "value",
    "another_key": {"operator": "value"}
  }
}
```

#### Response Schema

```json
{
  "answer": "Generated answer based on your documents...",
  "citations": [
    "s3://your-bucket/docs/document1.pdf",
    "s3://your-bucket/docs/document2.pdf"
  ]
}
```

### Knowledge Base Access Patterns

#### Tenant-Specific Knowledge Bases
```bash
# Access your organization's private knowledge base
GET /knowledge-bases/kb-acme-corp-internal/query
```

#### Shared Knowledge Bases  
```bash
# Access shared knowledge bases (available to all tenants)
GET /knowledge-bases/kb-shared-public-docs/query
```

#### Admin vs User Access

**Regular User Query** (sees only "general" access level documents):
```json
{
  "query": "What is our company policy?",
  "metadata_filters": {
    "document_type": "policy"
  }
}
```

**Admin User Query** (sees all access levels including sensitive documents):
```json
{
  "query": "What are the executive compensation details?",
  "metadata_filters": {
    "document_type": "executive_docs"
  }
}
```

### Department-Based Filtering

If your JWT token includes a `department` claim, you'll automatically see only documents for your department:

```json
{
  "query": "What are our engineering best practices?",
  "metadata_filters": {
    "document_type": "engineering_docs"
  }
}
```

### Error Responses

| Status Code | Description | Example |
|-------------|-------------|---------|
| `400` | Bad Request | Invalid JSON or missing required fields |
| `401` | Unauthorized | Missing or invalid JWT token |
| `403` | Forbidden | Access denied to knowledge base or insufficient permissions |
| `422` | Unprocessable Entity | Invalid request format |
| `500` | Internal Server Error | Bedrock API failure or server error |

**Example Error Response:**
```json
{
  "detail": "Access denied: KB kb-other-company-docs not accessible by tenant acme-corp"
}
```

### Interactive API Documentation

Visit `/docs` on your running API for interactive Swagger documentation:
```
https://your-api-domain.com/docs
```

## Security & Metadata Filtering Guide

This section explains how the API implements security through identity-based metadata filtering.

### Security Architecture Overview

```
JWT Token → Identity Extraction → Metadata Filters → Bedrock API → Filtered Results
```

1. **JWT Validation**: Extract identity claims from token
2. **Automatic Filtering**: Build security filters based on identity  
3. **Filter Combination**: Merge security filters with user filters
4. **Bedrock Query**: Execute query with combined filters
5. **Guardrails**: Apply content safety filtering

### Identity-Based Filtering

#### Tenant Isolation

Every query automatically applies tenant-based filtering:

```python
# Automatic filter applied based on JWT token
{
  "andAll": [
    {"equals": {"key": "tenant_id", "value": "acme-corp"}},
    # Additional filters based on role and user-provided filters
  ]
}
```

**Document Requirements:**
```json
{
  "tenant_id": "acme-corp",  # Must match JWT claim
  "access_level": "general", # or "admin"
  "department": "engineering" # Optional
}
```

#### Role-Based Access Control

**Regular Users** (`roles: ["user"]`):
- See only documents with `access_level: "general"`
- Cannot access admin-only documents

```json
{
  "andAll": [
    {"equals": {"key": "tenant_id", "value": "acme-corp"}},
    {"equals": {"key": "access_level", "value": "general"}}
  ]
}
```

**Admin Users** (`roles: ["admin"]`):
- See documents with any access level
- Can access sensitive/confidential documents

```json
{
  "andAll": [
    {"equals": {"key": "tenant_id", "value": "acme-corp"}}
    # No access_level filter - admins see everything
  ]
}
```

#### Department-Based Filtering

If JWT includes `department` claim, additional filtering is applied:

```json
{
  "andAll": [
    {"equals": {"key": "tenant_id", "value": "acme-corp"}},
    {"equals": {"key": "access_level", "value": "general"}},
    {"equals": {"key": "department", "value": "engineering"}}
  ]
}
```

### Practical Security Examples

#### Example 1: Basic User Query

**JWT Claims:**
```json
{
  "tenant_id": "acme-corp",
  "roles": ["user"],
  "department": "sales"
}
```

**Automatic Filters Applied:**
```json
{
  "andAll": [
    {"equals": {"key": "tenant_id", "value": "acme-corp"}},
    {"equals": {"key": "access_level", "value": "general"}},
    {"equals": {"key": "department", "value": "sales"}}
  ]
}
```

**Documents User Can Access:**
- ✅ `tenant_id: "acme-corp"`, `access_level: "general"`, `department: "sales"`
- ✅ `tenant_id: "acme-corp"`, `access_level: "general"`, `department: "all"`
- ❌ `tenant_id: "acme-corp"`, `access_level: "admin"` (admin-only)
- ❌ `tenant_id: "other-corp"` (different tenant)
- ❌ `tenant_id: "acme-corp"`, `department: "engineering"` (different dept)

#### Example 2: Admin User Query

**JWT Claims:**
```json
{
  "tenant_id": "acme-corp", 
  "roles": ["admin"]
}
```

**Automatic Filters Applied:**
```json
{
  "andAll": [
    {"equals": {"key": "tenant_id", "value": "acme-corp"}}
    # No access_level or department filters
  ]
}
```

**Documents Admin Can Access:**
- ✅ All documents with `tenant_id: "acme-corp"`
- ✅ Any `access_level` (general, admin, confidential)
- ✅ Any `department` 
- ❌ `tenant_id: "other-corp"` (still respects tenant isolation)

#### Example 3: User-Provided Filters

**Request:**
```json
{
  "query": "What are our Q1 financial results?",
  "metadata_filters": {
    "document_type": "financial_report",
    "quarter": "Q1"
  }
}
```

**Combined Filters (for regular user):**
```json
{
  "andAll": [
    {
      "andAll": [
        {"equals": {"key": "tenant_id", "value": "acme-corp"}},
        {"equals": {"key": "access_level", "value": "general"}}
      ]
    },
    {
      "document_type": "financial_report",
      "quarter": "Q1"
    }
  ]
}
```

### Document Metadata Best Practices

#### Required Metadata Fields

Every document should have these metadata fields:

```json
{
  "tenant_id": "string",     # Required - organization identifier
  "access_level": "string",  # Required - "general" or "admin"
  "department": "string",    # Optional - department filter
  "document_type": "string", # Optional - for user filtering
  "created_date": "string",  # Optional - for date filtering
  "tags": ["array"]          # Optional - for tag-based filtering
}
```

#### Access Level Guidelines

**Use `"access_level": "general"`** for:
- Company policies and procedures
- Product documentation
- Training materials
- Public announcements
- General reference documents

**Use `"access_level": "admin"`** for:
- Financial reports and sensitive data
- Executive communications
- Strategic planning documents
- Personnel information
- Legal and compliance documents

#### Department-Based Organization

Structure documents by department when appropriate:

```json
{
  "tenant_id": "acme-corp",
  "access_level": "general",
  "department": "engineering",
  "document_type": "technical_spec"
}
```

**Department Examples:**
- `"engineering"` - Technical specifications, API docs, architecture
- `"sales"` - Sales playbooks, customer information, pricing
- `"hr"` - HR policies, benefits information, onboarding
- `"finance"` - Budget information, expense policies
- `"all"` - Documents accessible to all departments

### Knowledge Base Naming Strategy

#### Tenant-Specific Knowledge Bases
```
kb-{tenant-id}-{purpose}

Examples:
- kb-acme-corp-policies
- kb-acme-corp-technical-docs  
- kb-acme-corp-sales-materials
```

#### Shared Knowledge Bases
```
kb-shared-{purpose}

Examples:
- kb-shared-public-docs
- kb-shared-industry-standards
- kb-shared-compliance-guides
```

### Security Considerations

#### What's Protected
- ✅ **Tenant Isolation**: Users cannot access other organizations' data
- ✅ **Role-Based Access**: Admins see more than regular users
- ✅ **Department Filtering**: Users see only relevant department docs
- ✅ **Content Safety**: Bedrock guardrails filter inappropriate content

#### What's NOT Protected
- ❌ **Rate Limiting**: No built-in API rate limiting
- ❌ **Audit Logging**: Basic logging only, no detailed audit trails
- ❌ **Data Encryption**: Relies on AWS Bedrock's encryption
- ❌ **Token Refresh**: No automatic JWT token refresh

#### Security Best Practices

1. **Environment Variables**: Never commit secrets to version control
2. **JWT Expiration**: Use short-lived tokens (1-24 hours)
3. **HTTPS Only**: Always use HTTPS in production
4. **IAM Roles**: Use IAM roles instead of access keys when possible
5. **Regular Audits**: Periodically review user access and document metadata
6. **Guardrail Updates**: Keep Bedrock guardrails updated

### Testing Security

#### Test Tenant Isolation
```bash
# Test with different tenant tokens
TOKEN_ACME=$(get_token_for_tenant "acme-corp")
TOKEN_OTHER=$(get_token_for_tenant "other-corp")

# Should work
curl -H "Authorization: Bearer $TOKEN_ACME" \
     .../knowledge-bases/kb-acme-corp-docs/query

# Should fail with 403
curl -H "Authorization: Bearer $TOKEN_OTHER" \
     .../knowledge-bases/kb-acme-corp-docs/query
```

#### Test Role-Based Access  
```bash
# Test admin vs user access to same query
USER_TOKEN=$(get_user_token)
ADMIN_TOKEN=$(get_admin_token)

# Compare results - admin should see more documents
curl -H "Authorization: Bearer $USER_TOKEN" \
     -d '{"query": "confidential information"}' \
     .../query

curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"query": "confidential information"}' \
     .../query
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

## Troubleshooting

### Common Issues and Solutions

#### Authentication Issues

**Problem: "Missing or invalid Authorization header"**
```json
{
  "detail": "Missing or invalid Authorization header"
}
```

**Solutions:**
1. Ensure you're including the `Authorization` header:
   ```bash
   curl -H "Authorization: Bearer YOUR_JWT_TOKEN" ...
   ```

2. Verify your JWT token is valid:
   ```bash
   # Decode JWT to check claims (use jwt.io or this command)
   echo "YOUR_JWT_TOKEN" | cut -d. -f2 | base64 -d | jq
   ```

3. Check token expiration (`exp` claim)

**Problem: "Missing tenant_id claim in token"**
```json
{
  "detail": "Missing tenant_id claim in token"
}
```

**Solutions:**
1. Verify your Okta custom claims are configured correctly
2. Check that your user profile has the `tenant_id` attribute
3. Ensure the claim is included in the access token (not just ID token)

#### Knowledge Base Access Issues

**Problem: "Access denied: KB not accessible by tenant"**
```json
{
  "detail": "Access denied: KB kb-other-company-docs not accessible by tenant acme-corp"
}
```

**Solutions:**
1. Verify KB ID follows naming convention:
   - Use `kb-{your-tenant-id}-{purpose}` for tenant-specific KBs
   - Use `kb-shared-{purpose}` for shared KBs
   
2. Check your JWT `tenant_id` claim matches the KB naming

3. For shared KBs, ensure they start with `kb-shared-`

#### Bedrock API Issues

**Problem: "Failed to process knowledge base query"**
```json
{
  "detail": "Failed to process knowledge base query"
}
```

**Solutions:**
1. **Check AWS Credentials:**
   ```bash
   aws sts get-caller-identity
   aws bedrock list-foundation-models --region us-east-1
   ```

2. **Verify IAM Permissions:**
   Ensure your AWS credentials have these permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:InvokeModel",
           "bedrock:RetrieveAndGenerate"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

3. **Check Knowledge Base Status:**
   - Verify the KB exists and is in "Active" status
   - Ensure the KB has been synced with your data source

4. **Verify Guardrail Configuration:**
   - Check `BEDROCK_GUARDRAIL_ID` exists
   - Ensure `BEDROCK_GUARDRAIL_VERSION` is valid

#### Environment Configuration Issues

**Problem: Application won't start or environment variables not recognized**

**Solutions:**
1. **Check Environment File:**
   ```bash
   # Verify .env file exists and has correct format
   cat .env
   
   # Ensure no spaces around = signs
   # Correct:   OKTA_ISSUER=https://your-okta.com
   # Incorrect: OKTA_ISSUER = https://your-okta.com
   ```

2. **Verify Required Variables:**
   ```bash
   # Check all required variables are set
   python -c "
   import os
   required = ['OKTA_ISSUER', 'OKTA_AUDIENCE', 'BEDROCK_GUARDRAIL_ID']
   for var in required:
       print(f'{var}: {os.getenv(var, \"NOT SET\")}')
   "
   ```

3. **Load Environment in Development:**
   ```bash
   # If using python-dotenv
   pip install python-dotenv
   
   # Or manually source
   set -a; source .env; set +a
   ```

#### Metadata Filtering Issues

**Problem: Query returns no results despite having documents**

**Solutions:**
1. **Check Document Metadata:**
   Ensure your documents have proper `.metadata.json` files:
   ```json
   {
     "tenant_id": "your-tenant-id",
     "access_level": "general",
     "department": "your-department"
   }
   ```

2. **Verify Metadata Alignment:**
   Your JWT claims must align with document metadata:
   - JWT `tenant_id` must match document `tenant_id`
   - Non-admin users need documents with `access_level: "general"`
   - Department claims must match if using department filtering

3. **Test Metadata Filters:**
   ```bash
   # Test without additional filters first
   curl -X POST ".../query" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{"query": "test query"}'
   
   # Then add filters gradually
   curl -X POST ".../query" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{"query": "test query", "metadata_filters": {"document_type": "policy"}}'
   ```

#### Local Development Issues

**Problem: Tests failing with authentication errors**

**Solutions:**
1. **Ensure Test Environment:**
   ```bash
   # Tests should use DANKLAS_ENV=test
   DANKLAS_ENV=test pytest
   ```

2. **Check Test Isolation:**
   ```python
   # Verify test environment is set before importing
   import os
   os.environ["DANKLAS_ENV"] = "test"
   from app.main import app
   ```

**Problem: "ModuleNotFoundError" when running locally**

**Solutions:**
1. **Activate Virtual Environment:**
   ```bash
   source venv/bin/activate
   pip install -r requirements.txt -r requirements-dev.txt
   ```

2. **Check Python Path:**
   ```bash
   # Run from project root
   python -m app.main
   # Or
   uvicorn app.main:app --reload
   ```

### Debug Mode

For debugging, you can enable detailed logging:

```bash
# Set environment variable
export DANKLAS_ENV=dev

# Or add to your .env file
echo "DANKLAS_ENV=dev" >> .env
```

This will provide more detailed error messages and logging output.

### Getting Help

1. **Check Logs:** Review application logs for detailed error messages
2. **Test Components Individually:** 
   - Test Okta token generation separately
   - Test AWS Bedrock access with AWS CLI
   - Verify Knowledge Base status in AWS Console
3. **Use Interactive Docs:** Visit `/docs` endpoint for API testing
4. **Check Dependencies:** Ensure all required services are running and accessible

## Client Integration Examples

This section provides practical examples for integrating with the Danklas API using different programming languages and common workflows.

### Python Client Example

#### Basic Python Client
```python
import requests
import json
from typing import Dict, List, Optional

class DanklasClient:
    def __init__(self, base_url: str, jwt_token: str):
        """
        Initialize Danklas API client.
        
        Args:
            base_url: API base URL (e.g., "https://api.example.com")
            jwt_token: JWT bearer token for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json"
        }
    
    def query_knowledge_base(
        self, 
        kb_id: str, 
        query: str, 
        metadata_filters: Optional[Dict] = None
    ) -> Dict:
        """
        Query a knowledge base.
        
        Args:
            kb_id: Knowledge base identifier
            query: Natural language query
            metadata_filters: Additional metadata filters
            
        Returns:
            Dictionary with 'answer' and 'citations' keys
            
        Raises:
            requests.HTTPError: If API request fails
        """
        url = f"{self.base_url}/knowledge-bases/{kb_id}/query"
        payload = {"query": query}
        
        if metadata_filters:
            payload["metadata_filters"] = metadata_filters
            
        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()
    
    def health_check(self) -> Dict:
        """Check API health status."""
        url = f"{self.base_url}/health"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()

# Usage example
if __name__ == "__main__":
    # Initialize client
    client = DanklasClient(
        base_url="https://your-api.example.com",
        jwt_token="your-jwt-token-here"
    )
    
    # Basic query
    result = client.query_knowledge_base(
        kb_id="kb-acme-corp-docs",
        query="What is our remote work policy?"
    )
    
    print(f"Answer: {result['answer']}")
    print(f"Sources: {result['citations']}")
    
    # Query with filters
    result = client.query_knowledge_base(
        kb_id="kb-acme-corp-docs",
        query="What are the Q1 sales numbers?",
        metadata_filters={
            "document_type": "sales_report",
            "quarter": "Q1"
        }
    )
    
    print(f"Filtered Answer: {result['answer']}")
```

#### Advanced Python Client with Error Handling
```python
import requests
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class QueryResult:
    answer: str
    citations: List[str]
    kb_id: str
    query: str

class DanklasAPIError(Exception):
    """Custom exception for Danklas API errors."""
    def __init__(self, message: str, status_code: int, response_body: str):
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(self.message)

class DanklasClient:
    def __init__(self, base_url: str, jwt_token: str, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json",
            "User-Agent": "DanklasClient/1.0"
        })
        self.logger = logging.getLogger(__name__)
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling."""
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.request(
                method, url, timeout=self.timeout, **kwargs
            )
            
            # Log request details
            self.logger.debug(f"{method} {url} -> {response.status_code}")
            
            if not response.ok:
                error_detail = "Unknown error"
                try:
                    error_data = response.json()
                    error_detail = error_data.get('detail', str(error_data))
                except:
                    error_detail = response.text
                
                raise DanklasAPIError(
                    message=f"API request failed: {error_detail}",
                    status_code=response.status_code,
                    response_body=response.text
                )
            
            return response
            
        except requests.exceptions.Timeout:
            raise DanklasAPIError("Request timeout", 408, "")
        except requests.exceptions.ConnectionError:
            raise DanklasAPIError("Connection error", 503, "")
    
    def query_knowledge_base(
        self, 
        kb_id: str, 
        query: str, 
        metadata_filters: Optional[Dict] = None
    ) -> QueryResult:
        """Query knowledge base with robust error handling."""
        payload = {"query": query}
        if metadata_filters:
            payload["metadata_filters"] = metadata_filters
        
        response = self._make_request(
            "POST", 
            f"/knowledge-bases/{kb_id}/query", 
            json=payload
        )
        
        data = response.json()
        return QueryResult(
            answer=data["answer"],
            citations=data["citations"],
            kb_id=kb_id,
            query=query
        )

# Usage with error handling
client = DanklasClient("https://api.example.com", "your-jwt-token")

try:
    result = client.query_knowledge_base(
        kb_id="kb-acme-corp-docs",
        query="What is our vacation policy?"
    )
    print(f"Answer: {result.answer}")
    
except DanklasAPIError as e:
    if e.status_code == 401:
        print("Authentication failed. Check your JWT token.")
    elif e.status_code == 403:
        print("Access denied. Check your permissions.")
    else:
        print(f"API Error: {e.message}")
```

### JavaScript/Node.js Client Example

```javascript
const axios = require('axios');

class DanklasClient {
    constructor(baseUrl, jwtToken) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.client = axios.create({
            baseURL: this.baseUrl,
            headers: {
                'Authorization': `Bearer ${jwtToken}`,
                'Content-Type': 'application/json'
            },
            timeout: 30000
        });
        
        // Add response interceptor for error handling
        this.client.interceptors.response.use(
            response => response,
            error => {
                if (error.response) {
                    const detail = error.response.data?.detail || 'Unknown error';
                    throw new Error(`API Error (${error.response.status}): ${detail}`);
                } else if (error.request) {
                    throw new Error('Network error: No response received');
                } else {
                    throw new Error(`Request error: ${error.message}`);
                }
            }
        );
    }
    
    async queryKnowledgeBase(kbId, query, metadataFilters = null) {
        const payload = { query };
        if (metadataFilters) {
            payload.metadata_filters = metadataFilters;
        }
        
        const response = await this.client.post(
            `/knowledge-bases/${kbId}/query`,
            payload
        );
        
        return response.data;
    }
    
    async healthCheck() {
        const response = await this.client.get('/health');
        return response.data;
    }
}

// Usage example
async function main() {
    const client = new DanklasClient(
        'https://your-api.example.com',
        'your-jwt-token-here'
    );
    
    try {
        // Basic query
        const result = await client.queryKnowledgeBase(
            'kb-acme-corp-docs',
            'What are our company values?'
        );
        
        console.log(`Answer: ${result.answer}`);
        console.log(`Citations: ${result.citations.join(', ')}`);
        
        // Query with filters
        const filteredResult = await client.queryKnowledgeBase(
            'kb-acme-corp-docs',
            'Show me engineering best practices',
            { 
                document_type: 'best_practices',
                department: 'engineering'
            }
        );
        
        console.log(`Filtered Answer: ${filteredResult.answer}`);
        
    } catch (error) {
        console.error('Error:', error.message);
    }
}

main();
```

### Common Workflow Patterns

#### 1. Multi-Tenant SaaS Integration

```python
class MultiTenantDanklasService:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.clients = {}  # Cache clients by tenant
    
    def get_client_for_tenant(self, tenant_id: str, jwt_token: str) -> DanklasClient:
        """Get or create client for specific tenant."""
        if tenant_id not in self.clients:
            self.clients[tenant_id] = DanklasClient(self.base_url, jwt_token)
        return self.clients[tenant_id]
    
    async def query_for_user(self, user_context: dict, query: str) -> dict:
        """Query knowledge base based on user context."""
        tenant_id = user_context['tenant_id']
        jwt_token = user_context['jwt_token']
        department = user_context.get('department')
        
        client = self.get_client_for_tenant(tenant_id, jwt_token)
        kb_id = f"kb-{tenant_id}-docs"
        
        # Add department filter if available
        filters = {}
        if department:
            filters['department'] = department
            
        return client.query_knowledge_base(kb_id, query, filters)

# Usage
service = MultiTenantDanklasService("https://api.example.com")

user_context = {
    'tenant_id': 'acme-corp',
    'jwt_token': 'user-jwt-token',
    'department': 'sales'
}

result = await service.query_for_user(
    user_context, 
    "What is our pricing strategy?"
)
```

#### 2. Batch Query Processing

```python
import asyncio
import aiohttp
from typing import List, Dict

class BatchQueryProcessor:
    def __init__(self, base_url: str, jwt_token: str):
        self.base_url = base_url
        self.jwt_token = jwt_token
    
    async def process_batch_queries(
        self, 
        queries: List[Dict[str, str]], 
        kb_id: str
    ) -> List[Dict]:
        """Process multiple queries concurrently."""
        async with aiohttp.ClientSession(
            headers={"Authorization": f"Bearer {self.jwt_token}"}
        ) as session:
            tasks = [
                self._query_single(session, kb_id, query_data)
                for query_data in queries
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results
    
    async def _query_single(
        self, 
        session: aiohttp.ClientSession, 
        kb_id: str, 
        query_data: Dict
    ) -> Dict:
        """Execute single query."""
        url = f"{self.base_url}/knowledge-bases/{kb_id}/query"
        
        async with session.post(url, json=query_data) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    'query': query_data['query'],
                    'success': True,
                    'result': data
                }
            else:
                error_text = await response.text()
                return {
                    'query': query_data['query'],
                    'success': False,
                    'error': error_text
                }

# Usage
processor = BatchQueryProcessor("https://api.example.com", "jwt-token")

queries = [
    {"query": "What is our remote work policy?"},
    {"query": "How do I submit expenses?"},
    {"query": "What are the holiday dates?"}
]

results = await processor.process_batch_queries(queries, "kb-acme-corp-docs")

for result in results:
    if result['success']:
        print(f"Q: {result['query']}")
        print(f"A: {result['result']['answer'][:100]}...")
    else:
        print(f"Failed: {result['query']} - {result['error']}")
```

#### 3. Streaming Response Pattern

```python
import json
from typing import Iterator

class StreamingQueryClient:
    def __init__(self, base_url: str, jwt_token: str):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json"
        }
    
    def query_with_streaming_response(
        self, 
        kb_id: str, 
        query: str,
        callback = None
    ) -> Iterator[str]:
        """
        Simulate streaming response by chunking the answer.
        Useful for real-time UI updates.
        """
        # Get full response first
        response = requests.post(
            f"{self.base_url}/knowledge-bases/{kb_id}/query",
            headers=self.headers,
            json={"query": query}
        )
        response.raise_for_status()
        
        data = response.json()
        answer = data['answer']
        
        # Stream answer in chunks
        chunk_size = 50  # Characters per chunk
        for i in range(0, len(answer), chunk_size):
            chunk = answer[i:i + chunk_size]
            if callback:
                callback(chunk)
            yield chunk
        
        # Yield citations at the end
        if data.get('citations'):
            citations_text = f"\n\nSources:\n" + "\n".join(data['citations'])
            if callback:
                callback(citations_text)
            yield citations_text

# Usage for real-time UI updates
def update_ui(chunk: str):
    print(chunk, end='', flush=True)

client = StreamingQueryClient("https://api.example.com", "jwt-token")

for chunk in client.query_with_streaming_response(
    "kb-acme-corp-docs", 
    "What is our company mission?",
    callback=update_ui
):
    # Chunk is already processed by callback
    # Could also update UI here if needed
    pass
```

### Integration Best Practices

#### 1. Token Management
```python
class TokenManager:
    def __init__(self, okta_config: dict):
        self.okta_config = okta_config
        self.cached_token = None
        self.token_expiry = None
    
    def get_valid_token(self) -> str:
        """Get valid JWT token, refreshing if necessary."""
        import time
        
        if (self.cached_token and self.token_expiry and 
            time.time() < self.token_expiry - 300):  # 5 min buffer
            return self.cached_token
        
        # Get new token from Okta
        token_data = self._request_token()
        self.cached_token = token_data['access_token']
        self.token_expiry = time.time() + token_data['expires_in']
        
        return self.cached_token
    
    def _request_token(self) -> dict:
        """Request new token from Okta."""
        # Implementation depends on your Okta setup
        pass

# Usage
token_manager = TokenManager(okta_config)
client = DanklasClient(
    "https://api.example.com", 
    token_manager.get_valid_token()
)
```

#### 2. Retry Logic
```python
import time
import random
from functools import wraps

def retry_with_backoff(max_retries=3, backoff_factor=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except DanklasAPIError as e:
                    if e.status_code in [500, 502, 503, 504] and attempt < max_retries - 1:
                        # Exponential backoff with jitter
                        delay = backoff_factor * (2 ** attempt) + random.uniform(0, 1)
                        time.sleep(delay)
                        continue
                    raise
            return None
        return wrapper
    return decorator

class ResilientDanklasClient(DanklasClient):
    @retry_with_backoff(max_retries=3)
    def query_knowledge_base(self, kb_id: str, query: str, metadata_filters=None):
        return super().query_knowledge_base(kb_id, query, metadata_filters)
```

#### 3. Caching Strategy
```python
import hashlib
import json
from typing import Optional

class CachedDanklasClient(DanklasClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache = {}  # In production, use Redis or similar
        self.cache_ttl = 300  # 5 minutes
    
    def _get_cache_key(self, kb_id: str, query: str, metadata_filters: dict) -> str:
        """Generate cache key for query."""
        cache_data = {
            'kb_id': kb_id,
            'query': query,
            'filters': metadata_filters or {}
        }
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    def query_knowledge_base(
        self, 
        kb_id: str, 
        query: str, 
        metadata_filters: Optional[dict] = None
    ) -> dict:
        """Query with caching."""
        cache_key = self._get_cache_key(kb_id, query, metadata_filters)
        
        # Check cache
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
        
        # Cache miss - make API call
        result = super().query_knowledge_base(kb_id, query, metadata_filters)
        
        # Store in cache
        self.cache[cache_key] = (result, time.time())
        
        return result
```

These examples provide a solid foundation for integrating with the Danklas API across different programming languages and use cases.

## Contributing

1. **Code Formatting**: Use `black` and `isort`
2. **Testing**: All tests must pass with `pytest`
3. **Documentation**: Update CLAUDE.md for architecture changes

## License

Private project - see repository settings for access permissions.