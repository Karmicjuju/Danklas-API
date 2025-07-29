import json
import logging
import os
from functools import lru_cache
from typing import Any, Dict, List

import boto3
import requests
from fastapi import Body, FastAPI, HTTPException, Path, Request, status
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

# --- Environment Configuration ---
DANKLAS_ENV = os.getenv("DANKLAS_ENV", "prod")
OKTA_ISSUER = os.getenv("OKTA_ISSUER", "https://YOUR_OKTA_DOMAIN/oauth2/default")
OKTA_AUDIENCE = os.getenv("OKTA_AUDIENCE", "api://default")
OKTA_JWKS_URI = f"{OKTA_ISSUER}/v1/keys"

# Bedrock configuration
BEDROCK_GUARDRAIL_ID = os.getenv("BEDROCK_GUARDRAIL_ID", "default-guardrail-id")
BEDROCK_GUARDRAIL_VERSION = os.getenv("BEDROCK_GUARDRAIL_VERSION", "1")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Initialize Bedrock client
bedrock_client = boto3.client("bedrock-agent-runtime", region_name=AWS_REGION)

# Initialize FastAPI app
app = FastAPI(
    title="Danklas API",
    description="""
    Identity-based orchestrator for Amazon Bedrock Knowledge Bases
    
    This API provides secure, tenant-isolated access to Amazon Bedrock Knowledge Bases with:
    - **🔐 JWT-based Authentication**: Okta OIDC token validation
    - **🛡️ Automatic Metadata Filtering**: Tenant, role, and department-based access control
    - **🚨 Content Guardrails**: Built-in Bedrock guardrail integration
    - **⚡ Simplified Architecture**: Single endpoint, minimal dependencies
    
    ## Authentication
    
    Include a Bearer token in the Authorization header:
    ```
    Authorization: Bearer <your-jwt-token>
    ```
    
    ## Required JWT Claims
    
    Your JWT token must include:
    - `tenant_id` (or `custom:tenant_id`, `tenantId`): Organization identifier
    - `roles` (or `custom:roles`, `groups`): User roles (e.g., ["user"], ["admin"])
    - `department` (optional): Department for additional filtering
    
    ## Knowledge Base Access
    
    - KB IDs should start with `kb-{tenant_id}-` for tenant-specific access
    - KB IDs starting with `kb-shared-` are accessible to all tenants
    - Admin users see all access levels, regular users only see "general" level documents
    """,
    version="2.0.0",
    contact={
        "name": "Danklas API Support",
        "url": "https://github.com/your-org/danklas-api",
    },
    license_info={
        "name": "Private License",
        "url": "https://github.com/your-org/danklas-api/blob/main/LICENSE",
    },
)

# Basic logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --- JWT Authentication ---
@lru_cache(maxsize=1)
def get_jwks():
    resp = requests.get(OKTA_JWKS_URI)
    resp.raise_for_status()
    return resp.json()


def verify_jwt(token: str):
    jwks = get_jwks()
    try:
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=OKTA_AUDIENCE,
            issuer=OKTA_ISSUER,
            options={"verify_aud": True, "verify_iss": True, "verify_exp": True},
        )

        # Extract tenant_id and roles from claims
        tenant_id = (
            payload.get("tenant_id")
            or payload.get("custom:tenant_id")
            or payload.get("tenantId")
        )
        roles = (
            payload.get("roles", [])
            or payload.get("custom:roles", [])
            or payload.get("groups", [])
        )

        # Ensure roles is a list
        if isinstance(roles, str):
            roles = [roles]

        # Validate required claims
        if not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing tenant_id claim in token",
            )

        return {
            "sub": payload.get("sub"),
            "tenant_id": tenant_id,
            "roles": roles,
            "department": payload.get("department"),
            "exp": payload.get("exp"),
            "aud": payload.get("aud"),
            "iss": payload.get("iss"),
        }
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}"
        )


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip auth for health check and docs
        public_paths = {
            "/",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico",
            "/health",
        }

        # Skip auth in test environment
        if DANKLAS_ENV == "test":
            return await call_next(request)

        if request.url.path in public_paths:
            return await call_next(request)

        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Authorization header",
            )

        token = auth.split(" ", 1)[1]
        payload = verify_jwt(token)

        # Attach user context to request state
        request.state.user = payload
        request.state.tenant_id = payload["tenant_id"]
        request.state.roles = payload["roles"]

        return await call_next(request)


app.add_middleware(AuthMiddleware)


# --- Metadata Filtering ---
def build_metadata_filter(identity: Dict[str, Any], kb_id: str) -> Dict[str, Any]:
    """Build metadata filter based on JWT identity for secure data access."""
    tenant_id = identity["tenant_id"]
    roles = identity["roles"]

    # Base tenant filter - users can only access their tenant's data
    filters = [{"equals": {"key": "tenant_id", "value": tenant_id}}]

    # Add role-based access control
    if "admin" not in roles:
        # Non-admin users only see general access level documents
        filters.append({"equals": {"key": "access_level", "value": "general"}})

    # Add department-based filtering if department is specified
    if department := identity.get("department"):
        filters.append({"equals": {"key": "department", "value": department}})

    # Additional KB-specific filtering could go here
    # e.g., filters based on the specific knowledge base ID

    return {"andAll": filters}


def check_kb_access(request: Request, kb_id: str):
    """Basic access control for knowledge base."""
    if DANKLAS_ENV == "test":
        return

    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="No tenant context available"
        )

    # Simple check: KB ID should start with tenant ID or be shared
    if not kb_id.startswith(f"kb-{tenant_id}") and not kb_id.startswith("kb-shared"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: KB {kb_id} not accessible by tenant {tenant_id}",
        )


# --- Data Models ---
class QueryRequest(BaseModel):
    """Request model for knowledge base queries."""
    
    query: str = Field(
        ..., 
        description="The question or query to ask the knowledge base",
        example="What are the latest product features for enterprise customers?",
        min_length=1,
        max_length=2000
    )
    metadata_filters: Dict[str, Any] = Field(
        default=None,
        description="Additional metadata filters to apply (combined with identity-based filters)",
        example={
            "document_type": "product_docs",
            "created_date": {"gte": "2024-01-01"}
        }
    )

    class Config:
        schema_extra = {
            "example": {
                "query": "What are the latest product features for enterprise customers?",
                "metadata_filters": {
                    "document_type": "product_docs",
                    "access_level": "premium"
                }
            }
        }


class QueryResponse(BaseModel):
    """Response model for knowledge base queries."""
    
    answer: str = Field(
        ..., 
        description="The generated answer from the knowledge base",
        example="Based on the latest product documentation, our enterprise features include..."
    )
    citations: List[str] = Field(
        ...,
        description="List of source document URIs that were used to generate the answer", 
        example=[
            "s3://your-bucket/enterprise-docs/features-2024.pdf",
            "s3://your-bucket/product-docs/changelog-q1.pdf"
        ]
    )

    class Config:
        schema_extra = {
            "example": {
                "answer": "Based on the latest product documentation, our enterprise features include advanced analytics, custom integrations, and dedicated support. These features are designed for organizations with complex requirements...",
                "citations": [
                    "s3://your-bucket/enterprise-docs/features-2024.pdf",
                    "s3://your-bucket/product-docs/changelog-q1.pdf"
                ]
            }
        }


# --- Endpoints ---
@app.get(
    "/",
    summary="API Root",
    description="Returns basic API information and status",
    response_description="API welcome message and description",
    tags=["General"]
)
def read_root():
    """Get basic API information."""
    return {
        "message": "Danklas API - Identity-based Bedrock orchestrator",
        "version": "2.0.0",
        "documentation": "/docs",
        "health": "/health"
    }


@app.get(
    "/health",
    summary="Health Check",
    description="Check API health status and environment information",
    response_description="Health status, environment, and version information",
    tags=["General"]
)
async def health_check():
    """
    Health check endpoint for monitoring and load balancer checks.
    
    Returns:
    - status: Always 'healthy' if API is running
    - environment: Current environment (dev/test/prod)
    - version: API version
    """
    return {"status": "healthy", "environment": DANKLAS_ENV, "version": "2.0.0"}


@app.post(
    "/knowledge-bases/{kb_id}/query",
    response_model=QueryResponse,
    summary="Query Knowledge Base",
    description="Query a knowledge base with automatic identity-based filtering and content guardrails",
    response_description="Answer and citations from the knowledge base",
    tags=["Knowledge Base"],
    responses={
        200: {
            "description": "Successful query response",
            "content": {
                "application/json": {
                    "example": {
                        "answer": "Based on the latest product documentation, our enterprise features include advanced analytics, custom integrations, and dedicated support.",
                        "citations": [
                            "s3://your-bucket/enterprise-docs/features-2024.pdf",
                            "s3://your-bucket/product-docs/changelog-q1.pdf"
                        ]
                    }
                }
            }
        },
        401: {"description": "Missing or invalid JWT token"},
        403: {"description": "Access denied to knowledge base or insufficient permissions"},
        422: {"description": "Invalid request format or missing required fields"},
        500: {"description": "Internal server error or Bedrock API failure"}
    }
)
async def query_knowledge_base(
    request: Request,
    kb_id: str = Path(
        ..., 
        description="Knowledge Base ID (must start with 'kb-{tenant_id}-' or 'kb-shared-')",
        example="kb-acme-corp-docs",
        regex=r"^kb-[a-zA-Z0-9\-]+$"
    ),
    body: QueryRequest = Body(...),
):
    """
    Query a knowledge base with automatic identity-based security filtering.
    
    ## Security Features
    
    - **Authentication**: Requires valid JWT Bearer token
    - **Tenant Isolation**: Users only access their organization's data
    - **Role-Based Access**: Admin users see all documents, regular users see only "general" level
    - **Department Filtering**: Optional department-based document filtering
    - **Content Guardrails**: Built-in Bedrock guardrails for content safety
    
    ## Metadata Filtering
    
    The API automatically applies security filters based on your JWT token:
    - `tenant_id`: Matches your organization
    - `access_level`: "general" for regular users, all levels for admins
    - `department`: Your department (if specified in token)
    
    Additional user-provided filters are combined with these security filters.
    
    ## Knowledge Base Access
    
    - KB IDs starting with `kb-{your-tenant-id}-` are accessible to your tenant
    - KB IDs starting with `kb-shared-` are accessible to all tenants
    - Other KB IDs will return 403 Forbidden
    
    ## Example Usage
    
    ```bash
    curl -X POST "https://api.example.com/knowledge-bases/kb-acme-corp-docs/query" \\
         -H "Authorization: Bearer your-jwt-token" \\
         -H "Content-Type: application/json" \\
         -d '{
           "query": "What are the latest product features?",
           "metadata_filters": {
             "document_type": "product_docs"
           }
         }'
    ```
    """

    # Check access to the knowledge base
    check_kb_access(request, kb_id)

    # Extract identity context
    identity = {
        "tenant_id": request.state.tenant_id,
        "roles": request.state.roles,
        "sub": request.state.user["sub"],
        "department": request.state.user.get("department"),
    }

    # Build metadata filter based on identity
    metadata_filter = build_metadata_filter(identity, kb_id)

    # Merge with any additional user-provided filters
    if body.metadata_filters:
        # Combine user filters with identity-based security filters
        combined_filter = {"andAll": [metadata_filter, body.metadata_filters]}
        metadata_filter = combined_filter

    try:
        # Call Bedrock RetrieveAndGenerate API
        response = bedrock_client.retrieve_and_generate(
            input={"text": body.query},
            retrieveAndGenerateConfiguration={
                "knowledgeBaseConfiguration": {
                    "knowledgeBaseId": kb_id,
                    "modelArn": f"arn:aws:bedrock:{AWS_REGION}::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0",
                    "generationConfiguration": {
                        "guardrailConfiguration": {
                            "guardrailId": BEDROCK_GUARDRAIL_ID,
                            "guardrailVersion": BEDROCK_GUARDRAIL_VERSION,
                        }
                    },
                    "retrievalConfiguration": {
                        "vectorSearchConfiguration": {"filter": metadata_filter}
                    },
                },
                "type": "KNOWLEDGE_BASE",
            },
        )

        # Extract response data
        answer = response["output"]["text"]
        citations = [
            cite["retrievedReferences"][0]["location"]["s3Location"]["uri"]
            for cite in response.get("citations", [])
            if cite.get("retrievedReferences")
        ]

        logger.info(
            f"Successfully processed query for tenant: {identity['tenant_id']}, KB: {kb_id}"
        )

        return QueryResponse(answer=answer, citations=citations)

    except Exception as e:
        logger.error(f"Bedrock API error for tenant {identity['tenant_id']}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process knowledge base query",
        )
