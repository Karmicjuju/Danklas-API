import json
import logging
import os
from functools import lru_cache
from typing import Any, Dict, List

import boto3
import requests
from fastapi import Body, FastAPI, HTTPException, Path, Request, status
from jose import JWTError, jwt
from pydantic import BaseModel
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
    description="Identity-based orchestrator for Amazon Bedrock Knowledge Bases",
    version="2.0.0",
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
        public_paths = {"/", "/docs", "/redoc", "/openapi.json", "/favicon.ico", "/health"}
        
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
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="No tenant context available"
        )

    # Simple check: KB ID should start with tenant ID or be shared
    if not kb_id.startswith(f"kb-{tenant_id}") and not kb_id.startswith("kb-shared"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: KB {kb_id} not accessible by tenant {tenant_id}",
        )


# --- Data Models ---
class QueryRequest(BaseModel):
    query: str
    metadata_filters: Dict[str, Any] = None


class QueryResponse(BaseModel):
    answer: str
    citations: List[str]


# --- Endpoints ---
@app.get("/")
def read_root():
    return {"message": "Danklas API - Identity-based Bedrock orchestrator"}


@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {
        "status": "healthy",
        "environment": DANKLAS_ENV,
        "version": "2.0.0"
    }


@app.post("/knowledge-bases/{kb_id}/query", response_model=QueryResponse)
async def query_knowledge_base(
    request: Request,
    kb_id: str = Path(..., description="Knowledge Base ID"),
    body: QueryRequest = Body(...),
):
    """Query a knowledge base with identity-based filtering and guardrails."""
    
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
        combined_filter = {
            "andAll": [
                metadata_filter,
                body.metadata_filters
            ]
        }
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
                            "guardrailVersion": BEDROCK_GUARDRAIL_VERSION
                        }
                    },
                    "retrievalConfiguration": {
                        "vectorSearchConfiguration": {
                            "filter": metadata_filter
                        }
                    }
                },
                "type": "KNOWLEDGE_BASE"
            }
        )
        
        # Extract response data
        answer = response["output"]["text"]
        citations = [
            cite["retrievedReferences"][0]["location"]["s3Location"]["uri"]
            for cite in response.get("citations", [])
            if cite.get("retrievedReferences")
        ]
        
        logger.info(f"Successfully processed query for tenant: {identity['tenant_id']}, KB: {kb_id}")
        
        return QueryResponse(answer=answer, citations=citations)
        
    except Exception as e:
        logger.error(f"Bedrock API error for tenant {identity['tenant_id']}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process knowledge base query"
        )