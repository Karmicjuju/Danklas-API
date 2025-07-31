import json
import logging
import os
from functools import lru_cache
from typing import Any, Dict, List

import boto3
import requests

# AWS X-Ray tracing
from aws_xray_sdk.core import patch_all, xray_recorder
from fastapi import Body, FastAPI, HTTPException, Path, Request, status
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

# Configuration
DANKLAS_ENV = os.getenv("DANKLAS_ENV", "prod")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Okta OIDC
OKTA_ISSUER = os.getenv("OKTA_ISSUER", "https://YOUR_OKTA_DOMAIN/oauth2/default")
OKTA_AUDIENCE = os.getenv("OKTA_AUDIENCE", "api://default")
OKTA_JWKS_URI = f"{OKTA_ISSUER}/v1/keys"

# AWS Services
BEDROCK_GUARDRAIL_ID = os.getenv("BEDROCK_GUARDRAIL_ID", "default-guardrail-id")
BEDROCK_GUARDRAIL_VERSION = os.getenv("BEDROCK_GUARDRAIL_VERSION", "1")
AVP_POLICY_STORE_ID = os.getenv("AVP_POLICY_STORE_ID", "default-policy-store")

# X-Ray Configuration
XRAY_SERVICE_NAME = os.getenv("XRAY_SERVICE_NAME", "danklas-api")

# Configure X-Ray
if DANKLAS_ENV != "test":
    # Auto-instrument AWS services (boto3, requests, etc.)
    patch_all()
    # Configure X-Ray recorder
    xray_recorder.configure(
        service=XRAY_SERVICE_NAME,
        dynamic_naming=f"*{XRAY_SERVICE_NAME}*",
        plugins=("EC2Plugin", "ECSPlugin"),
    )

# Initialize clients and app
bedrock_client = boto3.client("bedrock-agent-runtime", region_name=AWS_REGION)
avp_client = boto3.client("verifiedpermissions", region_name=AWS_REGION)
app = FastAPI(title="Danklas API", version="2.0.0")

# CloudWatch structured logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def log_structured(level: str, message: str, **context):
    """Log structured JSON for CloudWatch parsing with X-Ray trace correlation."""
    from datetime import datetime, timezone

    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "service": "danklas-api",
        "environment": DANKLAS_ENV,
        "message": message,
        **context,
    }

    # Add X-Ray trace correlation (only in non-test environments)
    if DANKLAS_ENV != "test":
        try:
            trace_entity = xray_recorder.get_trace_entity()
            if trace_entity:
                log_data["trace_id"] = trace_entity.trace_id
                if hasattr(trace_entity, "id"):
                    log_data["span_id"] = trace_entity.id
        except:
            pass  # Ignore X-Ray errors in logging

    getattr(logger, level.lower())(json.dumps(log_data))


# Log service startup
log_structured("info", "Danklas API starting", version="2.0.0", region=AWS_REGION)


# JWT Authentication
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

        # Extract dept_id and roles from claims
        dept_id = (
            payload.get("dept_id")
            or payload.get("custom:dept_id")
            or payload.get("deptId")
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
        if not dept_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing dept_id claim in token",
            )

        return {
            "sub": payload.get("sub"),
            "dept_id": dept_id,
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
        request.state.dept_id = payload["dept_id"]
        request.state.roles = payload["roles"]

        return await call_next(request)


app.add_middleware(AuthMiddleware)


# X-Ray middleware for FastAPI
class XrayMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if DANKLAS_ENV == "test":
            return await call_next(request)

        # Start X-Ray segment
        segment_name = f"{XRAY_SERVICE_NAME}::{request.method}_{request.url.path}"
        with xray_recorder.in_segment(segment_name) as segment:
            if segment:
                segment.put_http_meta(
                    "request",
                    {
                        "method": request.method,
                        "url": str(request.url),
                        "user_agent": request.headers.get("user-agent", ""),
                    },
                )

            response = await call_next(request)

            if segment:
                segment.put_http_meta(
                    "response",
                    {
                        "status": response.status_code,
                    },
                )

            return response


# Add X-Ray middleware (skip in test environment)
if DANKLAS_ENV != "test":
    app.add_middleware(XrayMiddleware)


# Helper Functions
def get_identity(request: Request) -> Dict[str, Any]:
    """Extract identity context from authenticated request."""
    return {
        "sub": request.state.user["sub"],
        "dept_id": request.state.dept_id,
        "roles": request.state.roles,
        "department": request.state.user.get("department"),
    }


# Authorization
def check_authorization(identity: Dict[str, Any], action: str, resource: str) -> None:
    """
    Check authorization using AWS Verified Permissions and raise exception if denied.

    Args:
        identity: User identity information (from JWT)
        action: The action being performed (e.g., "query", "read")
        resource: The resource being accessed (e.g., "KnowledgeBase::kb-tenant-123")

    Raises:
        HTTPException: If authorization is denied or check fails
    """
    # Skip AVP check in test environment
    if DANKLAS_ENV == "test":
        return

    # Create X-Ray subsegment for authorization check
    with xray_recorder.in_subsegment("avp_authorization") as subsegment:
        if subsegment:
            subsegment.put_metadata("user_id", identity["sub"])
            subsegment.put_metadata("dept_id", identity["dept_id"])
            subsegment.put_metadata("action", action)
            subsegment.put_metadata("resource", resource)

        try:
            # Build AVP request context
            context = {
                "contextMap": {
                    "dept_id": {"string": identity["dept_id"]},
                    "roles": {"list": [{"string": role} for role in identity["roles"]]},
                }
            }

            if identity.get("department"):
                context["contextMap"]["department"] = {"string": identity["department"]}

            # Make authorization decision request
            response = avp_client.is_authorized(
                policyStoreId=AVP_POLICY_STORE_ID,
                principal={"entityType": "User", "entityId": identity["sub"]},
                action={"actionType": "DanklasAPI::Action", "actionId": action},
                resource={"entityType": "DanklasAPI::Resource", "entityId": resource},
                context=context,
            )

            if response["decision"] != "ALLOW":
                if subsegment:
                    subsegment.put_annotation("decision", "DENY")
                log_structured(
                    "warning",
                    "AVP authorization denied",
                    user_id=identity["sub"],
                    dept_id=identity["dept_id"],
                    action=action,
                    resource=resource,
                    determining_policies=response.get("determiningPolicies", []),
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied by authorization policy",
                )

            if subsegment:
                subsegment.put_annotation("decision", "ALLOW")
            log_structured(
                "info",
                "AVP authorization allowed",
                user_id=identity["sub"],
                dept_id=identity["dept_id"],
                action=action,
                resource=resource,
            )

        except HTTPException:
            raise  # Re-raise HTTP exceptions
        except Exception as e:
            if subsegment:
                subsegment.put_annotation("error", True)
            log_structured(
                "error",
                "AVP authorization check failed",
                user_id=identity["sub"],
                dept_id=identity["dept_id"],
                action=action,
                resource=resource,
                error=str(e),
            )
            # Fail closed - deny access if AVP check fails
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied by authorization policy",
            )


# Metadata Filtering
def build_metadata_filter(identity: Dict[str, Any], kb_id: str) -> Dict[str, Any]:
    """Build metadata filter based on JWT identity for secure data access."""
    dept_id = identity["dept_id"]
    roles = identity["roles"]

    # Base department filter - users can only access their department's data
    filters = [{"equals": {"key": "dept_id", "value": dept_id}}]

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


# Data Models
class QueryRequest(BaseModel):
    """Request model for knowledge base queries."""

    query: str = Field(..., min_length=1, max_length=2000)
    metadata_filters: Dict[str, Any] = None


class QueryResponse(BaseModel):
    """Response model for knowledge base queries."""

    answer: str
    citations: List[str]


class RefreshResponse(BaseModel):
    """Response model for knowledge base refresh operations."""

    job_id: str
    status: str
    message: str


class KnowledgeBase(BaseModel):
    """Knowledge base information."""

    knowledge_base_id: str
    name: str


class KnowledgeBaseListResponse(BaseModel):
    """Response model for knowledge base listing."""

    knowledge_bases: List[KnowledgeBase]
    total_count: int


# Endpoints
@app.get(
    "/",
    summary="API Root",
    description="Returns basic API information and status",
    response_description="API welcome message and description",
    tags=["General"],
)
async def read_root(request: Request):
    """Get basic API information."""
    if hasattr(request.state, "user"):
        check_authorization(get_identity(request), "read", "ApiInfo")

    return {
        "message": "Danklas API - Identity-based Bedrock orchestrator",
        "version": "2.0.0",
        "documentation": "/docs",
        "health": "/health",
    }


@app.get(
    "/health",
    summary="Health Check",
    description="Check API health status and environment information",
    response_description="Health status, environment, and version information",
    tags=["General"],
)
async def health_check(request: Request):
    """Health check endpoint for monitoring and load balancer checks."""
    if hasattr(request.state, "user"):
        check_authorization(get_identity(request), "read", "HealthStatus")

    return {"status": "healthy", "environment": DANKLAS_ENV, "version": "2.0.0"}


@app.post("/knowledge-bases/{kb_id}/query", response_model=QueryResponse)
async def query_knowledge_base(
    request: Request,
    kb_id: str = Path(..., pattern=r"^kb-[a-zA-Z0-9\-]+$"),
    body: QueryRequest = Body(...),
):
    """
    Query a knowledge base with identity-based filtering and content guardrails.

    Requires JWT authentication. Users can only access their department's data.
    Admin users see all documents, regular users see only "general" level.
    User-provided metadata filters are combined with automatic security filters.
    """

    # Check authorization and extract identity
    identity = get_identity(request)
    check_authorization(identity, "query", f"KnowledgeBase::{kb_id}")

    # Build metadata filter based on identity
    metadata_filter = build_metadata_filter(identity, kb_id)

    # Merge with any additional user-provided filters
    if body.metadata_filters:
        # Combine user filters with identity-based security filters
        combined_filter = {"andAll": [metadata_filter, body.metadata_filters]}
        metadata_filter = combined_filter

    try:
        # Create X-Ray subsegment for Bedrock query
        with xray_recorder.in_subsegment("bedrock_query") as subsegment:
            if subsegment:
                subsegment.put_metadata("kb_id", kb_id)
                subsegment.put_metadata("dept_id", identity["dept_id"])
                subsegment.put_metadata("user_id", identity["sub"])

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

            if subsegment:
                subsegment.put_annotation("citations_count", len(citations))
                subsegment.put_annotation("success", True)

            log_structured(
                "info",
                "Knowledge base query successful",
                user_id=identity["sub"],
                dept_id=identity["dept_id"],
                kb_id=kb_id,
                citations_count=len(citations),
            )

            return QueryResponse(answer=answer, citations=citations)

    except Exception as e:
        log_structured(
            "error",
            "Knowledge base query failed",
            user_id=identity["sub"],
            dept_id=identity["dept_id"],
            kb_id=kb_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process knowledge base query",
        )


@app.post("/knowledge-bases/{kb_id}/refresh", response_model=RefreshResponse)
async def refresh_knowledge_base(
    request: Request,
    kb_id: str = Path(..., pattern=r"^kb-[a-zA-Z0-9\-]+$"),
):
    """
    Start an ingestion job to refresh the knowledge base with latest data sources.

    Requires JWT authentication and appropriate permissions. Triggers a Bedrock
    ingestion job that processes new, modified, or deleted documents and updates
    the vector store. Returns job_id for tracking progress.
    """

    # Check authorization and extract identity
    identity = get_identity(request)
    check_authorization(identity, "refresh", f"KnowledgeBase::{kb_id}")

    try:
        # Start ingestion job using Bedrock
        response = bedrock_client.start_ingestion_job(
            knowledgeBaseId=kb_id,
            dataSourceId=f"{kb_id}-datasource",  # Assumes standard naming convention
            description=f"Refresh job initiated by user {identity['sub']} from department {identity['dept_id']}",
        )

        job_id = response["ingestionJob"]["ingestionJobId"]
        status_value = response["ingestionJob"]["status"]

        log_structured(
            "info",
            "Knowledge base refresh initiated",
            user_id=identity["sub"],
            dept_id=identity["dept_id"],
            kb_id=kb_id,
            job_id=job_id,
            job_status=status_value,
        )

        return RefreshResponse(
            job_id=job_id,
            status=status_value,
            message="Knowledge base refresh initiated successfully",
        )

    except bedrock_client.exceptions.ConflictException:
        log_structured(
            "warning",
            "Knowledge base refresh conflict",
            user_id=identity["sub"],
            dept_id=identity["dept_id"],
            kb_id=kb_id,
            reason="job_already_running",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Another ingestion job is already running for this knowledge base",
        )
    except Exception as e:
        log_structured(
            "error",
            "Knowledge base refresh failed",
            user_id=identity["sub"],
            dept_id=identity["dept_id"],
            kb_id=kb_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start knowledge base refresh",
        )


@app.get("/knowledge-bases", response_model=KnowledgeBaseListResponse)
async def list_knowledge_bases(request: Request):
    """List all knowledge bases accessible to the authenticated user."""
    identity = get_identity(request)
    check_authorization(identity, "list", "KnowledgeBase")

    with xray_recorder.in_subsegment("list_knowledge_bases") as subsegment:
        if subsegment:
            subsegment.put_metadata("dept_id", identity["dept_id"])
            subsegment.put_metadata("user_id", identity["sub"])

        try:
            # Get all knowledge bases with pagination
            response = bedrock_client.list_knowledge_bases(maxResults=100)
            all_kbs = response.get("knowledgeBaseSummaries", [])

            while response.get("nextToken"):
                response = bedrock_client.list_knowledge_bases(
                    maxResults=100, nextToken=response["nextToken"]
                )
                all_kbs.extend(response.get("knowledgeBaseSummaries", []))

            # Filter KBs based on user access
            accessible_kbs = []
            for kb in all_kbs:
                try:
                    check_authorization(
                        identity, "query", f"KnowledgeBase::{kb['knowledgeBaseId']}"
                    )
                    accessible_kbs.append(
                        KnowledgeBase(
                            knowledge_base_id=kb["knowledgeBaseId"], name=kb["name"]
                        )
                    )
                except HTTPException:
                    continue

            if subsegment:
                subsegment.put_annotation("accessible_kbs", len(accessible_kbs))

            log_structured(
                "info",
                "Knowledge base list retrieved",
                user_id=identity["sub"],
                dept_id=identity["dept_id"],
                accessible_kbs=len(accessible_kbs),
            )

            return KnowledgeBaseListResponse(
                knowledge_bases=accessible_kbs, total_count=len(accessible_kbs)
            )

        except Exception as e:
            log_structured(
                "error",
                "Knowledge base list failed",
                user_id=identity["sub"],
                dept_id=identity["dept_id"],
                error=str(e),
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve knowledge base list",
            )
