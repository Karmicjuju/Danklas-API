import os
from fastapi import FastAPI, Request, HTTPException, status, Path, Body
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError
import requests
from functools import lru_cache
import logging
from pydantic import BaseModel
from typing import List, Dict, Any
import time
import uuid
import json
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

# Configure tracing before creating app
from app.tracing import configure_tracing, instrument_fastapi, get_tracer, create_span

# Initialize tracing
configure_tracing()

app = FastAPI(
    title="Danklas API",
    description="Multi-tenant facade for Amazon Bedrock Knowledge Bases",
    version="1.0.0"
)

# Instrument FastAPI with OpenTelemetry
instrument_fastapi(app)

# --- Okta OIDC config (replace with your Okta values) ---
OKTA_ISSUER = os.getenv("OKTA_ISSUER", "https://YOUR_OKTA_DOMAIN/oauth2/default")
OKTA_AUDIENCE = os.getenv("OKTA_AUDIENCE", "api://default")
OKTA_JWKS_URI = f"{OKTA_ISSUER}/v1/keys"

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
        tenant_id = payload.get("tenant_id") or payload.get("custom:tenant_id") or payload.get("tenantId")
        roles = payload.get("roles", []) or payload.get("custom:roles", []) or payload.get("groups", [])
        
        # Ensure roles is a list
        if isinstance(roles, str):
            roles = [roles]
        
        # Validate required claims
        if not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Missing tenant_id claim in token"
            )
        
        return {
            "sub": payload.get("sub"),
            "tenant_id": tenant_id,
            "roles": roles,
            "exp": payload.get("exp"),
            "aud": payload.get("aud"),
            "iss": payload.get("iss"),
        }
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")

DANKLAS_ENV = os.getenv("DANKLAS_ENV", "prod")
LOCAL_IPS = {"127.0.0.1", "::1"}

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        public_paths = {"/", "/docs", "/redoc", "/openapi.json", "/favicon.ico"}
        if DANKLAS_ENV == "test":
            return await call_next(request)
        if DANKLAS_ENV in {"dev", "test"} and request.url.path in public_paths:
            logging.warning("Unauthenticated access allowed to %s in %s mode from %s", request.url.path, DANKLAS_ENV, request.client.host)
            return await call_next(request)
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Authorization header")
        token = auth.split(" ", 1)[1]
        payload = verify_jwt(token)
        
        # Attach user context to request state
        request.state.user = payload
        request.state.tenant_id = payload["tenant_id"]
        request.state.roles = payload["roles"]
        
        return await call_next(request)

app.add_middleware(AuthMiddleware)

class JSONLogFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra"):
            log_record.update(record.extra)
        return json.dumps(log_record)

# Configure audit logger for CloudWatch (DANK-3.2)
audit_logger = logging.getLogger("danklas.audit")
audit_handler = logging.StreamHandler()  # In production, this would be CloudWatch handler
audit_handler.setFormatter(JSONLogFormatter())
audit_logger.handlers = [audit_handler]
audit_logger.setLevel(logging.INFO)

# Configure application logger
logger = logging.getLogger("danklas")
handler = logging.StreamHandler()
handler.setFormatter(JSONLogFormatter())
logger.handlers = [handler]
logger.setLevel(logging.INFO)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Get current span and add trace context to logs
    current_span = trace.get_current_span()
    span_context = current_span.get_span_context()
    trace_id = f"{span_context.trace_id:032x}" if span_context.is_valid else "unknown"
    span_id = f"{span_context.span_id:016x}" if span_context.is_valid else "unknown"
    
    # Extract tenant from request state (set by AuthMiddleware)
    tenant = getattr(request.state, "tenant_id", "unauthenticated")
    
    # Add trace context to span attributes
    if current_span.is_recording():
        current_span.set_attribute("http.request_id", request_id)
        current_span.set_attribute("danklas.tenant", tenant)
        current_span.set_attribute("http.client_ip", request.client.host)
    
    # Audit log entry for request start
    audit_logger.info(
        "request_started",
        extra={
            "request_id": request_id,
            "trace_id": trace_id,
            "span_id": span_id,
            "tenant": tenant,
            "method": request.method,
            "path": request.url.path,
            "client_ip": request.client.host,
            "user_agent": request.headers.get("user-agent", ""),
            "audit_type": "request_start"
        }
    )
    
    try:
        response = await call_next(request)
        latency_ms = int((time.time() - start_time) * 1000)
        
        # Add response attributes to span
        if current_span.is_recording():
            current_span.set_attribute("http.status_code", response.status_code)
            current_span.set_attribute("danklas.latency_ms", latency_ms)
            current_span.set_status(Status(StatusCode.OK))
        
        # Application log
        logger.info(
            "request completed",
            extra={
                "request_id": request_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "tenant": tenant,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "latency_ms": latency_ms,
            }
        )
        
        # Audit log entry for successful request
        audit_logger.info(
            "request_completed",
            extra={
                "request_id": request_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "tenant": tenant,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "latency_ms": latency_ms,
                "audit_type": "request_success"
            }
        )
        
        return response
    except Exception as e:
        latency_ms = int((time.time() - start_time) * 1000)
        
        # Add error attributes to span
        if current_span.is_recording():
            current_span.set_attribute("http.status_code", 500)
            current_span.set_attribute("danklas.latency_ms", latency_ms)
            current_span.set_status(Status(StatusCode.ERROR, str(e)))
            current_span.record_exception(e)
        
        # Application log for error
        logger.error(
            f"request failed: {e}",
            extra={
                "request_id": request_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "tenant": tenant,
                "method": request.method,
                "path": request.url.path,
                "status_code": 500,
                "latency_ms": latency_ms,
            }
        )
        
        # Audit log entry for failed request
        audit_logger.error(
            "request_failed",
            extra={
                "request_id": request_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "tenant": tenant,
                "method": request.method,
                "path": request.url.path,
                "status_code": 500,
                "latency_ms": latency_ms,
                "error": str(e),
                "audit_type": "request_failure"
            }
        )
        
        raise

@app.get("/")
def read_root():
    return {"Hello": "World"}


class QueryRequest(BaseModel):
    query: str
    metadata_filters: Dict[str, Any] = None

class QueryResponse(BaseModel):
    answer: str
    citations: List[str]

def check_kb_access(request: Request, kb_id: str, required_roles: list = None, env: str = None):
    """Check if the current user has access to the specified knowledge base."""
    test_env = env or DANKLAS_ENV
    if test_env == "test":
        return  # Skip authorization in test mode
    
    # In a real implementation, this would query a database or service
    # to check if the KB belongs to the user's tenant
    tenant_id = getattr(request.state, "tenant_id", None)
    user_roles = getattr(request.state, "roles", [])
    
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tenant context available"
        )
    
    # Mock KB-tenant mapping validation
    # In production, this would query the actual KB metadata
    if not kb_id.startswith(f"kb-{tenant_id}") and not kb_id.startswith("kb-shared"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: KB {kb_id} not accessible by tenant {tenant_id}"
        )
    
    # Check role-based permissions if required
    if required_roles:
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: requires one of roles {required_roles}"
            )

@app.post("/knowledge-bases/{kb_id}/query", response_model=QueryResponse)
def query_knowledge_base(
    request: Request,
    kb_id: str = Path(..., description="Knowledge Base ID"),
    body: QueryRequest = Body(...)
):
    # Check tenant access to KB
    check_kb_access(request, kb_id, required_roles=["user", "admin", "reader"])
    
    # Create custom span for KB query operation
    with create_span("bedrock.knowledge_base.query") as span:
        span.set_attribute("kb.id", kb_id)
        span.set_attribute("kb.query", body.query)
        span.set_attribute("kb.has_filters", body.metadata_filters is not None)
        span.set_attribute("kb.tenant_id", getattr(request.state, "tenant_id", "unknown"))
        
        try:
            # TODO: Call Bedrock RetrieveAndGenerate with guardrail JSON and metadata_filters
            # Simulate processing time
            import time
            time.sleep(0.1)
            
            # Mock response
            response = QueryResponse(
                answer=f"Mock answer for KB {kb_id} and query '{body.query}'",
                citations=["doc1.pdf", "doc2.pdf"]
            )
            
            span.set_attribute("kb.response.citations_count", len(response.citations))
            span.set_attribute("kb.response.answer_length", len(response.answer))
            span.set_status(Status(StatusCode.OK))
            
            return response
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise


class StatusResponse(BaseModel):
    status: str
    lastSyncedAt: str

@app.get("/knowledge-bases/{kb_id}/status", response_model=StatusResponse)
def knowledge_base_status(
    request: Request,
    kb_id: str = Path(..., description="Knowledge Base ID")
):
    # Check tenant access to KB
    check_kb_access(request, kb_id, required_roles=["user", "admin", "reader"])
    
    # Create custom span for KB status check
    with create_span("bedrock.knowledge_base.status") as span:
        span.set_attribute("kb.id", kb_id)
        span.set_attribute("kb.tenant_id", getattr(request.state, "tenant_id", "unknown"))
        
        try:
            # TODO: Replace with real Bedrock KB status lookup
            response = StatusResponse(status="READY", lastSyncedAt="2024-07-25T12:00:00Z")
            
            span.set_attribute("kb.status", response.status)
            span.set_attribute("kb.last_synced", response.lastSyncedAt)
            span.set_status(Status(StatusCode.OK))
            
            return response
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise


class RefreshResponse(BaseModel):
    jobId: str
    message: str

@app.post("/knowledge-bases/{kb_id}/refresh", response_model=RefreshResponse, status_code=202)
def refresh_knowledge_base(
    request: Request,
    kb_id: str = Path(..., description="Knowledge Base ID")
):
    # Check tenant access to KB (requires admin role for refresh)
    check_kb_access(request, kb_id, required_roles=["admin"])
    
    # Create custom span for KB refresh operation
    with create_span("bedrock.knowledge_base.refresh") as span:
        span.set_attribute("kb.id", kb_id)
        span.set_attribute("kb.tenant_id", getattr(request.state, "tenant_id", "unknown"))
        
        try:
            # TODO: Trigger async KB data sync job
            job_id = f"mock-job-{uuid.uuid4().hex[:8]}"
            response = RefreshResponse(jobId=job_id, message=f"Refresh started for KB {kb_id}")
            
            span.set_attribute("kb.refresh.job_id", job_id)
            span.set_status(Status(StatusCode.OK))
            
            return response
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise

