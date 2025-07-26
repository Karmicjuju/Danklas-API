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
from app.rate_limiting import create_limiter, rate_limit_exceeded_handler, get_tenant_limits, tenant_rate_limit, get_usage_stats
from app.guardrails import get_current_guardrail, get_guardrail_info, get_guardrail_manager

# Initialize tracing and guardrails
configure_tracing()
guardrail_manager = get_guardrail_manager()

app = FastAPI(
    title="Danklas API",
    description="Multi-tenant facade for Amazon Bedrock Knowledge Bases",
    version="1.0.0"
)

# Instrument FastAPI with OpenTelemetry
instrument_fastapi(app)

# Initialize rate limiter
limiter = create_limiter()
if limiter:
    from slowapi.middleware import SlowAPIMiddleware
    from slowapi.errors import RateLimitExceeded
    
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

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

# Add new usage stats endpoint for DANK-4.2
@app.get("/usage-stats")
@tenant_rate_limit("status")
async def get_tenant_usage_stats(request: Request):
    """Get current usage statistics for the authenticated tenant."""
    tenant_id = getattr(request.state, "tenant_id", "unknown")
    
    if tenant_id == "unknown":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view usage statistics"
        )
    
    stats = get_usage_stats(tenant_id)
    return {
        "tenant_id": tenant_id,
        "usage_statistics": stats
    }

# Add guardrail information endpoint for DANK-5.1
@app.get("/guardrails/info")
async def get_guardrails_info(request: Request):
    """Get current guardrail configuration information."""
    info = get_guardrail_info()
    return {
        "guardrail_info": info,
        "loaded_at_startup": True,
        "cache_enabled": True
    }

@app.get("/guardrails/config")
async def get_guardrails_config(request: Request):
    """Get full guardrail configuration (admin access)."""
    # Check admin access
    user_roles = getattr(request.state, "roles", [])
    if DANKLAS_ENV != "test" and "admin" not in user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required to view guardrail configuration"
        )
    
    guardrail = get_current_guardrail()
    return {
        "guardrail_configuration": guardrail,
        "metadata": get_guardrail_info()
    }

@app.post("/guardrails/refresh")
async def refresh_guardrails(request: Request):
    """Force refresh guardrail configuration from SSM Parameter Store (admin access)."""
    # Check admin access
    user_roles = getattr(request.state, "roles", [])
    if DANKLAS_ENV != "test" and "admin" not in user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required to refresh guardrails"
        )
    
    try:
        # Force refresh from SSM
        new_guardrail = guardrail_manager.get_guardrail(force_refresh=True)
        new_checksum = guardrail_manager.get_guardrail_checksum()
        
        return {
            "message": "Guardrail configuration refreshed successfully",
            "new_checksum": new_checksum,
            "version": new_guardrail.get("version", "unknown"),
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Failed to refresh guardrails: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh guardrail configuration"
        )


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
@tenant_rate_limit("query")
async def query_knowledge_base(
    request: Request,
    kb_id: str = Path(..., description="Knowledge Base ID"),
    body: QueryRequest = Body(...)
):
    # Apply dynamic rate limiting based on tenant tier
    if limiter:
        limits = get_tenant_limits(request)
        limiter.limit(limits)(lambda: None)()
    
    # Check tenant access to KB
    check_kb_access(request, kb_id, required_roles=["user", "admin", "reader"])
    
    # Get current guardrail configuration
    guardrail = get_current_guardrail()
    guardrail_checksum = guardrail_manager.get_guardrail_checksum()
    
    # Create custom span for KB query operation
    with create_span("bedrock.knowledge_base.query") as span:
        span.set_attribute("kb.id", kb_id)
        span.set_attribute("kb.query", body.query)
        span.set_attribute("kb.has_filters", body.metadata_filters is not None)
        span.set_attribute("kb.tenant_id", getattr(request.state, "tenant_id", "unknown"))
        span.set_attribute("kb.guardrail_checksum", guardrail_checksum)
        
        try:
            # Apply query filters from guardrail
            query_filters = guardrail.get("query_filters", {})
            
            # Check query length limit
            query_limit = query_filters.get("query_length_limit", {})
            if query_limit.get("enabled", False):
                max_chars = query_limit.get("max_chars", 8192)
                if len(body.query) > max_chars:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Query exceeds maximum length of {max_chars} characters"
                    )
            
            # Apply injection detection (basic check)
            injection_detection = query_filters.get("injection_detection", {})
            if injection_detection.get("enabled", False):
                suspicious_patterns = ["<script", "javascript:", "DROP TABLE", "DELETE FROM"]
                query_lower = body.query.lower()
                for pattern in suspicious_patterns:
                    if pattern.lower() in query_lower:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Query contains potentially malicious content"
                        )
            
            # TODO: Call Bedrock RetrieveAndGenerate with guardrail JSON and metadata_filters
            # In real implementation, guardrail would be passed to Bedrock API
            bedrock_config = guardrail.get("bedrock_config", {})
            model_settings = bedrock_config.get("model_settings", {})
            retrieval_config = bedrock_config.get("retrieval_config", {})
            
            # Simulate processing time
            import time
            time.sleep(0.1)
            
            # Mock response with guardrail-filtered content
            response = QueryResponse(
                answer=f"Mock answer for KB {kb_id} and query '{body.query}' (filtered by guardrail {guardrail_checksum[:8]})",
                citations=["doc1.pdf", "doc2.pdf"]
            )
            
            # Apply output filters
            output_filters = guardrail.get("output_filters", {})
            response_limit = output_filters.get("response_length_limit", {})
            if response_limit.get("enabled", False):
                max_tokens = response_limit.get("max_tokens", 4096)
                # In real implementation, this would limit the Bedrock response
                span.set_attribute("kb.response.max_tokens", max_tokens)
            
            span.set_attribute("kb.response.citations_count", len(response.citations))
            span.set_attribute("kb.response.answer_length", len(response.answer))
            span.set_attribute("kb.guardrail_applied", True)
            span.set_status(Status(StatusCode.OK))
            
            return response
        except HTTPException:
            # Re-raise HTTP exceptions (validation errors, etc.)
            raise
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise


class StatusResponse(BaseModel):
    status: str
    lastSyncedAt: str

@app.get("/knowledge-bases/{kb_id}/status", response_model=StatusResponse)
@tenant_rate_limit("status")
async def knowledge_base_status(
    request: Request,
    kb_id: str = Path(..., description="Knowledge Base ID")
):
    # Apply dynamic rate limiting based on tenant tier
    if limiter:
        limits = get_tenant_limits(request)
        limiter.limit(limits)(lambda: None)()
    
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
@tenant_rate_limit("refresh")
async def refresh_knowledge_base(
    request: Request,
    kb_id: str = Path(..., description="Knowledge Base ID")
):
    # Apply dynamic rate limiting based on tenant tier  
    if limiter:
        limits = get_tenant_limits(request)
        limiter.limit(limits)(lambda: None)()
    
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

