"""Knowledge base routes for Danklas API."""

import logging
import time
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, Body, HTTPException, Path, Request, status
from pydantic import BaseModel

from app.guardrails import validate_query
from app.rate_limiting import rate_limit_middleware

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/knowledge-bases", tags=["knowledge-bases"])


class QueryRequest(BaseModel):
    query: str
    metadata_filters: Dict[str, Any] = None


class QueryResponse(BaseModel):
    answer: str
    citations: List[str]


class StatusResponse(BaseModel):
    status: str
    lastSyncedAt: str


class RefreshResponse(BaseModel):
    jobId: str
    message: str


def check_kb_access(
    request: Request, kb_id: str, required_roles: list = None, env: str = None
):
    """Check if tenant has access to knowledge base."""
    if env == "test":
        return True
        
    tenant_id = getattr(request.state, "tenant_id", None)
    user_roles = getattr(request.state, "roles", [])
    
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    
    # Check if user has required roles
    if required_roles:
        has_required_role = any(role in user_roles for role in required_roles)
        if not has_required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {required_roles}",
            )
    
    # In a real implementation, check tenant access to specific KB
    # For now, allow access to any KB
    logger.info(f"Tenant {tenant_id} accessing KB {kb_id}")


@router.post("/{kb_id}/query", response_model=QueryResponse)
@rate_limit_middleware("query")
async def query_knowledge_base(
    request: Request,
    kb_id: str = Path(..., description="Knowledge Base ID"),
    body: QueryRequest = Body(...),
):
    """Query a knowledge base."""
    # Check tenant access to KB
    check_kb_access(request, kb_id, required_roles=["user", "admin", "reader"])
    
    # Validate query against guardrails
    validation = validate_query(body.query)
    if not validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=validation["errors"][0] if validation["errors"] else "Query validation failed"
        )
    
    try:
        # Simulate processing time
        time.sleep(0.1)
        
        # Mock response
        response = QueryResponse(
            answer=f"Mock answer for KB {kb_id} and query '{body.query}'",
            citations=["doc1.pdf", "doc2.pdf"],
        )
        
        logger.info(f"Query processed for KB {kb_id}")
        return response
        
    except Exception as e:
        logger.error(f"Error processing query for KB {kb_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/{kb_id}/status", response_model=StatusResponse)
@rate_limit_middleware("status")
async def knowledge_base_status(
    request: Request, kb_id: str = Path(..., description="Knowledge Base ID")
):
    """Get knowledge base status."""
    # Check tenant access to KB
    check_kb_access(request, kb_id, required_roles=["user", "admin", "reader"])
    
    try:
        # Mock status response
        response = StatusResponse(
            status="READY",
            lastSyncedAt="2024-07-25T12:00:00Z"
        )
        
        logger.info(f"Status retrieved for KB {kb_id}")
        return response
        
    except Exception as e:
        logger.error(f"Error getting status for KB {kb_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/{kb_id}/refresh", response_model=RefreshResponse, status_code=202)
@rate_limit_middleware("refresh")
async def refresh_knowledge_base(
    request: Request, kb_id: str = Path(..., description="Knowledge Base ID")
):
    """Refresh a knowledge base."""
    # Check tenant access to KB
    check_kb_access(request, kb_id, required_roles=["admin"])
    
    try:
        # Mock refresh job
        job_id = f"mock-job-{uuid.uuid4().hex[:8]}"
        response = RefreshResponse(
            jobId=job_id,
            message=f"Refresh started for KB {kb_id}"
        )
        
        logger.info(f"Refresh started for KB {kb_id}, job ID: {job_id}")
        return response
        
    except Exception as e:
        logger.error(f"Error starting refresh for KB {kb_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )