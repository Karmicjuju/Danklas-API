"""Simplified authentication middleware for Danklas API."""

import logging
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.jwt import verify_jwt
from app.config.settings import DANKLAS_ENV

logger = logging.getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """Simplified authentication middleware."""
    
    async def dispatch(self, request: Request, call_next):
        public_paths = {"/", "/docs", "/redoc", "/openapi.json", "/favicon.ico", "/health"}
        
        # Skip authentication in test environment
        if DANKLAS_ENV == "test":
            return await call_next(request)
            
        # Allow public access in dev/test for certain paths
        if DANKLAS_ENV in {"dev", "test"} and request.url.path in public_paths:
            logger.warning(
                "Unauthenticated access allowed to %s in %s mode from %s",
                request.url.path,
                DANKLAS_ENV,
                request.client.host,
            )
            return await call_next(request)
            
        # Check for Authorization header
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Authorization header",
            )
            
        # Verify JWT token
        token = auth.split(" ", 1)[1]
        payload = verify_jwt(token)

        # Attach user context to request state
        request.state.user = payload
        request.state.tenant_id = payload["tenant_id"]
        request.state.roles = payload["roles"]

        return await call_next(request)