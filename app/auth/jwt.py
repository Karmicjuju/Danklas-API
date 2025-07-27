"""Simplified JWT authentication for Danklas API."""

import logging
import requests
from functools import lru_cache
from typing import Dict, Any

from fastapi import HTTPException, status
from jose import JWTError, jwt

from app.config.settings import OKTA_JWKS_URI, OKTA_AUDIENCE, OKTA_ISSUER

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_jwks():
    """Get JWKS from Okta (cached)."""
    try:
        resp = requests.get(OKTA_JWKS_URI)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"Failed to fetch JWKS: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable"
        )


def verify_jwt(token: str) -> Dict[str, Any]:
    """Verify JWT token and extract claims."""
    try:
        jwks = get_jwks()
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
            "exp": payload.get("exp"),
            "aud": payload.get("aud"),
            "iss": payload.get("iss"),
        }
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail=f"Invalid token: {e}"
        )