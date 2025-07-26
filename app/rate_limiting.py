"""Rate limiting and quota management for Danklas API."""

import os
import logging
from typing import Optional, Dict, Any
from fastapi import HTTPException, Request, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import redis
from functools import wraps

logger = logging.getLogger(__name__)

# Rate limiting configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
DANKLAS_ENV = os.getenv("DANKLAS_ENV", "prod")
ENABLE_RATE_LIMITING = os.getenv("ENABLE_RATE_LIMITING", "true" if DANKLAS_ENV == "prod" else "false").lower() == "true"

# Usage tier configurations (DANK-4.2)
USAGE_TIERS = {
    "free": {
        "requests_per_minute": 10,
        "requests_per_hour": 100,
        "requests_per_day": 1000,
        "max_kb_queries": 5,
    },
    "pro": {
        "requests_per_minute": 60,
        "requests_per_hour": 1000,
        "requests_per_day": 10000,
        "max_kb_queries": 50,
    },
    "dank_ultra": {
        "requests_per_minute": 300,
        "requests_per_hour": 10000,
        "requests_per_day": 100000,
        "max_kb_queries": 500,
    }
}

def get_tenant_identifier(request: Request) -> str:
    """Get tenant identifier for rate limiting."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id:
        return f"tenant:{tenant_id}"
    # Fallback to IP-based limiting for unauthenticated requests
    return f"ip:{get_remote_address(request)}"

def get_tenant_tier(request: Request) -> str:
    """Get the usage tier for the current tenant."""
    # In a real implementation, this would query a database or service
    # For now, extract from roles or default to free tier
    user_roles = getattr(request.state, "roles", [])
    
    if "dank_ultra" in user_roles:
        return "dank_ultra"
    elif "pro" in user_roles:
        return "pro"
    else:
        return "free"

def create_limiter() -> Limiter:
    """Create and configure the rate limiter."""
    if not ENABLE_RATE_LIMITING:
        logger.info("Rate limiting disabled")
        return None
    
    try:
        # Try to connect to Redis for distributed rate limiting
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
        
        limiter = Limiter(
            key_func=get_tenant_identifier,
            storage_uri=REDIS_URL,
            default_limits=["1000/day", "100/hour", "10/minute"]  # Fallback limits
        )
        logger.info(f"Rate limiter configured with Redis at {REDIS_URL}")
        return limiter
        
    except Exception as e:
        logger.warning(f"Failed to connect to Redis, falling back to in-memory limiting: {e}")
        
        # Fallback to in-memory rate limiting
        limiter = Limiter(
            key_func=get_tenant_identifier,
            default_limits=["1000/day", "100/hour", "10/minute"]
        )
        logger.info("Rate limiter configured with in-memory storage")
        return limiter

def get_tenant_limits(request: Request) -> str:
    """Get rate limits based on tenant tier."""
    tier = get_tenant_tier(request)
    config = USAGE_TIERS.get(tier, USAGE_TIERS["free"])
    
    # Return limits in slowapi format
    return f"{config['requests_per_day']}/day;{config['requests_per_hour']}/hour;{config['requests_per_minute']}/minute"

def tenant_rate_limit(endpoint_type: str = "general"):
    """
    Decorator for tenant-based rate limiting with tier support.
    
    Args:
        endpoint_type: Type of endpoint (general, query, status, refresh)
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                # If no request found in args, look in kwargs
                request = kwargs.get('request')
            
            if request and ENABLE_RATE_LIMITING:
                tenant_id = getattr(request.state, "tenant_id", "unknown")
                tier = get_tenant_tier(request)
                config = USAGE_TIERS.get(tier, USAGE_TIERS["free"])
                
                # Log rate limit check
                logger.debug(f"Rate limit check - Tenant: {tenant_id}, Tier: {tier}, Endpoint: {endpoint_type}")
                
                # Special handling for KB query endpoints
                if endpoint_type == "query":
                    # Additional quota check for KB queries
                    # In a real implementation, this would check current usage against limits
                    pass
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Custom handler for rate limit exceeded errors."""
    tenant_id = getattr(request.state, "tenant_id", "unknown")
    tier = get_tenant_tier(request)
    
    logger.warning(f"Rate limit exceeded - Tenant: {tenant_id}, Tier: {tier}, Path: {request.url.path}")
    
    response = HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={
            "error": "Rate limit exceeded",
            "message": f"Too many requests for tier '{tier}'. Please upgrade your plan or try again later.",
            "tier": tier,
            "retry_after": exc.retry_after,
            "limits": USAGE_TIERS.get(tier, USAGE_TIERS["free"])
        }
    )
    return response

def get_usage_stats(tenant_id: str) -> Dict[str, Any]:
    """Get current usage statistics for a tenant."""
    # In a real implementation, this would query the rate limiting storage
    # For now, return mock statistics
    return {
        "current_usage": {
            "requests_today": 150,
            "requests_hour": 25,
            "requests_minute": 2,
            "kb_queries": 12
        },
        "limits": USAGE_TIERS["free"],
        "tier": "free",
        "reset_time": "2024-07-26T00:00:00Z"
    } 