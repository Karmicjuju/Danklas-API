"""Simplified in-memory rate limiting for Danklas API."""

import logging
import time
from collections import defaultdict
from typing import Dict, Tuple

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

# In-memory storage for rate limiting
_rate_limit_store: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))


def get_tenant_identifier(request: Request) -> str:
    """Get tenant identifier for rate limiting."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id:
        return f"tenant:{tenant_id}"
    # Fallback to IP-based limiting for unauthenticated requests
    return f"ip:{request.client.host}"


def check_rate_limit(request: Request, limit_type: str = "general") -> bool:
    """Check if request is within rate limits."""
    identifier = get_tenant_identifier(request)
    current_time = time.time()
    
    # Define limits based on type
    limits = {
        "query": {"requests": 60, "window": 60},  # 60 requests per minute
        "status": {"requests": 120, "window": 60},  # 120 requests per minute
        "refresh": {"requests": 10, "window": 60},  # 10 requests per minute
        "general": {"requests": 100, "window": 60},  # 100 requests per minute
    }
    
    limit_config = limits.get(limit_type, limits["general"])
    max_requests = limit_config["requests"]
    window_seconds = limit_config["window"]
    
    # Clean old entries
    cutoff_time = current_time - window_seconds
    _rate_limit_store[identifier][limit_type] = [
        timestamp for timestamp in _rate_limit_store[identifier][limit_type]
        if timestamp > cutoff_time
    ]
    
    # Check if limit exceeded
    if len(_rate_limit_store[identifier][limit_type]) >= max_requests:
        return False
    
    # Add current request
    _rate_limit_store[identifier][limit_type].append(current_time)
    return True


def rate_limit_middleware(limit_type: str = "general"):
    """Simple rate limiting middleware."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract request from args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                for value in kwargs.values():
                    if isinstance(value, Request):
                        request = value
                        break
            
            if request and not check_rate_limit(request, limit_type):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded for {limit_type}",
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def get_usage_stats(tenant_id: str) -> Dict[str, any]:
    """Get usage statistics for a tenant."""
    identifier = f"tenant:{tenant_id}"
    current_time = time.time()
    
    stats = {}
    for limit_type in ["query", "status", "refresh", "general"]:
        # Count requests in last hour
        hour_ago = current_time - 3600
        requests_last_hour = len([
            timestamp for timestamp in _rate_limit_store[identifier][limit_type]
            if timestamp > hour_ago
        ])
        
        # Count requests in last day
        day_ago = current_time - 86400
        requests_last_day = len([
            timestamp for timestamp in _rate_limit_store[identifier][limit_type]
            if timestamp > day_ago
        ])
        
        stats[limit_type] = {
            "requests_last_hour": requests_last_hour,
            "requests_last_day": requests_last_day,
        }
    
    return stats
