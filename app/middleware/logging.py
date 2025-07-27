"""Simplified logging middleware for Danklas API."""

import json
import logging
import time
import uuid
from fastapi import Request

logger = logging.getLogger(__name__)


class JSONLogFormatter(logging.Formatter):
    """Simple JSON log formatter."""
    
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra"):
            log_record.update(record.extra)
        return json.dumps(log_record)


async def log_requests(request: Request, call_next):
    """Simplified request logging middleware."""
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Extract tenant from request state
    tenant = getattr(request.state, "tenant_id", "unauthenticated")
    
    # Log request start
    logger.info(
        "request_started",
        extra={
            "request_id": request_id,
            "tenant": tenant,
            "method": request.method,
            "path": request.url.path,
            "client_ip": request.client.host,
        },
    )

    try:
        response = await call_next(request)
        latency_ms = int((time.time() - start_time) * 1000)
        
        # Log successful request
        logger.info(
            "request_completed",
            extra={
                "request_id": request_id,
                "tenant": tenant,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "latency_ms": latency_ms,
            },
        )
        
        return response
        
    except Exception as e:
        latency_ms = int((time.time() - start_time) * 1000)
        
        # Log failed request
        logger.error(
            f"request_failed: {e}",
            extra={
                "request_id": request_id,
                "tenant": tenant,
                "method": request.method,
                "path": request.url.path,
                "status_code": 500,
                "latency_ms": latency_ms,
                "error": str(e),
            },
        )
        raise