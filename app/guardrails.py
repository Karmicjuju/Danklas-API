"""Simplified guardrails for Danklas API."""

import logging
from typing import Dict, Any

from app.config.settings import GUARDRAILS

logger = logging.getLogger(__name__)


def validate_query(query: str) -> Dict[str, Any]:
    """Validate query against guardrails."""
    validation_result = {
        "valid": True,
        "errors": [],
        "warnings": []
    }
    
    # Check query length
    if len(query) > GUARDRAILS["query_length_limit"]:
        validation_result["valid"] = False
        validation_result["errors"].append(
            f"Query exceeds maximum length of {GUARDRAILS['query_length_limit']} characters"
        )
    
    # Check for suspicious patterns
    if GUARDRAILS["enable_injection_detection"]:
        query_lower = query.lower()
        for pattern in GUARDRAILS["suspicious_patterns"]:
            if pattern.lower() in query_lower:
                validation_result["valid"] = False
                validation_result["errors"].append(
                    "Query contains potentially malicious content"
                )
                break
    
    return validation_result


def get_guardrail_config() -> Dict[str, Any]:
    """Get current guardrail configuration."""
    return GUARDRAILS.copy()


def get_guardrail_info() -> Dict[str, str]:
    """Get guardrail information."""
    return {
        "version": "1.0",
        "description": "Simplified Danklas API guardrails",
        "query_length_limit": str(GUARDRAILS["query_length_limit"]),
        "response_length_limit": str(GUARDRAILS["response_length_limit"]),
        "injection_detection_enabled": str(GUARDRAILS["enable_injection_detection"]),
    }
