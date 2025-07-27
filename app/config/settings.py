"""Simplified configuration management for Danklas API."""

import os
from typing import Dict, Any

# Environment configuration
DANKLAS_ENV = os.getenv("DANKLAS_ENV", "prod")
ENABLE_RATE_LIMITING = os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true"

# Okta OIDC configuration
OKTA_ISSUER = os.getenv("OKTA_ISSUER", "https://YOUR_OKTA_DOMAIN/oauth2/default")
OKTA_AUDIENCE = os.getenv("OKTA_AUDIENCE", "api://default")
OKTA_JWKS_URI = f"{OKTA_ISSUER}/v1/keys"

# Rate limiting configuration
RATE_LIMITS = {
    "requests_per_minute": int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),
    "requests_per_hour": int(os.getenv("RATE_LIMIT_PER_HOUR", "1000")),
    "requests_per_day": int(os.getenv("RATE_LIMIT_PER_DAY", "10000")),
}

# Guardrails configuration (simplified)
GUARDRAILS = {
    "query_length_limit": int(os.getenv("QUERY_LENGTH_LIMIT", "8192")),
    "response_length_limit": int(os.getenv("RESPONSE_LENGTH_LIMIT", "4096")),
    "enable_injection_detection": os.getenv("ENABLE_INJECTION_DETECTION", "true").lower() == "true",
    "suspicious_patterns": [
        "<script",
        "javascript:",
        "DROP TABLE",
        "DELETE FROM",
    ]
}

# Bedrock configuration
BEDROCK_CONFIG = {
    "model_settings": {
        "temperature": float(os.getenv("BEDROCK_TEMPERATURE", "0.1")),
        "top_p": float(os.getenv("BEDROCK_TOP_P", "0.9")),
        "max_tokens": int(os.getenv("BEDROCK_MAX_TOKENS", "2048")),
    },
    "retrieval_config": {
        "number_of_results": int(os.getenv("BEDROCK_RESULTS_COUNT", "5")),
        "search_type": os.getenv("BEDROCK_SEARCH_TYPE", "HYBRID"),
    }
}

def get_config() -> Dict[str, Any]:
    """Get the complete configuration."""
    return {
        "environment": DANKLAS_ENV,
        "rate_limiting": {
            "enabled": ENABLE_RATE_LIMITING,
            "limits": RATE_LIMITS
        },
        "guardrails": GUARDRAILS,
        "bedrock": BEDROCK_CONFIG,
        "auth": {
            "okta_issuer": OKTA_ISSUER,
            "okta_audience": OKTA_AUDIENCE,
            "okta_jwks_uri": OKTA_JWKS_URI
        }
    }