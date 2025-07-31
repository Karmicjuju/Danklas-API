import json
import os
import logging
from typing import Dict, Any, Optional
from urllib.request import urlopen
from urllib.error import URLError
import jwt
from jwt import PyJWKClient
import time

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Cache for JWKS client and keys
_jwks_client = None
_last_jwks_refresh = 0
JWKS_CACHE_TTL = 3600  # 1 hour


def get_jwks_client() -> PyJWKClient:
    """Get or create JWKS client with caching."""
    global _jwks_client, _last_jwks_refresh

    current_time = time.time()
    if _jwks_client is None or (current_time - _last_jwks_refresh) > JWKS_CACHE_TTL:
        okta_issuer = os.environ["OKTA_ISSUER"]
        jwks_uri = f"{okta_issuer}/v1/keys"
        _jwks_client = PyJWKClient(jwks_uri, cache_ttl=JWKS_CACHE_TTL)
        _last_jwks_refresh = current_time
        logger.info(f"JWKS client refreshed from {jwks_uri}")

    return _jwks_client


def extract_token_from_event(event: Dict[str, Any]) -> Optional[str]:
    """Extract JWT token from API Gateway event."""
    # Check Authorization header
    headers = event.get("headers", {})
    auth_header = headers.get("Authorization") or headers.get("authorization")

    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove 'Bearer ' prefix

    # Check query parameters as fallback
    query_params = event.get("queryStringParameters") or {}
    return query_params.get("token")


def validate_jwt_token(token: str) -> Dict[str, Any]:
    """Validate JWT token against Okta."""
    try:
        # Get JWKS client
        jwks_client = get_jwks_client()

        # Get the signing key from JWT header
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Decode and validate the token
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=os.environ["OKTA_AUDIENCE"],
            issuer=os.environ["OKTA_ISSUER"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )

        logger.info(f"Token validated successfully for subject: {payload.get('sub')}")
        return payload

    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        raise ValueError(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        raise ValueError(f"Token validation failed: {str(e)}")


def extract_user_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extract user context from JWT payload."""
    # Extract dept_id from various possible claim locations
    dept_id = (
        payload.get("dept_id")
        or payload.get("custom:dept_id")
        or payload.get("deptId")
        or payload.get("org", {}).get("id")
        if isinstance(payload.get("org"), dict)
        else None
    )

    # Extract other user attributes
    user_context = {
        "user_id": payload.get("sub"),
        "email": payload.get("email"),
        "dept_id": dept_id,
        "roles": payload.get("roles", []),
        "department": payload.get("department"),
        "groups": payload.get("groups", []),
        "scope": payload.get("scope", "").split() if payload.get("scope") else [],
    }

    # Add custom claims if they exist
    for key, value in payload.items():
        if key.startswith("custom:"):
            user_context[key] = value

    return user_context


def generate_policy(
    effect: str, resource: str, context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generate IAM policy for API Gateway."""
    policy = {
        "principalId": context.get("user_id", "unknown") if context else "unknown",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}
            ],
        },
    }

    if context:
        # Add context to be passed to the backend
        policy["context"] = {
            str(k): str(v) if v is not None else ""
            for k, v in context.items()
            if isinstance(v, (str, int, float, bool)) or v is None
        }

    return policy


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda authorizer for API Gateway.
    Validates Okta JWT tokens and returns IAM policy.
    """
    try:
        logger.info(f"Authorization request for: {event.get('methodArn')}")

        # Extract token from event
        token = extract_token_from_event(event)
        if not token:
            logger.warning("No token found in request")
            raise ValueError("Authorization token required")

        # Validate token
        payload = validate_jwt_token(token)

        # Extract user context
        user_context = extract_user_context(payload)

        # Validate required claims
        if not user_context.get("dept_id"):
            logger.warning("No dept_id found in token")
            raise ValueError("Department ID is required")

        # Generate allow policy
        policy = generate_policy("Allow", event["methodArn"], user_context)

        logger.info(
            f"Authorization successful for user: {user_context.get('user_id')} in department: {user_context.get('dept_id')}"
        )
        return policy

    except ValueError as e:
        logger.warning(f"Authorization failed: {str(e)}")
        # Return deny policy for validation errors
        return generate_policy("Deny", event.get("methodArn", "*"))

    except Exception as e:
        logger.error(f"Unexpected error in authorizer: {str(e)}")
        # Return deny policy for unexpected errors
        return generate_policy("Deny", event.get("methodArn", "*"))


# For local testing
if __name__ == "__main__":
    # Test event structure
    test_event = {
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/knowledge-bases/kb-123/query",
        "headers": {"Authorization": "Bearer your-test-jwt-token-here"},
    }

    # Set environment variables for testing
    os.environ["OKTA_ISSUER"] = "https://your-okta-domain.okta.com/oauth2/default"
    os.environ["OKTA_AUDIENCE"] = "your-api-audience"

    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))
