import os
from unittest.mock import Mock, patch

# Set environment before importing the app
os.environ["DANKLAS_ENV"] = "test"

import pytest
from fastapi.testclient import TestClient

from app.main import app, build_metadata_filter, check_kb_access

client = TestClient(app)


@pytest.fixture
def test_client():
    return client


@pytest.fixture
def mock_bedrock_response():
    """Mock response from Bedrock RetrieveAndGenerate API"""
    return {
        "output": {"text": "This is a test answer from Bedrock."},
        "citations": [
            {
                "retrievedReferences": [
                    {"location": {"s3Location": {"uri": "s3://bucket/document1.pdf"}}}
                ]
            },
            {
                "retrievedReferences": [
                    {"location": {"s3Location": {"uri": "s3://bucket/document2.pdf"}}}
                ]
            },
        ],
    }


# Basic endpoint tests
def test_health_check(test_client):
    """Test the health check endpoint."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["environment"] == "test"
    assert data["version"] == "2.0.0"


def test_root_endpoint(test_client):
    """Test the root endpoint."""
    response = test_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "orchestrator" in data["message"]


# Query endpoint tests
@patch("app.main.bedrock_client")
def test_query_knowledge_base_success(
    mock_bedrock_client, test_client, mock_bedrock_response
):
    """Test successful knowledge base query."""
    mock_bedrock_client.retrieve_and_generate.return_value = mock_bedrock_response

    kb_id = "kb-test-tenant-123"
    payload = {"query": "What is machine learning?"}

    # Mock the request state since we're in test environment
    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123",
                "tenant_id": "test-tenant",
                "roles": ["user"],
                "department": None,
                "exp": 9999999999,
                "aud": "api://default",
                "iss": "https://test.okta.com",
            }

            headers = {"Authorization": "Bearer mock-token"}
            response = test_client.post(
                f"/knowledge-bases/{kb_id}/query", json=payload, headers=headers
            )

    assert response.status_code == 200

    data = response.json()
    assert "answer" in data
    assert "citations" in data
    assert data["answer"] == "This is a test answer from Bedrock."
    assert len(data["citations"]) == 2
    assert "s3://bucket/document1.pdf" in data["citations"]


@patch("app.main.bedrock_client")
def test_query_knowledge_base_with_metadata_filters(
    mock_bedrock_client, test_client, mock_bedrock_response
):
    """Test knowledge base query with additional metadata filters."""
    mock_bedrock_client.retrieve_and_generate.return_value = mock_bedrock_response

    kb_id = "kb-test-tenant-123"
    payload = {
        "query": "What is machine learning?",
        "metadata_filters": {"document_type": "tutorial"},
    }

    # Mock the request state since we're in test environment
    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123",
                "tenant_id": "test-tenant",
                "roles": ["user"],
                "department": "engineering",
                "exp": 9999999999,
                "aud": "api://default",
                "iss": "https://test.okta.com",
            }

            headers = {"Authorization": "Bearer mock-token"}
            response = test_client.post(
                f"/knowledge-bases/{kb_id}/query", json=payload, headers=headers
            )

    assert response.status_code == 200

    # Verify that bedrock client was called with combined filters
    mock_bedrock_client.retrieve_and_generate.assert_called_once()
    call_args = mock_bedrock_client.retrieve_and_generate.call_args[1]

    # Check that the filter includes both identity-based and user-provided filters
    filter_config = call_args["retrieveAndGenerateConfiguration"][
        "knowledgeBaseConfiguration"
    ]["retrievalConfiguration"]["vectorSearchConfiguration"]["filter"]
    assert "andAll" in filter_config


def test_query_knowledge_base_missing_query(test_client):
    """Test query endpoint with missing query field."""
    kb_id = "kb-test-tenant-123"
    payload = {"metadata_filters": {"type": "pdf"}}

    response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert (
        response.status_code == 422
    )  # Unprocessable Entity due to missing required field


@patch("app.main.bedrock_client")
def test_query_knowledge_base_bedrock_error(mock_bedrock_client, test_client):
    """Test handling of Bedrock API errors."""
    mock_bedrock_client.retrieve_and_generate.side_effect = Exception(
        "Bedrock API error"
    )

    kb_id = "kb-test-tenant-123"
    payload = {"query": "What is machine learning?"}

    # Mock the request state since we're in test environment
    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123",
                "tenant_id": "test-tenant",
                "roles": ["user"],
                "department": None,
                "exp": 9999999999,
                "aud": "api://default",
                "iss": "https://test.okta.com",
            }

            headers = {"Authorization": "Bearer mock-token"}
            response = test_client.post(
                f"/knowledge-bases/{kb_id}/query", json=payload, headers=headers
            )

    assert response.status_code == 500

    data = response.json()
    assert "Failed to process knowledge base query" in data["detail"]


# Metadata filtering tests
def test_build_metadata_filter_basic():
    """Test basic metadata filter construction."""
    identity = {"tenant_id": "acme-corp", "roles": ["user"], "sub": "user123"}

    result = build_metadata_filter(identity, "kb-acme-corp-docs")

    assert "andAll" in result
    filters = result["andAll"]

    # Should have tenant filter
    tenant_filter = next(
        f for f in filters if f.get("equals", {}).get("key") == "tenant_id"
    )
    assert tenant_filter["equals"]["value"] == "acme-corp"

    # Should have access level filter for non-admin
    access_filter = next(
        f for f in filters if f.get("equals", {}).get("key") == "access_level"
    )
    assert access_filter["equals"]["value"] == "general"


def test_build_metadata_filter_admin():
    """Test metadata filter for admin users."""
    identity = {"tenant_id": "acme-corp", "roles": ["admin"], "sub": "admin123"}

    result = build_metadata_filter(identity, "kb-acme-corp-docs")

    filters = result["andAll"]

    # Should have tenant filter
    tenant_filter = next(
        f for f in filters if f.get("equals", {}).get("key") == "tenant_id"
    )
    assert tenant_filter["equals"]["value"] == "acme-corp"

    # Should NOT have access level filter for admin
    access_filters = [
        f for f in filters if f.get("equals", {}).get("key") == "access_level"
    ]
    assert len(access_filters) == 0


def test_build_metadata_filter_with_department():
    """Test metadata filter with department information."""
    identity = {
        "tenant_id": "acme-corp",
        "roles": ["user"],
        "sub": "user123",
        "department": "engineering",
    }

    result = build_metadata_filter(identity, "kb-acme-corp-docs")

    filters = result["andAll"]

    # Should have department filter
    dept_filter = next(
        f for f in filters if f.get("equals", {}).get("key") == "department"
    )
    assert dept_filter["equals"]["value"] == "engineering"


# Access control tests
def test_check_kb_access_valid():
    """Test valid KB access check."""
    request = Mock()
    request.state.tenant_id = "acme-corp"

    # Should not raise exception for valid access
    try:
        check_kb_access(request, "kb-acme-corp-documents")
    except Exception:
        pytest.fail("Valid KB access should not raise exception")


def test_check_kb_access_shared():
    """Test access to shared KB."""
    request = Mock()
    request.state.tenant_id = "acme-corp"

    # Should not raise exception for shared KB
    try:
        check_kb_access(request, "kb-shared-public")
    except Exception:
        pytest.fail("Access to shared KB should not raise exception")


def test_check_kb_access_invalid():
    """Test invalid KB access check."""
    from fastapi import HTTPException

    request = Mock()
    request.state.tenant_id = "acme-corp"

    # Should raise exception for invalid access (not in test environment)
    with patch("app.main.DANKLAS_ENV", "prod"):
        with pytest.raises(HTTPException) as exc_info:
            check_kb_access(request, "kb-other-tenant-docs")

        assert exc_info.value.status_code == 403
        assert "not accessible by tenant" in str(exc_info.value.detail)


def test_check_kb_access_no_tenant():
    """Test KB access check without tenant context."""
    from fastapi import HTTPException

    request = Mock()
    request.state.tenant_id = None

    # Should raise exception when no tenant context (not in test environment)
    with patch("app.main.DANKLAS_ENV", "prod"):
        with pytest.raises(HTTPException) as exc_info:
            check_kb_access(request, "kb-any-docs")

        assert exc_info.value.status_code == 403
        assert "No tenant context available" in str(exc_info.value.detail)


# Test environment verification
def test_test_environment_auth_bypass(test_client):
    """Verify that test environment bypasses authentication."""
    # In test environment, this should work without auth headers
    response = test_client.get("/health")
    assert response.status_code == 200

    # Root endpoint should also work
    response = test_client.get("/")
    assert response.status_code == 200
