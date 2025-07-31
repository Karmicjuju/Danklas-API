import os
from unittest.mock import Mock, patch

# Set environment before importing the app
os.environ["DANKLAS_ENV"] = "test"

import pytest
from fastapi.testclient import TestClient

from app.main import app, build_metadata_filter, check_authorization

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


@pytest.fixture
def mock_avp_allow_response():
    """Mock response from AVP is_authorized API - Allow decision"""
    return {
        "decision": "ALLOW",
        "determiningPolicies": [
            {"policyId": "policy-123", "policyType": "STATIC"}
        ],
        "errors": [],
    }


@pytest.fixture
def mock_avp_deny_response():
    """Mock response from AVP is_authorized API - Deny decision"""
    return {
        "decision": "DENY",
        "determiningPolicies": [],
        "errors": [],
    }


@pytest.fixture
def mock_bedrock_refresh_response():
    """Mock response from Bedrock start_ingestion_job API"""
    return {
        "ingestionJob": {
            "ingestionJobId": "12345678-1234-1234-1234-123456789012",
            "status": "STARTING",
            "knowledgeBaseId": "kb-test-dept-123",
            "dataSourceId": "kb-test-dept-123-datasource",
        }
    }


@pytest.fixture
def mock_bedrock_list_response():
    """Mock response from Bedrock list_knowledge_bases API"""
    return {
        "knowledgeBaseSummaries": [
            {
                "knowledgeBaseId": "kb-engineering-docs",
                "name": "Engineering Documentation",
                "description": "Technical docs for engineering team",
                "status": "ACTIVE"
            },
            {
                "knowledgeBaseId": "kb-shared-public",
                "name": "Public Knowledge Base", 
                "description": "Shared public documentation",
                "status": "ACTIVE"
            },
            {
                "knowledgeBaseId": "kb-finance-docs",
                "name": "Finance Documentation",
                "description": "Financial documents and policies",
                "status": "ACTIVE"
            }
        ]
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
@patch("app.main.avp_client")
@patch("app.main.bedrock_client")
def test_query_knowledge_base_success(
    mock_bedrock_client, mock_avp_client, test_client, mock_bedrock_response, mock_avp_allow_response
):
    """Test successful knowledge base query."""
    mock_bedrock_client.retrieve_and_generate.return_value = mock_bedrock_response
    mock_avp_client.is_authorized.return_value = mock_avp_allow_response

    kb_id = "kb-test-dept-123"
    payload = {"query": "What is machine learning?"}

    # Mock the request state since we're in test environment
    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123",
                "dept_id": "test-dept",
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

    # Verify AVP was called with correct parameters
    mock_avp_client.is_authorized.assert_called_once()
    avp_call_args = mock_avp_client.is_authorized.call_args[1]
    assert avp_call_args["principal"]["entityId"] == "user123"
    assert avp_call_args["action"]["actionId"] == "query"
    assert avp_call_args["resource"]["entityId"] == f"KnowledgeBase::{kb_id}"

    data = response.json()
    assert "answer" in data
    assert "citations" in data
    assert data["answer"] == "This is a test answer from Bedrock."
    assert len(data["citations"]) == 2
    assert "s3://bucket/document1.pdf" in data["citations"]


@patch("app.main.avp_client")
@patch("app.main.bedrock_client")
def test_query_knowledge_base_with_metadata_filters(
    mock_bedrock_client, mock_avp_client, test_client, mock_bedrock_response, mock_avp_allow_response
):
    """Test knowledge base query with additional metadata filters."""
    mock_bedrock_client.retrieve_and_generate.return_value = mock_bedrock_response
    mock_avp_client.is_authorized.return_value = mock_avp_allow_response

    kb_id = "kb-test-dept-123"
    payload = {
        "query": "What is machine learning?",
        "metadata_filters": {"document_type": "tutorial"},
    }

    # Mock the request state since we're in test environment
    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123",
                "dept_id": "test-dept",
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
    kb_id = "kb-test-dept-123"
    payload = {"metadata_filters": {"type": "pdf"}}

    response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert (
        response.status_code == 422
    )  # Unprocessable Entity due to missing required field


@patch("app.main.avp_client")
@patch("app.main.bedrock_client")
def test_query_knowledge_base_bedrock_error(mock_bedrock_client, mock_avp_client, test_client, mock_avp_allow_response):
    """Test handling of Bedrock API errors."""
    mock_bedrock_client.retrieve_and_generate.side_effect = Exception(
        "Bedrock API error"
    )
    mock_avp_client.is_authorized.return_value = mock_avp_allow_response

    kb_id = "kb-test-dept-123"
    payload = {"query": "What is machine learning?"}

    # Mock the request state since we're in test environment
    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123",
                "dept_id": "test-dept",
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
    identity = {"dept_id": "acme-corp", "roles": ["user"], "sub": "user123"}

    result = build_metadata_filter(identity, "kb-acme-corp-docs")

    assert "andAll" in result
    filters = result["andAll"]

    # Should have department filter
    dept_filter = next(
        f for f in filters if f.get("equals", {}).get("key") == "dept_id"
    )
    assert dept_filter["equals"]["value"] == "acme-corp"

    # Should have access level filter for non-admin
    access_filter = next(
        f for f in filters if f.get("equals", {}).get("key") == "access_level"
    )
    assert access_filter["equals"]["value"] == "general"


def test_build_metadata_filter_admin():
    """Test metadata filter for admin users."""
    identity = {"dept_id": "acme-corp", "roles": ["admin"], "sub": "admin123"}

    result = build_metadata_filter(identity, "kb-acme-corp-docs")

    filters = result["andAll"]

    # Should have department filter
    dept_filter = next(
        f for f in filters if f.get("equals", {}).get("key") == "dept_id"
    )
    assert dept_filter["equals"]["value"] == "acme-corp"

    # Should NOT have access level filter for admin
    access_filters = [
        f for f in filters if f.get("equals", {}).get("key") == "access_level"
    ]
    assert len(access_filters) == 0


def test_build_metadata_filter_with_department():
    """Test metadata filter with department information."""
    identity = {
        "dept_id": "acme-corp",
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




# Test environment verification
def test_test_environment_auth_bypass(test_client):
    """Verify that test environment bypasses authentication."""
    # In test environment, this should work without auth headers
    response = test_client.get("/health")
    assert response.status_code == 200

    # Root endpoint should also work
    response = test_client.get("/")
    assert response.status_code == 200


# AVP Authorization tests
@patch("app.main.avp_client")
def test_avp_authorization_denied(mock_avp_client, test_client, mock_avp_deny_response):
    """Test access denied by AVP."""
    mock_avp_client.is_authorized.return_value = mock_avp_deny_response

    kb_id = "kb-test-dept-123"
    payload = {"query": "What is machine learning?"}

    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123",
                "dept_id": "test-dept",
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

    assert response.status_code == 403
    data = response.json()
    assert "Access denied by authorization policy" in data["detail"]


@patch("app.main.avp_client")
def test_avp_authorization_error(mock_avp_client, test_client):
    """Test AVP service error handling."""
    mock_avp_client.is_authorized.side_effect = Exception("AVP service error")

    kb_id = "kb-test-dept-123"
    payload = {"query": "What is machine learning?"}

    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123",
                "dept_id": "test-dept",
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

    # Should fail closed - deny access if AVP check fails
    assert response.status_code == 403
    data = response.json()
    assert "Access denied by authorization policy" in data["detail"]


def test_check_authorization_with_context():
    """Test authorization function with different contexts."""
    from app.main import check_authorization

    # Test in test environment - should not raise exception
    with patch("app.main.DANKLAS_ENV", "test"):
        identity = {
            "sub": "user123",
            "dept_id": "test-dept",
            "roles": ["user"],
            "department": "engineering",
        }
        # Should not raise exception in test environment
        check_authorization(identity, "query", "KnowledgeBase::kb-123")


@patch("app.main.avp_client")
def test_avp_context_formatting(mock_avp_client):
    """Test that AVP context is properly formatted."""
    from app.main import check_authorization

    mock_avp_client.is_authorized.return_value = {"decision": "ALLOW"}

    with patch("app.main.DANKLAS_ENV", "prod"):
        identity = {
            "sub": "user123",
            "dept_id": "test-dept",
            "roles": ["admin", "user"],
            "department": "engineering",
        }

        check_authorization(identity, "query", "KnowledgeBase::kb-123")

        # Verify the call was made with proper formatting
        call_args = mock_avp_client.is_authorized.call_args[1]

        # Check principal formatting
        assert call_args["principal"]["entityType"] == "User"
        assert call_args["principal"]["entityId"] == "user123"

        # Check action formatting
        assert call_args["action"]["actionType"] == "DanklasAPI::Action"
        assert call_args["action"]["actionId"] == "query"

        # Check resource formatting
        assert call_args["resource"]["entityType"] == "DanklasAPI::Resource"
        assert call_args["resource"]["entityId"] == "KnowledgeBase::kb-123"

        # Check context formatting
        context = call_args["context"]["contextMap"]
        assert context["dept_id"]["string"] == "test-dept"
        assert context["department"]["string"] == "engineering"
        assert len(context["roles"]["list"]) == 2
        assert context["roles"]["list"][0]["string"] == "admin"
        assert context["roles"]["list"][1]["string"] == "user"


# Refresh endpoint tests
@patch("app.main.avp_client")
@patch("app.main.bedrock_client")
def test_refresh_knowledge_base_success(
    mock_bedrock_client, mock_avp_client, test_client, mock_bedrock_refresh_response, mock_avp_allow_response
):
    """Test successful knowledge base refresh."""
    mock_bedrock_client.start_ingestion_job.return_value = mock_bedrock_refresh_response
    mock_avp_client.is_authorized.return_value = mock_avp_allow_response

    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123", "dept_id": "test-dept", "roles": ["admin"],
                "department": None, "exp": 9999999999, "aud": "api://default", "iss": "https://test.okta.com"
            }
            
            response = test_client.post("/knowledge-bases/kb-test-dept-123/refresh", 
                                     headers={"Authorization": "Bearer mock-token"})

    assert response.status_code == 200
    data = response.json()
    assert data["job_id"] == "12345678-1234-1234-1234-123456789012"
    assert data["status"] == "STARTING"


@patch("app.main.avp_client")
def test_refresh_knowledge_base_denied(mock_avp_client, test_client, mock_avp_deny_response):
    """Test refresh denied by AVP."""
    mock_avp_client.is_authorized.return_value = mock_avp_deny_response

    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123", "dept_id": "test-dept", "roles": ["user"],
                "department": None, "exp": 9999999999, "aud": "api://default", "iss": "https://test.okta.com"
            }
            
            response = test_client.post("/knowledge-bases/kb-test-dept-123/refresh", 
                                     headers={"Authorization": "Bearer mock-token"})

    assert response.status_code == 403


# Knowledge base listing tests
@patch("app.main.avp_client")
@patch("app.main.bedrock_client")
def test_list_knowledge_bases_success(
    mock_bedrock_client, mock_avp_client, test_client, mock_bedrock_list_response, mock_avp_allow_response
):
    """Test successful knowledge base listing with filtered results."""
    mock_bedrock_client.list_knowledge_bases.return_value = mock_bedrock_list_response
    
    # Mock AVP to allow list action and specific KBs
    def mock_avp_side_effect(*args, **kwargs):
        resource_id = kwargs.get('resource', {}).get('entityId', '')
        action_id = kwargs.get('action', {}).get('actionId', '')
        
        # Allow list action
        if action_id == "list":
            return mock_avp_allow_response
        # Allow access to engineering and shared KBs only
        elif resource_id in ["KnowledgeBase::kb-engineering-docs", "KnowledgeBase::kb-shared-public"]:
            return mock_avp_allow_response
        else:
            return {"decision": "DENY", "determiningPolicies": [], "errors": []}
    
    mock_avp_client.is_authorized.side_effect = mock_avp_side_effect

    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123", "dept_id": "engineering", "roles": ["user"],
                "department": "engineering", "exp": 9999999999, "aud": "api://default", "iss": "https://test.okta.com"
            }
            
            response = test_client.get("/knowledge-bases", 
                                    headers={"Authorization": "Bearer mock-token"})

    assert response.status_code == 200
    data = response.json()
    
    # Should have 2 accessible KBs (engineering and shared, but not finance)
    assert data["total_count"] == 2
    assert len(data["knowledge_bases"]) == 2
    
    kb_ids = [kb["knowledge_base_id"] for kb in data["knowledge_bases"]]
    assert "kb-engineering-docs" in kb_ids
    assert "kb-shared-public" in kb_ids
    assert "kb-finance-docs" not in kb_ids
    
    # Check KB details
    engineering_kb = next(kb for kb in data["knowledge_bases"] if kb["knowledge_base_id"] == "kb-engineering-docs")
    assert engineering_kb["name"] == "Engineering Documentation"


@patch("app.main.avp_client")
def test_list_knowledge_bases_no_list_permission(mock_avp_client, test_client, mock_avp_deny_response):
    """Test KB listing when user doesn't have list permission."""
    mock_avp_client.is_authorized.return_value = mock_avp_deny_response

    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123", "dept_id": "test-dept", "roles": ["user"],
                "department": None, "exp": 9999999999, "aud": "api://default", "iss": "https://test.okta.com"
            }
            
            response = test_client.get("/knowledge-bases", 
                                    headers={"Authorization": "Bearer mock-token"})

    assert response.status_code == 403


@patch("app.main.avp_client") 
@patch("app.main.bedrock_client")
def test_list_knowledge_bases_bedrock_error(
    mock_bedrock_client, mock_avp_client, test_client, mock_avp_allow_response
):
    """Test handling of Bedrock API errors during KB listing.""" 
    mock_avp_client.is_authorized.return_value = mock_avp_allow_response
    mock_bedrock_client.list_knowledge_bases.side_effect = Exception("Bedrock API error")

    with patch("app.main.DANKLAS_ENV", "prod"):
        with patch("app.main.verify_jwt") as mock_verify_jwt:
            mock_verify_jwt.return_value = {
                "sub": "user123", "dept_id": "test-dept", "roles": ["user"],
                "department": None, "exp": 9999999999, "aud": "api://default", "iss": "https://test.okta.com"
            }
            
            response = test_client.get("/knowledge-bases", 
                                    headers={"Authorization": "Bearer mock-token"})

    assert response.status_code == 500
    data = response.json()
    assert "Failed to retrieve knowledge base list" in data["detail"]
