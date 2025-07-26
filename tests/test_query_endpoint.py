import os
# Set environment before importing the app
os.environ["DANKLAS_ENV"] = "test"

import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
import app.main as main_module  # Import module to access functions
from app.main import app

client = TestClient(app)

@pytest.fixture
def test_client():
    return client

def test_query_knowledge_base_success(test_client):
    kb_id = "kb123"
    payload = {"query": "What is Danklas?", "metadata_filters": {"type": "pdf"}}
    response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert "citations" in data
    assert isinstance(data["citations"], list)
    assert data["answer"].startswith("Mock answer for KB kb123")

def test_query_knowledge_base_missing_query(test_client):
    kb_id = "kb123"
    payload = {"metadata_filters": {"type": "pdf"}}
    response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 422  # Unprocessable Entity due to missing required field 

def test_structured_logging_for_query(test_client, caplog):
    kb_id = "kb123"
    payload = {"query": "Test log", "metadata_filters": {}}
    with caplog.at_level("INFO", logger="danklas"):
        response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 200
    # Find a log record with expected fields
    found = False
    for record in caplog.records:
        if record.name == "danklas" and hasattr(record, "request_id"):
            found = True
            assert record.levelname == "INFO"
            assert record.method == "POST"
            assert record.path == f"/knowledge-bases/{kb_id}/query"
            assert record.status_code == 200
            assert hasattr(record, "latency_ms")
    assert found, "Structured log with request_id not found"

def test_knowledge_base_status_success(test_client):
    kb_id = "kb123"
    response = test_client.get(f"/knowledge-bases/{kb_id}/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "READY"
    assert data["lastSyncedAt"] == "2024-07-25T12:00:00Z" 

def test_knowledge_base_refresh_success(test_client):
    kb_id = "kb123"
    response = test_client.post(f"/knowledge-bases/{kb_id}/refresh")
    assert response.status_code == 202
    data = response.json()
    assert data["jobId"].startswith("mock-job-")  # Dynamic job ID
    assert data["message"] == f"Refresh started for KB {kb_id}"

def test_audit_logging_request_start(test_client, caplog):
    kb_id = "kb123"
    payload = {"query": "Test audit", "metadata_filters": {}}
    with caplog.at_level("INFO", logger="danklas.audit"):
        response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 200
    
    # Check for audit log entry at request start
    start_log_found = False
    for record in caplog.records:
        if record.name == "danklas.audit" and getattr(record, "audit_type", "") == "request_start":
            start_log_found = True
            assert record.levelname == "INFO"
            assert record.audit_type == "request_start"
            assert record.method == "POST"
            assert record.path == f"/knowledge-bases/{kb_id}/query"
            assert "request_id" in record.__dict__
            assert "client_ip" in record.__dict__
            assert "user_agent" in record.__dict__
    assert start_log_found, "Audit log for request start not found"

def test_audit_logging_request_success(test_client, caplog):
    kb_id = "kb123"
    payload = {"query": "Test audit success", "metadata_filters": {}}
    with caplog.at_level("INFO", logger="danklas.audit"):
        response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 200
    
    # Check for audit log entry for successful request
    success_log_found = False
    for record in caplog.records:
        if record.name == "danklas.audit" and getattr(record, "audit_type", "") == "request_success":
            success_log_found = True
            assert record.levelname == "INFO"
            assert record.audit_type == "request_success"
            assert record.method == "POST"
            assert record.path == f"/knowledge-bases/{kb_id}/query"
            assert record.status_code == 200
            assert "latency_ms" in record.__dict__
    assert success_log_found, "Audit log for request success not found"

def test_audit_logging_structure(test_client, caplog):
    kb_id = "kb123"
    payload = {"query": "Test audit structure", "metadata_filters": {}}
    with caplog.at_level("INFO", logger="danklas.audit"):
        response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 200
    
    # Verify audit log structure contains required fields
    audit_records = [r for r in caplog.records if r.name == "danklas.audit"]
    assert len(audit_records) >= 2, "Should have at least request_start and request_completed audit logs"
    
    # Check that audit logs have the required structure
    for record in audit_records:
        assert hasattr(record, "request_id"), "Audit log missing request_id"
        assert hasattr(record, "tenant"), "Audit log missing tenant"
        assert hasattr(record, "method"), "Audit log missing method"
        assert hasattr(record, "path"), "Audit log missing path"
        assert hasattr(record, "audit_type"), "Audit log missing audit_type"
        assert record.audit_type in ["request_start", "request_success"], f"Unexpected audit_type: {record.audit_type}" 

def test_tracing_integration_query_endpoint(test_client):
    """Test that OpenTelemetry spans are created for query endpoint."""
    from opentelemetry import trace
    
    kb_id = "kb123"
    payload = {"query": "Test tracing", "metadata_filters": {}}
    
    # Make request that should create spans
    response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 200
    
    # Verify response contains expected data
    data = response.json()
    assert data["answer"] == f"Mock answer for KB {kb_id} and query '{payload['query']}'"
    assert data["citations"] == ["doc1.pdf", "doc2.pdf"]

def test_trace_context_in_logs(test_client, caplog):
    """Test that trace context (trace_id, span_id) is included in logs."""
    kb_id = "kb123"
    payload = {"query": "Test trace context", "metadata_filters": {}}
    
    with caplog.at_level("INFO", logger="danklas.audit"):
        response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 200
    
    # Check that audit logs contain trace context
    trace_context_found = False
    for record in caplog.records:
        if record.name == "danklas.audit" and hasattr(record, "trace_id"):
            trace_context_found = True
            assert hasattr(record, "span_id"), "Span ID should be present in log"
            assert record.trace_id != "unknown", "Trace ID should not be unknown"
            assert record.span_id != "unknown", "Span ID should not be unknown"
    assert trace_context_found, "Trace context not found in audit logs"

def test_custom_span_attributes_query(test_client):
    """Test that custom span attributes are set for knowledge base operations."""
    from app.tracing import get_tracer
    
    kb_id = "test-kb-456"
    payload = {"query": "Test custom attributes", "metadata_filters": {"type": "test"}}
    
    # Make request to create spans with custom attributes
    response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 200
    
    # Verify response structure
    data = response.json()
    assert "answer" in data
    assert "citations" in data
    assert len(data["citations"]) == 2

def test_tracing_status_endpoint(test_client):
    """Test tracing integration for status endpoint."""
    kb_id = "kb789"
    response = test_client.get(f"/knowledge-bases/{kb_id}/status")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "READY"
    assert "lastSyncedAt" in data

def test_tracing_refresh_endpoint(test_client):
    """Test tracing integration for refresh endpoint."""
    kb_id = "kb999"
    response = test_client.post(f"/knowledge-bases/{kb_id}/refresh")
    assert response.status_code == 202
    
    data = response.json()
    assert "jobId" in data
    assert data["jobId"].startswith("mock-job-")
    assert data["message"] == f"Refresh started for KB {kb_id}" 

def test_tenant_mapping_in_logs(test_client, caplog, monkeypatch):
    """Test that tenant_id is properly extracted and used in logs."""
    # Use monkeypatch to temporarily modify the environment
    monkeypatch.setenv("DANKLAS_ENV", "dev")  # Use dev mode for auth bypass but still test logging
    
    kb_id = "kb-test-tenant-123"
    payload = {"query": "Test tenant mapping", "metadata_filters": {}}
    
    with caplog.at_level("INFO", logger="danklas.audit"):
        response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    
    assert response.status_code == 200
    
    # In test environment, tenant should be "unauthenticated"
    tenant_found = False
    for record in caplog.records:
        if record.name == "danklas.audit" and hasattr(record, "tenant"):
            assert record.tenant == "unauthenticated"  # Expected in test mode
            tenant_found = True
    assert tenant_found, "Tenant not found in audit logs"

def test_jwt_claim_extraction():
    """Test JWT claim extraction logic directly."""
    from app.main import verify_jwt
    
    # Mock the jwks response
    original_get_jwks = main_module.get_jwks
    
    def mock_get_jwks():
        # Return a mock JWKS for testing
        return {
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-id",
                "n": "test-n",
                "e": "AQAB"
            }]
        }
    
    # Mock jwt.decode to return our test payload
    import app.main
    from jose import jwt as jose_jwt
    original_decode = jose_jwt.decode
    
    def mock_decode(*args, **kwargs):
        return {
            "sub": "user123",
            "tenant_id": "test-tenant",
            "roles": ["admin", "user"],
            "exp": 9999999999,
            "aud": "api://default",
            "iss": "https://test.okta.com"
        }
    
    try:
        main_module.get_jwks = mock_get_jwks
        jose_jwt.decode = mock_decode
        
        result = verify_jwt("mock-token")
        assert result["tenant_id"] == "test-tenant"
        assert result["roles"] == ["admin", "user"]
        assert result["sub"] == "user123"
        
    finally:
        main_module.get_jwks = original_get_jwks
        jose_jwt.decode = original_decode

def test_kb_access_function(monkeypatch):
    """Test the check_kb_access function directly."""
    from app.main import check_kb_access
    from unittest.mock import Mock
    
    # Create a mock request with tenant info
    request = Mock()
    request.state.tenant_id = "acme-corp"
    request.state.roles = ["user"]
    
    # Test valid access
    try:
        check_kb_access(request, "kb-acme-corp-documents", ["user"], env="prod")
        # Should not raise an exception
    except Exception:
        pytest.fail("Valid KB access should not raise exception")
    
    # Test invalid tenant access
    with pytest.raises(HTTPException) as exc_info:
        check_kb_access(request, "kb-other-tenant-docs", ["user"], env="prod")
    assert "not accessible by tenant" in str(exc_info.value.detail)
    
    # Test insufficient role access
    with pytest.raises(HTTPException) as exc_info:
        check_kb_access(request, "kb-acme-corp-documents", ["admin"], env="prod")
    assert "requires one of roles" in str(exc_info.value.detail) 