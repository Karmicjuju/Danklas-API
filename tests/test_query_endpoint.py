import os
os.environ["DANKLAS_ENV"] = "test"

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

@pytest.fixture(scope="module")
def test_client():
    return TestClient(app)

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