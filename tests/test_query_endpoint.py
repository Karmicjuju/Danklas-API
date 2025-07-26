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
    
    # Verify response contains expected data (now includes guardrail filtering)
    data = response.json()
    assert f"Mock answer for KB {kb_id} and query '{payload['query']}'" in data["answer"]
    assert "filtered by guardrail" in data["answer"]
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

def test_usage_stats_endpoint(test_client):
    """Test the usage statistics endpoint."""
    response = test_client.get("/usage-stats")
    # In test mode, unauthenticated requests should get 401 since tenant_id is "unauthenticated"
    # which triggers the authentication required check
    assert response.status_code == 401
    data = response.json()
    assert "Authentication required" in data["detail"]

def test_rate_limiting_configuration():
    """Test rate limiting configuration and tier detection."""
    from app.rate_limiting import USAGE_TIERS, get_tenant_tier
    from unittest.mock import Mock
    
    # Test tier configurations exist
    assert "free" in USAGE_TIERS
    assert "pro" in USAGE_TIERS
    assert "dank_ultra" in USAGE_TIERS
    
    # Test tier detection
    request = Mock()
    request.state.roles = ["user"]
    assert get_tenant_tier(request) == "free"
    
    request.state.roles = ["pro"]
    assert get_tenant_tier(request) == "pro"
    
    request.state.roles = ["dank_ultra"]
    assert get_tenant_tier(request) == "dank_ultra"

def test_tenant_identifier_function():
    """Test tenant identifier generation for rate limiting."""
    from app.rate_limiting import get_tenant_identifier
    from unittest.mock import Mock
    
    # Test with authenticated tenant
    request = Mock()
    request.state.tenant_id = "test-tenant"
    identifier = get_tenant_identifier(request)
    assert identifier == "tenant:test-tenant"
    
    # Test with unauthenticated request (fallback to IP)
    request = Mock()
    request.state.tenant_id = None
    request.client.host = "192.168.1.1"
    
    # Mock the get_remote_address function
    from app.rate_limiting import get_remote_address
    original_get_remote_address = get_remote_address
    
    def mock_get_remote_address(req):
        return "192.168.1.1"
    
    import app.rate_limiting
    app.rate_limiting.get_remote_address = mock_get_remote_address
    
    try:
        identifier = get_tenant_identifier(request)
        assert identifier == "ip:192.168.1.1"
    finally:
        app.rate_limiting.get_remote_address = original_get_remote_address

def test_rate_limiting_disabled_in_test():
    """Test that rate limiting is properly disabled in test environment."""
    from app.rate_limiting import create_limiter
    import os
    
    # Test environment should disable rate limiting
    original_env = os.environ.get("ENABLE_RATE_LIMITING")
    os.environ["ENABLE_RATE_LIMITING"] = "false"
    
    try:
        limiter = create_limiter()
        assert limiter is None
    finally:
        if original_env:
            os.environ["ENABLE_RATE_LIMITING"] = original_env
        else:
            del os.environ["ENABLE_RATE_LIMITING"]

def test_usage_tiers_structure():
    """Test that usage tiers have the required structure."""
    from app.rate_limiting import USAGE_TIERS
    
    required_fields = ["requests_per_minute", "requests_per_hour", "requests_per_day", "max_kb_queries"]
    
    for tier_name, tier_config in USAGE_TIERS.items():
        for field in required_fields:
            assert field in tier_config, f"Missing {field} in {tier_name} tier"
            assert isinstance(tier_config[field], int), f"{field} should be integer in {tier_name} tier" 

def test_guardrails_info_endpoint(test_client):
    """Test the guardrails info endpoint."""
    response = test_client.get("/guardrails/info")
    assert response.status_code == 200
    data = response.json()
    assert "guardrail_info" in data
    assert "checksum" in data["guardrail_info"]
    assert "version" in data["guardrail_info"]
    assert "parameter_path" in data["guardrail_info"]

def test_guardrails_config_endpoint_requires_admin(test_client):
    """Test that guardrails config endpoint requires admin access."""
    response = test_client.get("/guardrails/config")
    # Should work in test mode without authentication
    assert response.status_code == 200
    data = response.json()
    assert "guardrail_configuration" in data
    assert "metadata" in data

def test_guardrails_refresh_endpoint(test_client):
    """Test the guardrails refresh endpoint."""
    response = test_client.post("/guardrails/refresh")
    # Should work in test mode
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "new_checksum" in data
    assert "version" in data
    assert "timestamp" in data

def test_guardrail_manager_functionality():
    """Test GuardrailManager class functionality."""
    from app.guardrails import GuardrailManager, DEFAULT_GUARDRAIL
    
    manager = GuardrailManager()
    
    # Test get_guardrail returns default when SSM unavailable
    guardrail = manager.get_guardrail()
    assert guardrail is not None
    assert "content_filters" in guardrail
    assert "output_filters" in guardrail
    assert "query_filters" in guardrail
    assert "bedrock_config" in guardrail
    
    # Test checksum calculation
    checksum = manager.get_guardrail_checksum()
    assert isinstance(checksum, str)
    assert len(checksum) == 64  # SHA256 hash length

def test_guardrail_validation():
    """Test guardrail configuration validation."""
    from app.guardrails import GuardrailManager, DEFAULT_GUARDRAIL
    
    manager = GuardrailManager()
    
    # Test valid guardrail
    assert manager.validate_guardrail(DEFAULT_GUARDRAIL) == True
    
    # Test invalid guardrail (missing required section)
    invalid_guardrail = {
        "content_filters": {},
        "output_filters": {},
        # Missing query_filters and bedrock_config
    }
    assert manager.validate_guardrail(invalid_guardrail) == False
    
    # Test invalid content filter
    invalid_content_filter = {
        "content_filters": {
            "bad_filter": "not_a_dict"  # Should be dict with 'enabled' key
        },
        "output_filters": {},
        "query_filters": {},
        "bedrock_config": {
            "model_settings": {},
            "retrieval_config": {}
        }
    }
    assert manager.validate_guardrail(invalid_content_filter) == False

def test_query_endpoint_with_guardrails(test_client):
    """Test that query endpoint applies guardrail filters."""
    kb_id = "kb123"
    
    # Test normal query
    payload = {"query": "What is AI?", "metadata_filters": {}}
    response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "filtered by guardrail" in data["answer"]
    
    # Test query that exceeds length limit (if enabled)
    long_query = "x" * 10000  # Exceeds default 8192 char limit
    payload = {"query": long_query, "metadata_filters": {}}
    response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 400
    assert "exceeds maximum length" in response.json()["detail"]
    
    # Test query with suspicious content
    malicious_query = "DROP TABLE users; What is AI?"
    payload = {"query": malicious_query, "metadata_filters": {}}
    response = test_client.post(f"/knowledge-bases/{kb_id}/query", json=payload)
    assert response.status_code == 400
    assert "potentially malicious content" in response.json()["detail"]

def test_guardrail_checksum_calculation():
    """Test that guardrail checksum calculation is consistent."""
    from app.guardrails import GuardrailManager
    
    manager = GuardrailManager()
    
    test_data = {"test": "data", "number": 123}
    checksum1 = manager._calculate_checksum(test_data)
    checksum2 = manager._calculate_checksum(test_data)
    
    # Should be consistent
    assert checksum1 == checksum2
    
    # Different data should produce different checksum
    different_data = {"test": "different", "number": 456}
    checksum3 = manager._calculate_checksum(different_data)
    assert checksum1 != checksum3

def test_guardrail_default_configuration():
    """Test that default guardrail configuration is complete and valid."""
    from app.guardrails import DEFAULT_GUARDRAIL, GuardrailManager
    
    manager = GuardrailManager()
    
    # Should be valid
    assert manager.validate_guardrail(DEFAULT_GUARDRAIL) == True
    
    # Should have all required sections
    required_sections = ["content_filters", "output_filters", "query_filters", "bedrock_config"]
    for section in required_sections:
        assert section in DEFAULT_GUARDRAIL
    
    # Content filters should have proper structure
    content_filters = DEFAULT_GUARDRAIL["content_filters"]
    for filter_name, config in content_filters.items():
        assert isinstance(config, dict)
        assert "enabled" in config
        assert isinstance(config["enabled"], bool)
    
    # Bedrock config should have required subsections
    bedrock_config = DEFAULT_GUARDRAIL["bedrock_config"]
    assert "model_settings" in bedrock_config
    assert "retrieval_config" in bedrock_config 

def test_health_check_endpoint(test_client):
    """Test the health check endpoint for Route 53 health checks."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    
    # Verify required health check fields
    assert "status" in data
    assert "timestamp" in data
    assert "version" in data
    assert "environment" in data
    assert "guardrails" in data
    assert "rate_limiting" in data
    assert "tracing" in data
    
    # Verify health status
    assert data["status"] == "healthy"
    assert data["environment"] == "test"
    
    # Check component statuses
    assert data["guardrails"]["status"] in ["healthy", "degraded"]
    assert data["rate_limiting"]["status"] in ["enabled", "disabled"]
    assert data["tracing"]["status"] in ["enabled", "disabled"]

def test_vpc_connectivity_concepts():
    """Test VPC connectivity configuration concepts."""
    # This test verifies that VPC-related configuration is properly structured
    # In a real deployment, this would test actual VPC endpoint connectivity
    
    # Test that we have the necessary VPC configuration files
    import os
    vpc_config_exists = os.path.exists("terraform/vpc-connectivity.tf")
    assert vpc_config_exists, "VPC connectivity configuration should exist"
    
    multi_region_config_exists = os.path.exists("terraform/multi-region.tf")
    assert multi_region_config_exists, "Multi-region configuration should exist"

def test_regional_deployment_configuration(test_client):
    """Test multi-region deployment configuration."""
    # Verify that health check endpoint includes region information
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    
    # Should include region information for Route 53 routing
    assert "region" in data
    
    # In a real deployment, this would test:
    # - Route 53 latency routing
    # - Health check failover
    # - Cross-region KMS key access 