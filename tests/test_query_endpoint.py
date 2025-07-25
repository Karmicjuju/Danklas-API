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
    assert data["jobId"] == "mock-job-123"
    assert data["message"] == f"Refresh started for KB {kb_id}" 