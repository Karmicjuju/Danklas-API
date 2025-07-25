import os
from fastapi import FastAPI, Request, HTTPException, status, Path, Body
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError
import requests
from functools import lru_cache
import logging
from pydantic import BaseModel
from typing import List, Dict, Any

app = FastAPI()

# --- Okta OIDC config (replace with your Okta values) ---
OKTA_ISSUER = os.getenv("OKTA_ISSUER", "https://YOUR_OKTA_DOMAIN/oauth2/default")
OKTA_AUDIENCE = os.getenv("OKTA_AUDIENCE", "api://default")
OKTA_JWKS_URI = f"{OKTA_ISSUER}/v1/keys"

@lru_cache(maxsize=1)
def get_jwks():
    resp = requests.get(OKTA_JWKS_URI)
    resp.raise_for_status()
    return resp.json()

def verify_jwt(token: str):
    jwks = get_jwks()
    try:
        return jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=OKTA_AUDIENCE,
            issuer=OKTA_ISSUER,
            options={"verify_aud": True, "verify_iss": True, "verify_exp": True},
        )
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")

DANKLAS_ENV = os.getenv("DANKLAS_ENV", "prod")
LOCAL_IPS = {"127.0.0.1", "::1"}

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        public_paths = {"/", "/docs", "/redoc", "/openapi.json", "/favicon.ico"}
        if DANKLAS_ENV == "test":
            return await call_next(request)
        if DANKLAS_ENV in {"dev", "test"} and request.url.path in public_paths:
            logging.warning("Unauthenticated access allowed to %s in %s mode from %s", request.url.path, DANKLAS_ENV, request.client.host)
            return await call_next(request)
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Authorization header")
        token = auth.split(" ", 1)[1]
        payload = verify_jwt(token)
        request.state.user = payload
        return await call_next(request)

app.add_middleware(AuthMiddleware)

@app.get("/")
def read_root():
    return {"Hello": "World"}


class QueryRequest(BaseModel):
    query: str
    metadata_filters: Dict[str, Any] = None

class QueryResponse(BaseModel):
    answer: str
    citations: List[str]

@app.post("/knowledge-bases/{kb_id}/query", response_model=QueryResponse)
def query_knowledge_base(
    kb_id: str = Path(..., description="Knowledge Base ID"),
    body: QueryRequest = Body(...)
):
    # TODO: Call Bedrock RetrieveAndGenerate with guardrail JSON and metadata_filters
    # For now, return a mock response
    return QueryResponse(
        answer=f"Mock answer for KB {kb_id} and query '{body.query}'",
        citations=["doc1.pdf", "doc2.pdf"]
    )


class StatusResponse(BaseModel):
    status: str
    lastSyncedAt: str

@app.get("/knowledge-bases/{kb_id}/status", response_model=StatusResponse)
def knowledge_base_status(kb_id: str = Path(..., description="Knowledge Base ID")):
    # TODO: Replace with real Bedrock KB status lookup
    return StatusResponse(status="READY", lastSyncedAt="2024-07-25T12:00:00Z")


class RefreshResponse(BaseModel):
    jobId: str
    message: str

@app.post("/knowledge-bases/{kb_id}/refresh", response_model=RefreshResponse, status_code=202)
def refresh_knowledge_base(kb_id: str = Path(..., description="Knowledge Base ID")):
    # TODO: Trigger async KB data sync job
    return RefreshResponse(jobId="mock-job-123", message=f"Refresh started for KB {kb_id}")

