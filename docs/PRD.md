
# Danklas‑api — Product Requirements Document (PRD)  

*Version:* 0.1  
*Last updated:* 2025-07-25  

---

## 1. Overview  
Danklas‑api is a multi‑tenant, FastAPI‑based façade that sits between **client front‑ends** (e.g. Streamlit apps) and **Amazon Bedrock Knowledge Bases (KBs)**.  
It enforces tenant‑aware authentication & authorization, applies common guardrails, hides underlying Bedrock complexity, and provides a consistent, versioned contract for querying, refreshing, and monitoring KBs—whether they use **S3 + OpenSearch Serverless** or **Kendra + SharePoint Online** data sources.  

---

## 2. Goals  

| # | Goal | Metric / Exit Criteria |
|---|------|------------------------|
| G1 | Secure, role‑based access to tenant KBs | 100 % of requests authenticated with Okta‑issued JWT; unauthorized access attempts blocked |
| G2 | Dumb client UX—no direct Bedrock calls | Front‑end uses only Danklas‑api endpoints; Bedrock APIs are **not** exposed by IAM policy |
| G3 | Multi‑region active‑active (us‑east‑1 & us‑east‑2) | ≤ 100 ms added latency via Route 53 latency‑based routing or ALB GW |
| G4 | Central guardrail enforcement | Same JSON guardrail file injected in 100 % of Bedrock invocations |
| G5 | Auditable & throttled | All requests logged (> 99 % ingest success) & per‑tenant rate limited in API Gateway |

### Non‑Goals  
* Full analytics UI (handled by AWS native/OTEL tooling).  
* KB **creation** (handled via Terraform pipelines).  
* Cross‑region read replicas of OpenSearch/Kendra (out of scope v1).  

---

## 3. Personas  

| Persona | Description | Pain Point |
|---------|-------------|------------|
| **Dank Dev** | Front‑end or agent developer consuming the API | Needs a simple `/query` endpoint, no Bedrock nuances |
| **Cloud Sec** | Org’s security engineer | Needs audit trail, tenant isolation, guardrail consistency |
| **API Owner** | Team operating Danklas‑api | Needs IaC deploy, health checks, rate limiting, minimal ops |  

---

## 4. Functional Requirements  

1. **F1 AuthN** – Validate Okta OIDC JWT, cache JWKs.  
2. **F2 AuthZ** – Map `tenant_id` & `roles[]` claims → IAM roles/KBs. Deny if mismatch.  
3. **F3 /knowledge‑bases/{id}/query** – Invoke Bedrock `RetrieveAndGenerate` with shared guardrail JSON and optional metadata filter list (internal).  
4. **F4 /knowledge‑bases/{id}/status** – Return Bedrock KB ingestion status, DS health.  
5. **F5 /knowledge‑bases/{id}/refresh** – Trigger KB data sync (async).  
6. **F6 Rate limiting** – Per‑tenant quota via API Gateway usage plans.  
7. **F7 Audit log** – Structured “Dank Logger Pro” JSON lines to CloudWatch; trace to OTEL > X‑Ray/AMP.  

---

## 5. Non‑Functional Requirements  

* **Security** – TLS 1.2+, AWS WAF, KMS‑encrypted secrets (ref external CMKs).  
* **Availability** – ≥ 99.9 % via active‑active Lambda or ECS/Fargate; stateless.  
* **Latency** – P99 ≤ 800 ms end‑to‑end for 16‑KB answer.  
* **Cost ceiling** – ≤ $0.05 per 1K lightweight retrieval calls (excl. Bedrock cost).  

---

## 6. High‑Level Architecture  

```mermaid
graph TD
  subgraph Client VPC/Internet
    A[Streamlit / Agent]
  end
  A -->|JWT| APIG[API Gateway<br>HTTP API<br>(multi‑region)]
  APIG -->|Lambda / Fargate| F[FastAPI<br>(Danklas‑api)]
  F -->|Bedrock Retrieve + Generate| BR[Amazon Bedrock]
  F -->|OpenSearch<br>Serverless| OS[(Vector Store)]
  F -->|Kendra| K[Kendra Index]
  BR -->|S3| S3[(Tenant Buckets)]
  F --> CW[CloudWatch Logs + Traces]
  APIG --> WAF[AWS WAF] 
  note over APIG,WAF: Usage plans & <br>throttling
  subgraph Org Networking
    TGW[Transit Gateway]
    VPCe[VPC Interface Endpoints]
  end
  A -->|Private DNS| VPCe
```

---

## 7. Deployment & Ops  

| Layer | Tech | Terraform Module |
|-------|------|------------------|
| API Gateway | `aws_apigatewayv2_*` | `module.dank_api_gw` |
| Compute | Lambda + AWS SAM *or* ECS Fargate Service | `module.dank_service` |
| Auth | Okta OIDC + custom authorizer Lambda | `module.dank_authorizer` |
| Guardrails | SSM Parameter `/dank/guardrail/v1` | `module.dank_guardrails` |
| CI/CD | GitHub Actions → ECR → 🍻 | — |

External KMS keys, Route 53 latency records, and CloudWatch Contributor Insights alarms defined in the **platform** repo.

---

## 8. Risks & Mitigations  

| Risk | Mitigation |
|------|------------|
| Bedrock TPS quota exhaustion | API GW throttling + CloudWatch alarm |
| JWT claim abuse | Validate `aud`, `iss`, `exp`; short TTL (15 m) |
| Regional outage | Active‑active with Route 53 fail‑over |
| Guardrail drift | Guardrail file hash verified on cold start |

---

## 9. Glossary  

* **Dank Guardrail** – JSON block injected into every Bedrock call.  
* **Tenant** – A logical client/org; maps 1‑N KBs.  
* **Knowledge Base** – Bedrock KB with data sources.  

---