# User Story Backlog  

> Format follows sample MD: `<story‑id> – As a <persona> I want … so that …`  

## Epic 0 – Foundation 🏗️  

| ID | Story | Acceptance Criteria | Priority | Points |
|----|-------|--------------------|----------|--------|
| **DANK‑0.1** | As an **API Owner**, I want a Git repo bootstrapped with FastAPI + Poetry so that I start coding features quickly. | Repo contains `pyproject.toml`, Dockerfile, CI lint/test workflow. | High | 1 |
| **DANK‑0.2** | As an **API Owner**, I want a Terraform root module scaffold so that infra can be provisioned IaC. | `terraform {}` block, AWS provider, backend config. | High | 1 |

## Epic 1 – AuthN & AuthZ 🔐  

| ID | Story | Acceptance Criteria | Priority | Points |
|----|-------|--------------------|----------|--------|
| **DANK‑1.1** | As **Dank Dev**, I want my Okta access token validated by the API so that unauthorized clients are rejected. | 401 if token invalid/expired; unit tests for `aud/iss/exp` claims. | High | 3 |
| **DANK‑1.2** | As **Cloud Sec**, I want token claims mapped to `tenant_id` and `roles[]` so that each request is evaluated against the right KB ACL. | Middleware attaches `request.state.tenant`; e2e test passes/denies. | High | 5 |
| **DANK‑1.3** | As **Cloud Sec**, I need an IAM policy boundary ensuring the API can only access KBs tagged with its tenant id. | Terraform enforces `Condition StringEquals bedrock:ResourceTag/tenant`. | Med | 5 |

## Epic 2 – Core KB Endpoints 📚  

| ID | Story | Acceptance Criteria | Priority | Points |
|----|-------|--------------------|----------|--------|
| **DANK‑2.1** | As **Dank Dev**, I want `/knowledge‑bases/:id/query` so that I can ask questions. | 200 returns `answer`, `citations[]`; uses guardrail JSON. | High | 8 |
| **DANK‑2.2** | As **Dank Dev**, I want `/knowledge‑bases/:id/status` so that my UI shows ingestion progress. | 200 returns `{status, lastSyncedAt}`. | Med | 3 |
| **DANK‑2.3** | As **API Owner**, I want `/knowledge‑bases/:id/refresh` to kick off ingestion so that admins can update data. | 202 accepted; Bedrock sync job started; idempotent. | Med | 5 |

## Epic 3 – Observability 👀  

| ID | Story | Acceptance Criteria | Priority | Points |
|----|-------|--------------------|----------|--------|
| **DANK‑3.1** | As **API Owner**, I want structured **Dank Logger Pro** output so that logs are human & machine readable. | JSON logs include `request_id`, `tenant`, latency ms. | High | 2 |
| **DANK‑3.2** | As **Cloud Sec**, I need audit logs retained 1 yr per compliance. | CloudWatch retention set 400 days; alarm on failure. | Med | 3 |
| **DANK‑3.3** | As **API Owner**, I want OTEL traces exported to X‑Ray so that I can view spans across services. | End‑to‑end trace visible in console for happy path. | Med | 5 |

## Epic 4 – Rate Limiting & Quotas 🚦  

| ID | Story | Acceptance Criteria | Priority | Points |
|----|-------|--------------------|----------|--------|
| **DANK‑4.1** | As **Cloud Sec**, I want per‑tenant usage plans to avoid Bedrock throttling. | API GW rejects > configured RPS with 429. | High | 3 |
| **DANK‑4.2** | As **Cloud Sec**, I want configurable quota tiers (Free, Pro, Dank Ultra) so that monetization is easy. | Usage plan created via Terraform variable. | Low | 3 |

## Epic 5 – Guardrails Management 🛡️  

| ID | Story | Acceptance Criteria | Priority | Points |
|----|-------|--------------------|----------|--------|
| **DANK‑5.1** | As **API Owner**, I want guardrail JSON stored in SSM Parameter Store so that we can update it without redeploy. | API reads value on cold start; checksum logged. | Med | 5 |
| **DANK‑5.2** | As **Cloud Sec**, I want CI pipeline approval step when guardrails change so that risky edits are reviewed. | GitHub Actions requires CODEOWNERS approval. | Med | 2 |

## Epic 6 – Multi‑Region & DR 🌎  

| ID | Story | Acceptance Criteria | Priority | Points |
|----|-------|--------------------|----------|--------|
| **DANK‑6.1** | As **API Owner**, I want the service deployed in us‑east‑1 & us‑east‑2 behind Route 53 latency routing so that users have HA. | Fail regional ALB health check → traffic shifts within 60 s. | High | 8 |
| **DANK‑6.2** | As **Cloud Sec**, I need KMS CMKs replicated to the secondary region for decrypt. | Multi‑Region KMS key ARN referenced; decrypt success. | Med | 3 |

## Epic 7 – VPC Connectivity 🌐  

| ID | Story | Acceptance Criteria | Priority | Points |
|----|-------|--------------------|----------|--------|
| **DANK‑7.1** | As **Client Dev**, I want to call the API via VPC Interface Endpoints so that traffic stays inside our AWS Org. | Endpoint services published; DNS names resolvable. | Med | 5 |
| **DANK‑7.2** | As **Network Ops**, I want Transit Gateway routes & SG rules Terraform‑managed to avoid snowflake config. | Plan/apply idempotent; test traffic flow ❤️ | Low | 5 |

---