# Sentriq — Master Platform Roadmap

> **Platform**: Sentriq Application Security Intelligence
> **Repository**: [https://github.com/Induvardhan116/Sentriq.git](https://github.com/Induvardhan116/Sentriq.git)
> **Current Version**: 1.0.0-rc
> **Status**: **Phases 1–12 Completed & Locally Verified (221 Backend Tests / 98 Frontend Tests)**

---

## 1. Executive Implementation Roadmap

```
[Phase 1] Foundation & Auth       ───► [Phase 2] Web Scanner         ───► [Phase 3] Project Mgmt
         │                                    │                                  │
         ▼                                    ▼                                  ▼
[Phase 4] Findings Hub & OCC      ───► [Phase 5] Risk Analytics      ───► [Phase 6] Repo Security
         │                                    │                                  │
         ▼                                    ▼                                  ▼
[Phase 7] API Security            ───► [Phase 8] Cloud CSPM          ───► [Phase 9] Reports & PDF
         │                                    │                                  │
         ▼                                    ▼                                  ▼
[Phase 10] Settings & Controls    ───► [Phase 11] Integrations/SIEM  ───► [Phase 12] Enterprise RBAC
```

---

## 2. Completed Milestones (Phases 1–12)

### Phase 1: Platform Foundation & Identity Security
- **Backend Core**: FastAPI async core, Pydantic settings, SQLAlchemy 2.0 async engine (SQLite for local development, asyncpg for PostgreSQL).
- **Authentication**: Email/Password registration, Argon2id/Bcrypt hashing with constant-time verification, session rotation on login.
- **Session Security**: 256-bit cryptographically secure session tokens, SHA-256 token hashing in database, `Secure; HttpOnly; SameSite=Lax` cookies.
- **CSRF & Rate Limiting**: HMAC-SHA256 CSRF protection, IP proxy extraction with anti-spoofing CIDR validation, progressive lockout defense.
- **GitHub OAuth**: One-time atomic state consumption (`OAuthState`) preventing replay and CSRF attacks.
- **Status**: **LOCALLY VERIFIED** (Production Gate `AUTH_ENABLED=false` held for safe staging).

### Phase 2: Website Security Scanner
- **SSRF Guardrail**: `validate_target_url` enforcing RFC 1918 private subnet blocking, cloud metadata rejection (`169.254.169.254`), and loopback blocking (`127.0.0.1`).
- **TLS/SSL Evaluation**: Certificate validity, expiration warnings, hostname mismatch, HTTP-to-HTTPS redirect posture.
- **Security Headers**: Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy.
- **Cookie Security**: Zero raw cookie exposure (`name=REDACTED`), evaluation of `Secure`, `HttpOnly`, and `SameSite` flags.
- **CORS & Exposure**: Wildcard origin reflection, credential reflection, server banner disclosures.
- **Status**: **LOCALLY VERIFIED & PRODUCTION DEPLOYED**.

### Phase 3: Project Management & Target Ownership
- **Project Ownership**: Strict tenant scoping preventing cross-account access (IDOR protection).
- **Target Authorization**: Mandatory `authorization_confirmed=True` confirmation before scan execution.
- **Lifecycle & Cascading**: Multi-scan tracking, finding status preservation across rescans, cascade deletion.
- **Status**: **LOCALLY VERIFIED & PRODUCTION DEPLOYED**.

### Phase 4: Finding Lifecycle & Vulnerability Triage Hub
- **OCC Versioning**: Optimistic concurrency control (`version`) preventing race conditions during concurrent triage.
- **Mandatory Justification**: Strict validation requiring non-empty rationale for `accepted_risk` and `false_positive` transitions.
- **Immutable Audit Trail**: `finding_status_events` table backed by PostgreSQL and SQLite immutability triggers.
- **Findings Hub UI**: Centralized filtering, keyword search, severity cards, and interactive modal triage.
- **Status**: **LOCALLY VERIFIED**.

### Phase 5: Risk Analytics & Scoring Dashboard
- **Deterministic Posture Scoring**: 0–100 posture scoring engine with severity deductions and ceiling caps (Critical caps score at 49).
- **Domain Breakdown**: 6-domain security posture breakdown (TLS, Headers, Cookies, CORS, Exposure, Config).
- **Chronological Posture Trends**: Delta tracking and trajectory direction ('improving', 'degrading', 'stable').
- **Project Leaderboard**: Risk index ranking (100 - posture score) and critical finding density.
- **Status**: **LOCALLY VERIFIED**.

### Phase 6: Repository Security (SAST & SCA)
- **Secret Detection**: High-entropy regex scanning for AWS keys, GitHub PATs, private keys, Slack tokens, and JWT secrets. All secrets strictly masked (`AKIA****MPLE`).
- **SAST Pattern Engine**: Non-destructive static analysis for SQL injection string concat, command injection (`os.system`), deserialization, and insecure crypto.
- **SCA Dependency Auditor**: Manifest parser for `package.json` and `requirements.txt` mapped against CVE vulnerability identifiers.
- **Execution Boundary**: Text-only virtual scanning; untrusted repository code is never executed.
- **Status**: **LOCALLY VERIFIED**.

### Phase 7: API Security Assessment
- **OpenAPI Ingestion**: JSON and YAML parser supporting OpenAPI 3.0 and Swagger 2.0 specifications.
- **OWASP API Top 10**: Automated evaluation of missing route authentication, excessive data exposure, unconstrained parameters, and insecure transport.
- **Endpoint Inventory**: Categorized catalog of all API endpoints with HTTP verbs, authentication types, and risk flags.
- **Analysis Distinction**: Clearly demarcated as Static Specification Analysis.
- **Status**: **LOCALLY VERIFIED**.

### Phase 8: Cloud Security Posture Management (CSPM)
- **Multi-Cloud CIS Benchmarks**: Read-only audits for AWS, GCP, and Supabase.
- **Audit Rules**: S3 public bucket access, unencrypted storage volumes, root MFA omission, wildcard IAM privileges (`*:*`), stale access keys (>90 days), public ingress on ports 22/3389/5432, Supabase Row Level Security (RLS) disabled.
- **Credential Masking**: IAM role ARNs and secrets masked (`arn:aws:iam::****:role/...`).
- **Connection Demarcation**: Transparently displays integration status (`Awaiting Live Cloud Credentials • Simulated CIS Baseline Audit` vs. `Live Connected`).
- **Status**: **LOCALLY VERIFIED**.

### Phase 9: Reports & Export Engine
- **Downloadable PDF Engine**: Pure-Python standard PDF 1.4 document builder generating multi-page binary PDF files without third-party C dependencies.
- **Supported Report Types**: Executive Posture, Project Security, Vulnerability Catalog, Risk Analytics, Repository Security, API Security, Cloud Security, and Compliance Evidence.
- **Spreadsheet Export**: Streaming UTF-8 CSV with Byte Order Mark (BOM) for Excel and BI tools.
- **Machine-Readable Posture**: Full JSON posture bundle with OWASP Web, OWASP API, and CIS Cloud compliance control mappings.
- **Status**: **LOCALLY VERIFIED**.

### Phase 10: Settings, Preferences & Session Controls
- **User Profile**: Display name customization and tenant metadata.
- **Password Management**: Bcrypt/Argon2id credential update requiring current password verification.
- **Active Session Inspector**: Enumerate active devices with IP, user-agent, and last active timestamp. Per-device revocation and bulk `revoke-others`.
- **Scanner & Notification Preferences**: Persisted user settings (`user_settings` table) for scanner timeout, redirect limits, SSL enforcement, strict headers, email alerts, and default scan cadence.
- **Status**: **LOCALLY VERIFIED**.

### Phase 11: Integrations, Scheduling & SIEM Automation
- **Webhook Delivery Engine**: Real-time security alerts with SSRF validation, HTTPS protocol enforcement, and HMAC-SHA256 signatures (`X-Sentriq-Signature`).
- **Automated Cadence**: Recurring scan schedules (Daily, Weekly, Monthly) with on-demand immediate execution trigger (`POST /api/integrations/schedules/{id}/run`).
- **SIEM Event Stream**: Common Event Format (CEF) log exporter for Splunk, Microsoft Sentinel, and Datadog.
- **Status**: **LOCALLY VERIFIED**.

### Phase 12: Enterprise Governance & Multi-Tenant RBAC
- **Workspaces & Organizations**: Multi-tenant workspace creation, switching, and team invitations.
- **Role-Based Access Control**: Granular roles: `owner`, `admin`, `analyst`, `auditor`.
- **Sole Owner Protection**: Application-level and service-level guardrails preventing accidental demotion or removal of the last remaining owner.
- **Compliance Audit Logs**: Immutable activity logs capturing workspace creation, role updates, and member removal.
- **Status**: **LOCALLY VERIFIED**.

---

## 3. Future Horizon (Post-Release Milestones)

| Milestone | Target Capability | Description |
| :--- | :--- | :--- |
| **v1.1** | **Distributed Worker Pool** | Celery/Redis or Temporal asynchronous background workers for high-volume concurrent scans. |
| **v1.2** | **Dynamic API Fuzzing** | Active automated fuzz testing for OpenAPI endpoints within an isolated sandbox. |
| **v1.3** | **Jira & ServiceNow Sync** | Bi-directional ticket synchronization for finding remediation tracking. |
| **v1.4** | **Custom DAST Plugins** | Pluggable rule architecture allowing enterprise security teams to author custom YAML/Python checks. |
| **v2.0** | **Automated Compliance Evidence** | Automated evidence gathering for SOC 2 Type II, ISO 27001, and HIPAA audits. |
