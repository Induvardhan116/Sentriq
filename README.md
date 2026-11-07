# Sentriq — Application Security Intelligence Platform

Sentriq is a production-grade, full-lifecycle defensive cybersecurity platform designed to continuously assess, correlate, and score the security posture of web applications, source code repositories, API endpoints, and cloud infrastructure.

> **Responsible Security Notice**: Sentriq performs safe, authorized, non-destructive security checks (HTTPS/TLS configuration, response headers, cookie flags, CORS policies, information disclosure, repository SAST/SCA/secrets, OpenAPI specifications, and read-only CSPM audits). It does **not** conduct intrusive exploitation, denial of service, or brute force attacks. Users must explicitly confirm target authorization prior to testing.

---

## Master Architecture & Capabilities (Phases 1–12 Complete)

Sentriq delivers an end-to-end cybersecurity posture management solution across 12 integrated phases:

1. **Authentication & Identity**:
   - Secure Argon2id / Bcrypt password hashing, email verification, password reset flows.
   - Per-device session rotation, CSRF token verification, and generic error responses preventing account enumeration.
   - GitHub OAuth with atomic one-time state consumption (`OAuthState`) preventing CSRF and replay attacks.
   - Progressive throttle delay with IP flood bounds preventing denial-of-service victim lockout.

2. **Website Security Scanner**:
   - SSRF protection layer with DNS resolution and private network blocking (RFC 1918, RFC 3927, loopback, cloud metadata).
   - Non-destructive HTTPS/TLS assessment, SSL certificate expiration check, hostname mismatch validation.
   - Comprehensive security headers (`CSP`, `HSTS`, `X-Content-Type-Options`, `X-Frame-Options`, `Permissions-Policy`).
   - Cookie security validation with **zero raw cookie value leakage** (`name=REDACTED`).
   - CORS policy analysis (wildcards, credentials reflection, null origins) and information exposure detection.

3. **Project Management & Ownership**:
   - Cryptographically isolated tenant ownership.
   - Multi-scan history tracking with cascade deletion preserving user identity.
   - Target ownership confirmation requirement before scanning.

4. **Finding Lifecycle & Triage Hub**:
   - Centralized finding repository with multi-dimensional filtering, searching, and sorting.
   - Optimistic Concurrency Control (OCC) versioning (`version`) preventing race conditions during status triage.
   - Mandatory justification validation for `accepted_risk` and `false_positive` transitions.
   - Tamper-evident database audit log (`finding_status_events`) backed by immutability triggers.

5. **Risk Analytics & Scoring Engine**:
   - Multi-project posture scoring (0–100) with grade tiers (A through F).
   - Ceiling caps ensuring critical findings cap overall posture.
   - 6-domain security breakdown and historical posture trend calculations.
   - Automated project risk ranking based on risk index and critical density.

6. **Repository Security (SAST & SCA)**:
   - Safe regex/AST secret detection with zero raw credential leakage (all secrets masked as `AKIA****MPLE`).
   - SAST pattern analyzer detecting OWASP Top 10 vulnerabilities (SQLi, command injection, deserialization, path traversal).
   - SCA dependency scanner mapping manifest files (`package.json`, `requirements.txt`) against CVE databases.

7. **API Security Assessment**:
   - OpenAPI 3.0 and Swagger 2.0 parser (JSON & YAML).
   - Ingests endpoint inventories with authentication scheme analysis.
   - OWASP API Security Top 10 automated checks (broken object auth, excessive data exposure, rate limit omissions, insecure transport).

8. **Cloud Security Posture (CSPM)**:
   - Read-only multi-cloud audits against CIS benchmarks for AWS, GCP, and Supabase.
   - Checks for public S3 buckets, unencrypted disks, root MFA omission, wildcard IAM permissions (`*:*`), stale credentials, open security groups (ports 22, 3389, 5432).
   - **Demarcation Transparency**: Clear UI badges and API fields distinguishing between simulated CIS baseline audits and live IAM credential audits.

9. **Reports & Pure-Python PDF Engine**:
   - Pure-Python standard PDF 1.4 document builder (`PurePDFDocument`, `SentriqPdfReportBuilder`) with zero external C-binary dependencies.
   - Generates downloadable multi-page PDF documents across 8 report types (`executive`, `project`, `vulnerability`, `risk`, `repo`, `api`, `cloud`, `compliance`).
   - Standalone printable HTML executive report with print stylesheets (`@page`, `@media print`).
   - Streaming UTF-8 CSV exporter with byte order mark (BOM) for native Excel compatibility.
   - Comprehensive structured JSON posture bundle mapped to OWASP and CIS benchmarks.

10. **Settings, Session Management & Preferences**:
    - `UserSettings` model and preferences persistence (`/api/settings/preferences`) for scanner timeout, max redirects, SSL verification toggle, strict headers toggle, and notification flags.
    - User profile customization and password update with credential validation.
    - Active device session inspector with IP, user-agent, and last activity timestamp.
    - Per-device revocation and one-click bulk revocation (`revoke-others`).

11. **Integrations & Alerting**:
    - Outbound webhook delivery system with strict HTTPS enforcement, SSRF validation, and HMAC-SHA256 signatures (`X-Sentriq-Signature`).
    - Automated recurring scan scheduler (daily, weekly, monthly) with immediate on-demand execution (`POST /api/integrations/schedules/{id}/run`).
    - Common Event Format (CEF) SIEM log exporter for Splunk, Datadog, or Microsoft Sentinel.

12. **Enterprise Governance & RBAC**:
    - Organization workspaces with Role-Based Access Control (`owner`, `admin`, `analyst`, `auditor`).
    - Sole owner protection rule preventing accidental removal or demotion of the last remaining owner.
    - Tamper-evident workspace compliance audit logs with PostgreSQL/SQLite immutability triggers.

---

## Complete Documentation Index

For in-depth technical specifications, architectural designs, API contracts, and runbooks:

- [ROADMAP.md](file:///d:/Sentriq/ROADMAP.md) — Master milestone progress, completed phases 1-12, and future v1.1-v2.0 roadmap.
- [ARCHITECTURE.md](file:///d:/Sentriq/ARCHITECTURE.md) — System topology, Mermaid architecture diagrams, security layers, and Pure-Python PDF engine design.
- [API_DOCUMENTATION.md](file:///d:/Sentriq/API_DOCUMENTATION.md) — Comprehensive REST API reference across all 13 router modules.
- [DATABASE_SCHEMA.md](file:///d:/Sentriq/DATABASE_SCHEMA.md) — Complete 25-table database schema, indexes, relationships, and immutability triggers.
- [SECURITY.md](file:///d:/Sentriq/SECURITY.md) — Application security posture, SSRF defense, Argon2id, session rotation, CSRF, and threat models.
- [DEPLOYMENT.md](file:///d:/Sentriq/DEPLOYMENT.md) — Production deployment runbook for Vercel, Render, and Supabase PostgreSQL.
- [ENVIRONMENT_VARIABLES.md](file:///d:/Sentriq/ENVIRONMENT_VARIABLES.md) — Full configuration reference for backend and frontend environments.
- [TESTING.md](file:///d:/Sentriq/TESTING.md) — Testing guide, test suite breakdown, fixtures, and regression workflows.
- [CHANGELOG.md](file:///d:/Sentriq/CHANGELOG.md) — Detailed chronological record of all features, fixes, and architectural milestones.
- [PROJECT_STATUS.md](file:///d:/Sentriq/PROJECT_STATUS.md) — Current implementation matrix and test verification results.

---

## Directory Structure

```
Sentriq/
├── backend/                              # FastAPI Asynchronous Core
│   ├── app/
│   │   ├── api/                          # Modular API Routers
│   │   │   ├── auth.py                   # Authentication, registration, OAuth, sessions
│   │   │   ├── system.py                 # GET /api/system/health, GET /api/system/info
│   │   │   ├── projects.py               # Projects CRUD & scan launching
│   │   │   ├── scans.py                  # Scan status, score, and summary
│   │   │   ├── findings.py               # Findings Hub, triage, OCC versioning, audit trail
│   │   │   ├── analytics.py              # Posture trends, project risk rankings
│   │   │   ├── repositories.py           # SAST, SCA, and secret scanning
│   │   │   ├── api_security.py           # OpenAPI ingestion & OWASP API Top 10
│   │   │   ├── cloud_security.py         # Multi-cloud CSPM audits
│   │   │   ├── reports.py                # Pure-Python PDF, Executive HTML, CSV, JSON
│   │   │   ├── settings.py               # Profile, password, preferences, sessions
│   │   │   ├── integrations.py           # Webhooks, schedules, immediate execution, SIEM
│   │   │   └── workspaces.py             # RBAC organizations & compliance audit logs
│   │   ├── config.py                     # Pydantic Settings & environment validation
│   │   ├── database/                     # SQLAlchemy 2.0 Async Session & migrations
│   │   ├── models/                       # SQLAlchemy declarative models (25 entities)
│   │   ├── schemas/                      # Pydantic validation schemas
│   │   ├── security/                     # Argon2id/Bcrypt hashing, CSRF, IP proxy extraction
│   │   ├── services/                     # Pure-Python PDF builder & reporting services
│   │   └── scanners/                     # Security scanner modules
│   │       ├── web/                      # Non-destructive website security scanner
│   │       ├── repo/                     # SAST, SCA, and masked secret scanner
│   │       ├── api_sec/                  # OpenAPI / Swagger analyzer
│   │       └── cloud/                    # CIS benchmark CSPM analyzer
│   └── tests/                            # 221 Automated Async Unit & Integration Tests
│
├── frontend/                             # Vite + React 18 + TypeScript Client
│   ├── src/
│   │   ├── components/                   # Views: Projects, FindingsHub, RiskAnalytics, RepoSecurity,
│   │   │                                 # ApiSecurity, CloudSecurity, Reports, Settings, Integrations, Workspaces
│   │   ├── context/                      # AuthContext session & user state management
│   │   ├── services/                     # Typed API client with friendly HTTP 503 handling
│   │   ├── types/                        # TypeScript interfaces for all 12 modules
│   │   ├── utils/                        # Route parsing, finding status math, risk calculators
│   │   └── index.css                     # Dark cybersecurity design system
│   └── tests/                            # 98 Automated Frontend Unit Tests
│
├── API_DOCUMENTATION.md                  # Complete API reference
├── ARCHITECTURE.md                       # Architecture design & Mermaid diagrams
├── CHANGELOG.md                          # Release log
├── DATABASE_SCHEMA.md                    # Database entity dictionary & ER diagrams
├── DEPLOYMENT.md                         # Vercel / Render / Supabase runbook
├── ENVIRONMENT_VARIABLES.md              # Environment variables reference
├── PROJECT_STATUS.md                     # Master implementation progress matrix
├── ROADMAP.md                            # Milestone roadmap
├── SECURITY.md                           # Threat model & security protections
├── TESTING.md                            # Testing guide & execution commands
├── vercel.json                           # Frontend deployment & reverse-proxy configuration
└── render.yaml                           # Backend deployment configuration
```

---

## Running the Application Locally

### 1. Backend Setup

```powershell
# Activate python virtual environment
.\.venv\Scripts\activate   # Windows (or source .venv/bin/activate on Linux/macOS)

# Run full backend test suite (221 tests)
pytest backend/tests -v

# Start FastAPI server on port 8000
uvicorn backend.app.main:app --reload --port 8000
```

### 2. Frontend Setup

```powershell
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Run full frontend unit test suite (98 tests)
npm test

# Build production bundle (TypeScript verification + Vite bundle)
npm run build

# Start frontend development server on port 5173
npm run dev
```

---

## Verification & Test Results

- **Backend Test Suite**: **221 passed, 0 failed** (`pytest backend/tests -v`)
- **Frontend Test Suite**: **98 passed, 0 failed** (`npm --prefix frontend test`)
- **Frontend Production Build**: **Clean build with 0 TypeScript errors** (`tsc -b && vite build`)
- **Security Compliance**:
  - `AUTH_ENABLED=false` and `PRODUCTION_AUTH_VERIFIED=false` held for safe pre-production staging.
  - Mandatory justification on high-impact triage actions.
  - Zero raw credential or secret storage.
  - Private network SSRF fail-closed boundaries.
