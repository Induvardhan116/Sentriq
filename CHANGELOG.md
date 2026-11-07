# Sentriq — Changelog

All notable changes, architectural implementations, and enhancements across the Sentriq cybersecurity platform.

---

## [1.0.0] — 2026-11-07 — Master Platform Completion (All 12 Phases)

### Phase 1 — Core Architecture, Database Foundation & Diagnostics
- Initialized FastAPI asynchronous backend with SQLAlchemy 2.0 Async (`asyncpg` for PostgreSQL in production, `aiosqlite` for local dev/testing).
- Implemented automated database migration engine (`backend/app/database/migrations.py`) to initialize 25 entities and indexes.
- Added system health and diagnostics endpoints (`/api/system/health`, `/api/system/info`) with real-time database connection status.
- Configured Vite React 19 frontend Single Page Application with clean component architecture and dark cybersecurity theme.

### Phase 2 — Authentication, Authorization & Security Hardening
- Implemented Argon2id password hashing with custom salt generation.
- Built JWT session token issuance and rotating refresh token architecture with secure cookie storage (`HttpOnly`, `Secure`, `SameSite=None/Lax`).
- Added CSRF double-submit cookie protection with token rotation.
- Added email verification tokens and password reset workflows via Resend transactional email integration.
- Implemented sliding-window rate limiting per IP address to defend against brute-force and credential stuffing attacks.
- Configured production safety interlocks (`AUTH_ENABLED` and `PRODUCTION_AUTH_VERIFIED`).

### Phase 3 — Active & Passive Vulnerability Scanning Engine
- Built asynchronous scanner service supporting concurrent multi-target scanning.
- Implemented SSRF (Server-Side Request Forgery) protection blocking loopback (`127.0.0.1`), RFC 1918 private subnets, and cloud metadata IP ranges (`169.254.169.254`).
- Added active probes: TLS/SSL handshake analysis, missing security headers (`HSTS`, `CSP`, `X-Frame-Options`), open port detection, and CORS misconfiguration checks.
- Implemented scan lifecycle tracking (`QUEUED`, `SCANNING`, `COMPLETED`, `FAILED`) with real-time UI status polling.

### Phase 4 — Vulnerability Management & Triage
- Developed unified vulnerability registry with standardized CVSS v3.1 scoring, CVE correlation, and CWE classification.
- Added vulnerability triage state machine (`OPEN`, `CONFIRMED`, `RESOLVED`, `FALSE_POSITIVE`).
- Implemented multi-criteria filtering by severity, category, status, and target.
- Added sliding drawer view for comprehensive finding remediation steps and remediation verification.

### Phase 5 — Risk Analytics, Scoring & Threat Intelligence
- Developed composite risk score engine calculating organization-wide posture metrics (0-100 scale and letter grades A-F).
- Integrated threat intelligence feed aggregator with CVE search, known exploited vulnerabilities (KEV), and IoC tracking.
- Added remediation prioritization matrix ranking vulnerabilities by exploitability and asset criticality.
- Added interactive risk breakdown charts and trend visualizations.

### Phase 6 — Repository Security & SAST Engine
- Implemented static application security testing (SAST) for source code repositories.
- Added high-entropy secret detection with regex patterns for 20+ secret types (AWS keys, GitHub tokens, private keys, database URLs).
- Added dependency vulnerability scanning to identify out-of-date or vulnerable packages.
- Added branch selection and scan summary dashboards.

### Phase 7 — API Security & Schema Inspection
- Built OpenAPI 3.0 and Swagger specification parser.
- Implemented OWASP API Security Top 10 rule engine detecting:
  - Broken Object Level Authorization (BOLA / IDOR)
  - Broken Authentication & lack of security schemes
  - Broken Object Property Level Authorization & Mass Assignment
  - Unrestricted Resource Consumption & missing rate limiting
  - Security Misconfigurations and unencrypted endpoints
- Added interactive endpoint catalog displaying security status per HTTP method and path.

### Phase 8 — Cloud Security Posture Management (CSPM)
- Developed multi-cloud assessment engine for AWS, Google Cloud, and Microsoft Azure.
- Implemented CIS Benchmark compliance rules across IAM, storage buckets, network security groups, and encryption.
- Added transparent UI and API demarcation: clearly distinguishing between `Simulated CIS Baseline Audit` (when credentials are not provided) vs. `Connected (Read-Only IAM)`.
- Added compliance breakdown across frameworks (CIS, SOC 2, ISO 27001, HIPAA).

### Phase 9 — Reports & Downloadable Pure-Python PDF Engine
- Built a zero-dependency, pure-Python PDF 1.4 document generator (`PurePDFDocument`, `SentriqPdfReportBuilder`) in `backend/app/services/pdf_generator.py`.
- Generates downloadable multi-page PDF documents across all 8 report types:
  1. `executive`: High-level executive posture summary, key KPIs, letter grades, and top recommendations.
  2. `vulnerability`: Complete vulnerability inventory with CVSS scores and technical descriptions.
  3. `risk`: In-depth risk exposure analysis and posture breakdown.
  4. `repo`: Code repository SAST findings and detected secret leaks.
  5. `api`: OpenAPI inventory, OWASP API Top 10 findings, and endpoint security statuses.
  6. `cloud`: CSPM findings, CIS benchmark compliance, and cloud inventory.
  7. `compliance`: Multi-standard compliance scores and audit status.
  8. `project`: Project-scoped comprehensive assessment report.
- Added endpoint `GET /api/reports/export/pdf?report_type={type}` returning `application/pdf` with `Content-Disposition: attachment`.
- Updated `ReportsView.tsx` with scope dropdown, primary "Download PDF (.pdf)" action, and printable HTML modal view.

### Phase 10 — Settings, User Preferences & Persistence
- Created `UserSettings` database model in `backend/app/models/settings.py` and registered in migration sequence.
- Added API endpoints `GET /api/settings/preferences` and `PATCH /api/settings/preferences`.
- Persists user preferences:
  - Scanner timeout (10-120 seconds)
  - Max redirects (0-10)
  - SSL certificate verification toggle
  - Strict security headers enforcement toggle
  - Email notification toggles (scan completion, critical alerts)
  - Webhook dispatch toggle
  - Scan cadence preferences
  - Session timeout configurations
- Added Preferences Tab in `SettingsView.tsx` with live form binding, dirty state tracking, and persistence notifications.

### Phase 11 — Integrations & Automation Engine
- Added webhook configuration management and payload signing.
- Added recurring scan schedule management (daily, weekly, monthly).
- Added immediate scan schedule execution endpoint: `POST /api/integrations/schedules/{schedule_id}/run`.
- Added "Run Now" action button in `IntegrationsView.tsx` to trigger scheduled jobs on demand with instant feedback.
- Added API key management with prefix hashing and masking.

### Phase 12 — Workspaces, Multi-Tenancy & Immutability Ledger
- Implemented workspace multi-tenancy with member invitation and role assignment (`Owner`, `Admin`, `Analyst`, `Viewer`).
- Built append-only `AuditLog` entity recording all user actions, scan launches, setting updates, and authentication events.
- Created database triggers blocking `UPDATE` and `DELETE` operations on the audit log table, ensuring an untamperable audit trail.
- Added comprehensive audit log viewer with actor filtering, event type filtering, and timestamp sorting.

---

## Quality & Verification Summary
- **Backend Tests**: 221 / 221 passed (100% pass rate).
- **Frontend Tests**: 98 / 98 passed (100% pass rate).
- **Build Status**: TypeScript (`tsc -b`) and Vite production build pass cleanly with 0 errors.
- **Security Audit**: Zero credential exposure, masked tokens in logs, SSRF protection active, CSRF protection active.
