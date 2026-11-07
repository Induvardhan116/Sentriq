# Sentriq — Testing & Quality Assurance Guide

Comprehensive test suite documentation, execution instructions, fixtures, and regression testing standards for the Sentriq platform.

---

## 1. Test Architecture Overview

Sentriq enforces automated testing across both backend and frontend layers:

```
+---------------------------------------------------------------------------------+
|                                 TEST HARNESS                                    |
+----------------------------------------+----------------------------------------+
|             BACKEND TESTS              |             FRONTEND TESTS             |
|          (pytest / pytest-asyncio)     |         (Vitest / React Testing Lib)   |
|         221 Tests Passing (100%)       |           98 Tests Passing (100%)      |
+----------------------------------------+----------------------------------------+
| * Unit Tests: Models, Schemas, Utils   | * Component Render & State Tests       |
| * Service Logic: PDF Generator, Risk,  | * Form Validation & Error State Tests  |
|   Repo, API & Cloud Security Engines   | * API Service Client Tests             |
| * API Integration: 13 Router Modules   | * Tab Navigation & Modal Interactions  |
| * Security Tests: CSRF, Auth, SSRF     | * Download Trigger & Event Handlers    |
| * Migration & DB Integrity Fixtures    | * TypeScript Typecheck (`tsc -b`)      |
+----------------------------------------+----------------------------------------+
```

---

## 2. Backend Automated Testing

The backend test suite is powered by **pytest** and **pytest-asyncio**, testing asynchronous FastAPI route handlers, database persistence, and service engines against an isolated async SQLite test database.

### 2.1 Running Backend Tests

Run the full backend test suite:
```powershell
.venv\Scripts\pytest backend\tests -v
```

Run a specific test module:
```powershell
.venv\Scripts\pytest backend\tests\test_reports_api.py -v
.venv\Scripts\pytest backend\tests\test_settings_api.py -v
.venv\Scripts\pytest backend\tests\test_integrations_api.py -v
.venv\Scripts\pytest backend\tests\test_risk_analytics_api.py -v
.venv\Scripts\pytest backend\tests\test_cloud_security_api.py -v
.venv\Scripts\pytest backend\tests\test_api_security_api.py -v
.venv\Scripts\pytest backend\tests\test_repo_security_api.py -v
```

Run tests with keyword matching:
```powershell
.venv\Scripts\pytest backend\tests -k "pdf or preferences or schedule" -v
```

### 2.2 Test Suite Breakdown (221 Tests)

| Test Module | Coverage Area | Key Test Cases |
| :--- | :--- | :--- |
| `test_reports_api.py` | Phase 9 Reports & PDF Export | PDF binary generation, valid `%PDF-1.4` headers, all 8 report types (`executive`, `vulnerability`, `risk`, `repo`, `api`, `cloud`, `compliance`, `project`), HTML report generation, scope validation. |
| `test_settings_api.py` | Phase 10 Settings & Preferences | `UserSettings` model creation, preference updates (`timeout`, `verify_ssl`, `email_alerts`, `cadence`), validation errors, system info retrieval. |
| `test_integrations_api.py` | Phase 11 Integrations & Schedules | Webhook CRUD, scan schedule creation, immediate scan schedule execution (`POST /schedules/{id}/run`), API key generation. |
| `test_risk_analytics_api.py` | Phase 5 Risk Analytics & Scoring | Dynamic risk scoring calculations, CVSS aggregation, threat intel correlation, posture letter grades (A-F), remediation priorities. |
| `test_repo_security_api.py` | Phase 6 Repository Security | Git repo scanning, secret detection regex, SAST pattern matches, dependency vulnerability analysis. |
| `test_api_security_api.py` | Phase 7 API Security | OpenAPI 3.0 / Swagger spec parsing, OWASP API Top 10 rule checks (BOLA, broken auth, lack of rate limiting). |
| `test_cloud_security_api.py` | Phase 8 Cloud Security (CSPM) | Multi-cloud resource audit, CIS baseline compliance checks, simulated vs. live IAM connection status demarcation. |
| `test_auth_api.py` | Authentication & Security | Password hashing with Argon2id, login, registration, JWT session issuance, refresh token rotation, logout, CSRF protection. |
| `test_scans_api.py` | Active & Passive Scanners | Target creation, scan dispatch, status polling, lifecycle state transitions (`QUEUED`, `SCANNING`, `COMPLETED`, `FAILED`). |
| `test_vulnerabilities_api.py` | Vulnerability Management | Finding listing, severity filtering, status triage (`OPEN`, `CONFIRMED`, `RESOLVED`, `FALSE_POSITIVE`). |
| `test_audit_logs_api.py` | Immutability & Ledger | Tamper-evident event recording, filtering by actor and workspace, write-only immutability safeguards. |
| `test_system_api.py` | Diagnostics & Health | Health probe `/api/system/health`, DB ping, version reporting, diagnostic metrics. |

### 2.3 Fixtures & Test Isolation (`conftest.py`)
- **`async_client`**: An `httpx.AsyncClient` bound to the FastAPI application with dependency overrides.
- **`db_session`**: Creates a fresh in-memory SQLite database (`sqlite+aiosqlite:///:memory:`) before each test, automatically executing database schema migrations to ensure 100% test isolation.

---

## 3. Frontend Automated Testing

Frontend testing uses **Vitest** with **React Testing Library** and **jsdom** for headless component testing.

### 3.1 Running Frontend Tests

Run all unit tests:
```powershell
npm --prefix frontend test
```

Run tests in watch mode during UI development:
```powershell
npm --prefix frontend run test:watch
```

Run a specific component test file:
```powershell
npx vitest run src/components/ReportsView.test.ts
```

### 3.2 Frontend Test Suite Breakdown (98 Tests)

| Component Test File | Verified Functionality |
| :--- | :--- |
| `ReportsView.test.ts` | Report scope selector, PDF download trigger, `getPdfExportUrl` invocation, printable HTML modal, loading spinners, error states. |
| `SettingsView.test.ts` | Preferences tab rendering, form field binding (timeout, verify SSL, notification toggles), save action, success notifications. |
| `IntegrationsView.test.ts` | Webhooks and schedules roster, "Run Now" execution button handler, schedule trigger dispatch, integration status badges. |
| `CloudSecurityView.test.ts` | Cloud provider tabs (AWS, GCP, Azure), CIS benchmark compliance breakdown, "Awaiting Live Cloud Credentials • Simulated" badge demarcation. |
| `ApiSecurityView.test.ts` | OpenAPI spec file upload/paste, endpoint inventory table, OWASP API Top 10 security findings display. |
| `RepositorySecurityView.test.ts`| Git repository listing, SAST scan initiation, secret leak alerts, branch selection. |
| `RiskAnalyticsView.test.ts` | Posture score circular gauge, breakdown charts, remediation priority recommendations. |
| `DashboardView.test.ts` | Executive summary metrics, scan activity timeline, severity count badges, quick-action shortcuts. |
| `ScansView.test.ts` | Scan target submission modal, real-time status polling, scan cancel action, filter controls. |
| `VulnerabilitiesView.test.ts` | Severity filters, search query input, vulnerability detail drawer, triage status update dropdown. |
| `ThreatIntelView.test.ts` | Threat feed aggregation, CVE lookup search, IoC indicators, threat feed health status. |

---

## 4. Production Build Verification

To guarantee zero TypeScript errors, broken imports, or asset bundler failures:

```powershell
npm --prefix frontend run build
```

**Build Verification Criteria**:
- `tsc -b` completes with 0 errors and 0 type warnings.
- Vite bundles all 1,600+ modules into production assets in `frontend/dist/`.
- No missing CSS or JavaScript chunk errors.

---

## 5. End-to-End Simulation Workflow

To manually verify the full end-to-end user journey:

1. **Start Local Backend**:
   ```powershell
   .venv\Scripts\uvicorn backend.app.main:app --reload --port 8000
   ```
2. **Start Local Frontend**:
   ```powershell
   npm --prefix frontend run dev
   ```
3. **Execute Verification Checklist**:
   - Access `http://localhost:5173`.
   - Trigger a target scan on `https://example.com` in Scans.
   - Verify findings populate in Vulnerabilities.
   - Open Reports, generate an Executive Summary PDF, and verify downloaded file.
   - Open Settings, alter Scanner Timeout to `45`, and save preferences.
   - Open Integrations, click "Run Now" on a schedule, and observe instant scan trigger.
