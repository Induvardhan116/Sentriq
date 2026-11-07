# Sentriq — Complete REST API Documentation

> **Base URL**: `https://sentriq.onrender.com/api` (Production) / `http://localhost:8000/api` (Local)
> **Protocol**: HTTPS (Production) / HTTP (Local)
> **Content-Type**: `application/json` (unless specified otherwise)
> **Authentication**: Cookie-based session (`sentriq_session`) with `X-CSRF-Token` header for mutations.

---

## 1. System & Health Diagnostics

### `GET /api/system/health`
Canonical system and database health probe.
- **Access**: Public
- **Response `200 OK`**:
```json
{
  "status": "healthy",
  "database": "connected",
  "auth_enabled": false,
  "environment": "production",
  "version": "1.0.0-rc",
  "timestamp": "2026-11-07T14:00:00Z"
}
```

---

## 2. Authentication & Identity (`/api/auth`)

| Method | Endpoint | Description | Auth Required | CSRF Required |
| :--- | :--- | :--- | :---: | :---: |
| `POST` | `/api/auth/register` | Register new user account with email/password | No | No |
| `POST` | `/api/auth/login` | Authenticate with credentials & rotate session | No | No |
| `POST` | `/api/auth/logout` | Revoke session and clear session cookie | Yes | Yes |
| `GET` | `/api/auth/me` | Fetch authenticated user identity and role | Yes | No |
| `POST` | `/api/auth/verify-email` | Validate email verification token | No | No |
| `POST` | `/api/auth/password-reset-request` | Request password reset email (Anti-enumeration) | No | No |
| `POST` | `/api/auth/password-reset-confirm` | Reset password using one-time cryptographic token | No | No |
| `GET` | `/api/auth/github` | Initiate GitHub OAuth authorization | No | No |
| `GET` | `/api/auth/github/callback` | Atomic one-time OAuth state exchange | No | No |

---

## 3. Projects & Target Management (`/api/projects`)

### `POST /api/projects`
Create an authorized scanning target.
- **Payload**:
```json
{
  "name": "Acme SaaS Web Portal",
  "target_url": "https://portal.acme.com",
  "authorization_confirmed": true
}
```

### `GET /api/projects`
List projects owned by the authenticated tenant.

### `GET /api/projects/{id}`
Retrieve project details and chronological scan history.

### `PATCH /api/projects/{id}`
Update target project name or URL (triggers SSRF validation).

### `DELETE /api/projects/{id}`
Delete target project and cascade delete associated scans and findings.

### `POST /api/projects/{id}/scans`
Launch a safe, non-destructive background security assessment.

---

## 4. Website Scans & Results (`/api/scans`)

### `GET /api/scans/{id}`
Retrieve scan status (`queued`, `running`, `completed`, `failed`), score (0-100), and grade.

### `GET /api/scans/{id}/findings`
List findings for a specific scan sorted by risk score.

### `GET /api/scans/{id}/summary`
Get aggregate severity and category breakdown for a scan.

---

## 5. Finding Lifecycle & Triage Hub (`/api/findings`)

### `GET /api/findings`
Multi-dimensional query for centralized findings.
- **Query Parameters**:
  - `project_id` (string): Filter by target project.
  - `scan_id` (string): Filter by scan instance.
  - `severity` (string): `critical`, `high`, `medium`, `low`, `informational`.
  - `status` (string): `open`, `in_progress`, `resolved`, `false_positive`, `accepted_risk`.
  - `category` (string): Filter by security category (`Headers`, `Cookies`, `TLS`, `CORS`, `Exposure`).
  - `search` (string): Free text search in title, description, or remediation.
  - `page` (int, default 1): Page number.
  - `page_size` (int, default 20): Items per page.
  - `sort_by` (string): `risk_score`, `severity`, `created_at`, `status`.
  - `sort_order` (string): `asc`, `desc`.

### `PATCH /api/findings/{id}`
Triage finding lifecycle with Optimistic Concurrency Control (OCC).
- **Payload**:
```json
{
  "status": "accepted_risk",
  "expected_version": 1,
  "justification": "Risk accepted by CISO due to internal VPC network boundary controls."
}
```
- **Response**: `200 OK` on success, `409 Conflict` if version mismatch detected.

### `GET /api/findings/{id}/history`
Fetch chronological, immutable audit timeline of status changes from `finding_status_events`.

---

## 6. Risk Analytics & Scoring (`/api/analytics`)

### `GET /api/analytics/risk-summary`
Returns multi-project posture scores, active severity counts, 6-domain breakdown, and MTTR metrics.

### `GET /api/analytics/posture-trends`
Returns chronological posture assessment trends, score deltas, and trajectory direction.

### `GET /api/analytics/project-rankings`
Returns monitored projects ranked by risk index (`100 - posture_score`) and critical density.

---

## 7. Repository Security Analysis (`/api/repositories`)

### `POST /api/repositories`
Connect repository with safe HTTPS git URL.

### `GET /api/repositories`
List connected repositories with latest scan status and scores.

### `POST /api/repositories/{id}/scan`
Trigger SAST, SCA, and masked secret detection scan.

### `GET /api/repositories/{id}/findings`
List normalized repository findings with masked secret snippets (`AKIA****MPLE`).

### `PATCH /api/repositories/findings/{id}`
Triage repository finding status with mandatory justification.

---

## 8. API Security Assessment (`/api/api-security`)

### `POST /api/api-security/specs`
Import OpenAPI 3.0 / Swagger 2.0 specification in JSON or YAML format.

### `GET /api/api-security/specs`
List imported API specifications with posture scores.

### `GET /api/api-security/specs/{id}/endpoints`
List parsed API endpoints with HTTP methods, tags, and authentication scheme requirements.

### `GET /api/api-security/specs/{id}/findings`
List OWASP API Security Top 10 vulnerabilities discovered via static specification analysis.

---

## 9. Cloud Security Posture Management (`/api/cloud-security`)

### `POST /api/cloud-security/accounts`
Register cloud account (AWS, GCP, Supabase) with masked role ARNs.

### `GET /api/cloud-security/accounts`
List cloud integrations with connection status and CIS posture scores.

### `POST /api/cloud-security/accounts/{id}/scan`
Trigger CSPM audit against CIS Benchmarks.

### `GET /api/cloud-security/accounts/{id}/findings`
List cloud compliance violations (S3 public access, IAM wildcard admin, unencrypted volumes).

---

## 10. Reports & Compliance Export (`/api/reports`)

### `GET /api/reports/summary`
JSON summary of overall posture and cross-domain asset counts.

### `GET /api/reports/executive`
Standalone printable executive cybersecurity report in HTML format.

### `GET /api/reports/export/pdf?report_type={type}`
Download authentic multi-page PDF report (`application/pdf`).
- Supported `report_type`: `executive`, `project`, `vulnerability`, `risk`, `repo`, `api`, `cloud`, `compliance`.

### `GET /api/reports/export/csv`
Download findings spreadsheet in UTF-8 CSV with Byte Order Mark (BOM).

### `GET /api/reports/export/json`
Download full JSON posture bundle mapped to OWASP Web, OWASP API, and CIS Cloud benchmarks.

---

## 11. Settings, Preferences & Sessions (`/api/settings`)

### `GET /api/settings/profile`
Retrieve authenticated user profile.

### `PATCH /api/settings/profile`
Update user display name.

### `POST /api/settings/password`
Securely update password verifying current password with Bcrypt/Argon2id.

### `GET /api/settings/sessions`
Enumerate active sessions with IP, user-agent, and `is_current` device flag.

### `DELETE /api/settings/sessions/{id}`
Revoke specific active session token.

### `POST /api/settings/sessions/revoke-others`
Revoke all active sessions except the caller's current session.

### `GET /api/settings/preferences`
Retrieve user scanner and notification preferences.

### `PATCH /api/settings/preferences`
Update persisted preferences (timeouts, redirect limits, SSL verification, cadence).

---

## 12. Integrations & SIEM Automation (`/api/integrations`)

### `POST /api/integrations/webhooks`
Register outbound webhook with SSRF validation and HMAC secret key.

### `POST /api/integrations/webhooks/{id}/test`
Send test ping verifying payload delivery and `X-Sentriq-Signature`.

### `POST /api/integrations/schedules`
Create recurring automated scan schedule (`daily`, `weekly`, `monthly`).

### `POST /api/integrations/schedules/{id}/run`
Trigger immediate execution of a scheduled recurring assessment.

### `GET /api/integrations/siem/events`
Stream security findings in Common Event Format (CEF) for Splunk, Sentinel, or Datadog.

---

## 13. Enterprise Governance & Workspaces (`/api/workspaces`)

### `POST /api/workspaces`
Create a new organization workspace.

### `GET /api/workspaces`
List workspaces the user is a member of.

### `GET /api/workspaces/{id}/members`
List workspace team members with RBAC roles (`owner`, `admin`, `analyst`, `auditor`).

### `POST /api/workspaces/{id}/members/invite`
Invite a new user to the workspace with a specified role.

### `PATCH /api/workspaces/{id}/members/{user_id}/role`
Update member role (protected by Sole Owner Protection rule).

### `DELETE /api/workspaces/{id}/members/{user_id}`
Remove team member from workspace (protected by Sole Owner Protection rule).

### `GET /api/workspaces/{id}/audit-logs`
Fetch tamper-evident compliance audit trail for workspace administrative actions.
