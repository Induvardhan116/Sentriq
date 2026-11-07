# Sentriq — Production Deployment Runbook

Comprehensive guide for deploying and maintaining the Sentriq Cybersecurity Platform across **Vercel** (Frontend), **Render** (FastAPI Backend), and **Supabase PostgreSQL** (Production Database).

---

## 1. Architecture & Deployment Topology

```
                  +--------------------------------+
                  |    Client Web Browser / CLI    |
                  +---------------+----------------+
                                  |
                                  | HTTPS (TLS 1.3)
                 +----------------+----------------+
                 |                                 |
                 v                                 v
   +---------------------------+     +-------------------------------+
   |      Vercel Hosting       |     |      Render Web Service       |
   |   (React 19 / Vite SPA)   |     |    (FastAPI / Uvicorn ASGI)   |
   | sentriq-rouge.vercel.app  |     |     sentriq.onrender.com      |
   +-------------+-------------+     +---------------+---------------+
                 |                                   |
                 | API Calls (Cookie Auth/Bearer)    | SQLAlchemy 2.0 Async
                 +---------------------------------->| (asyncpg connection pool)
                                                     v
                                     +-------------------------------+
                                     |      Supabase PostgreSQL      |
                                     |     (Database & Indexes)      |
                                     +-------------------------------+
```

---

## 2. Pre-Deployment Readiness Checklist

Before triggering any production deployment:

- [ ] **Working Tree Cleanliness**: `git status` reports no untracked secrets or uncommitted modifications.
- [ ] **Zero Secrets in Git**: No `.env`, private keys, JWT secrets, or DB connection strings committed.
- [ ] **Backend Test Suite Passes**: All 221 pytest unit and integration tests pass with 0 failures:
  ```powershell
  .venv\Scripts\pytest backend\tests -v
  ```
- [ ] **Frontend Test Suite Passes**: All 98 Vitest component tests pass:
  ```powershell
  npm --prefix frontend test
  ```
- [ ] **Frontend Production Build Passes**: TypeScript compilation and Vite bundling pass cleanly:
  ```powershell
  npm --prefix frontend run build
  ```
- [ ] **CORS Origins Aligned**: Ensure `CORS_ORIGINS` on Render contains the exact Vercel production origin: `https://sentriq-rouge.vercel.app`.
- [ ] **Cookie Security Flags**: Ensure `COOKIE_SECURE=true`, `COOKIE_SAMESITE=none` (or `lax` if custom apex domain configured), and `COOKIE_DOMAIN` is correctly configured if sharing cross-subdomain.

---

## 3. Database Deployment (Supabase PostgreSQL)

Sentriq uses SQLAlchemy 2.0 with asynchronous `asyncpg` drivers in production and `aiosqlite` in local testing.

### 3.1 Connection String Configuration
- In Render Environment variables, set:
  ```env
  DATABASE_URL=postgresql+asyncpg://postgres:[PASSWORD]@[SUPABASE_HOST]:5432/postgres
  DATABASE_POOL_SIZE=10
  DATABASE_MAX_OVERFLOW=5
  DATABASE_POOL_TIMEOUT=30
  ```
- Note: Always use the `postgresql+asyncpg://` scheme for async SQLAlchemy.

### 3.2 Automated Schema Migrations
The backend automatically runs schema initialization and non-destructive column/table migrations on startup via `backend/app/database/migrations.py`.

During container boot, the migration sequence:
1. Verifies connection to Supabase via `SELECT 1`.
2. Inspects `information_schema.tables` and creates any missing tables across all 25 system entities:
   - `users`, `user_settings`, `email_verification_tokens`, `password_reset_tokens`, `oauth_states`
   - `workspaces`, `workspace_members`, `projects`
   - `scans`, `vulnerabilities`, `audit_logs`
   - `risk_assessments`, `compliance_scores`, `threat_intel_records`
   - `repo_targets`, `repo_scans`, `repo_secrets`
   - `api_targets`, `api_scans`, `api_endpoints`
   - `cloud_accounts`, `cloud_scans`, `cloud_resources`
   - `integration_configs`, `scan_schedules`
3. Dynamically adds newly introduced columns (e.g., `user_settings` table, `connection_status`, `audit_mode` in `cloud_accounts`).
4. Creates necessary performance indexes on `workspace_id`, `project_id`, `user_id`, `created_at`, `status`, and `severity`.
5. Sets up PostgreSQL immutability audit triggers to block `UPDATE` and `DELETE` queries on the `audit_logs` ledger.

---

## 4. Backend Deployment (Render Web Service)

### 4.1 Service Configuration
- **Type**: Web Service
- **Runtime**: Python 3.11+ (or Python 3.14 compatible)
- **Repo**: `https://github.com/Induvardhan116/Sentriq.git`
- **Branch**: `main`
- **Root Directory**: Project Root (`.`)
- **Build Command**:
  ```bash
  pip install --upgrade pip && pip install -r backend/requirements.txt
  ```
- **Start Command**:
  ```bash
  uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT --workers 2 --proxy-headers --forwarded-allow-ips='*'
  ```
- **Health Check Path**: `/api/system/health`
- **Auto-Deploy**: Enabled on Git push to `main` (or trigger via manual deploy hook).

### 4.2 Key Backend Environment Variables
| Variable | Production Value / Example | Notes |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `production` | Enables strict production protections |
| `DEBUG` | `false` | Disables stack traces and internal debug details |
| `DATABASE_URL` | `postgresql+asyncpg://...` | Connection to Supabase |
| `SECRET_KEY` | *(64-character random hex)* | High-entropy signing key for tokens & sessions |
| `CORS_ORIGINS` | `["https://sentriq-rouge.vercel.app"]` | Whitelisted frontend origins (JSON array or comma-sep) |
| `AUTH_ENABLED` | `false` (or `true` once verified) | Gating for strict authentication enforcement |
| `PRODUCTION_AUTH_VERIFIED` | `false` (or `true` once verified) | Production auth safeguard |
| `COOKIE_SECURE` | `true` | Required for HTTPS-only transmission |
| `COOKIE_SAMESITE` | `none` | Cross-domain frontend-to-backend cookie allowance |
| `RESEND_API_KEY` | `re_...` | For verification and password reset emails |
| `EMAIL_FROM` | `security@sentriq.io` | Verified sending domain |

---

## 5. Frontend Deployment (Vercel)

### 5.1 Project Configuration
- **Framework Preset**: Vite
- **Root Directory**: `frontend`
- **Build Command**: `npm run build`
- **Output Directory**: `dist`
- **Install Command**: `npm install`
- **Node.js Version**: 20.x or 22.x

### 5.2 Frontend Environment Variables
| Variable | Value | Notes |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `https://sentriq.onrender.com` | Base URL for FastAPI backend |
| `VITE_APP_ENV` | `production` | Frontend environment tag |

### 5.3 Vercel Routing Configuration (`vercel.json`)
To support client-side Single Page App (SPA) routing:
```json
{
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" }
      ]
    }
  ]
}
```

---

## 6. Post-Deployment Verification & Smoke Tests

Run these checks immediately following any deployment:

### 6.1 Backend Health & Diagnostics
1. Execute health endpoint request:
   ```bash
   curl -i https://sentriq.onrender.com/api/system/health
   ```
   **Expected Response**: HTTP 200 OK with:
   ```json
   {
     "status": "healthy",
     "environment": "production",
     "database": "connected",
     "auth_enabled": false,
     "timestamp": "..."
   }
   ```
2. Verify system info endpoint:
   ```bash
   curl -i https://sentriq.onrender.com/api/system/info
   ```

### 6.2 Frontend Accessibility & Asset Loading
1. Open `https://sentriq-rouge.vercel.app` in an incognito window.
2. Confirm the app loads without blank screen or runtime script errors in browser console.
3. Verify navigation across all 14 core views:
   - Dashboard (`/`)
   - Scans (`/scans`)
   - Vulnerabilities (`/vulnerabilities`)
   - Threat Intelligence (`/threat-intel`)
   - Risk Analytics & Scoring (`/risk-analytics`)
   - Repository Security (`/repositories`)
   - API Security (`/api-security`)
   - Cloud Security (`/cloud-security`)
   - Reports (`/reports`)
   - Settings & Preferences (`/settings`)
   - Integrations & Automation (`/integrations`)
   - Workspaces (`/workspaces`)
   - Audit Log Ledger (`/audit-logs`)
   - System Diagnostics (`/diagnostics`)

### 6.3 End-to-End Functional Smoke Tests
1. **Report Export**:
   - Navigate to `/reports`.
   - Select "Executive Summary" and click **Download PDF (.pdf)**.
   - Verify valid PDF file downloads (`sentriq_executive_report.pdf`), opens in viewer, and contains formatted headers, severity counts, and confidential footer.
2. **Settings Persistence**:
   - Navigate to `/settings` -> Preferences tab.
   - Change "Scanner Timeout" to `45` and toggle "Email on Scan Complete".
   - Click "Save Preferences" and verify success toast.
   - Refresh the page and confirm settings remain persisted.
3. **Scan Execution**:
   - Trigger an on-demand scan or click "Run Now" in Integrations -> Schedules.
   - Verify scan transition from `QUEUED` -> `SCANNING` -> `COMPLETED`.

---

## 7. Rollback & Emergency Recovery Runbook

### 7.1 Frontend Rollback (Vercel)
1. Open Vercel Dashboard -> Sentriq Project -> **Deployments**.
2. Locate the previous stable deployment commit.
3. Click `...` -> **Promote to Production**. Instant switch takes <5 seconds with zero downtime.

### 7.2 Backend Rollback (Render)
1. Open Render Dashboard -> `sentriq` Web Service -> **Events**.
2. Identify the last healthy deploy.
3. Click **Rollback to this deploy**.
4. Or push a Git revert commit to `main`:
   ```bash
   git revert HEAD
   git push origin main
   ```

### 7.3 Database Recovery (Supabase)
1. Since migrations are strictly additive (no destructive drops or schema truncations), the previous backend version remains compatible with the database schema.
2. If data restoration is required, utilize Supabase's Point-in-Time Recovery (PITR) or automated daily backups from the Supabase Database dashboard.
