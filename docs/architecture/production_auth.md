# Sentriq Production Authentication Architecture & Security Guide

## Phase 3.3 Security Review & Production Safety Architecture

### 1. The Cross-Site Cookie Problem (Vercel + Render)

In standard decoupled cloud deployments without a custom domain:
- **Frontend**: Hosted on Vercel (`https://sentriq-rouge.vercel.app`)
- **Backend**: Hosted on Render (`https://sentriq.onrender.com`)

Both `vercel.app` and `onrender.com` are registered on Mozilla's **Public Suffix List (PSL)**. Consequently, they are treated by web browsers as separate, unrelated effective Top-Level Domains (eTLD+1). Cross-domain requests between them are classified as **cross-site**.

#### Why Cross-Site Cookies Fail in Modern Browsers:
1. **Third-Party Cookie Deprecation**:
   - Apple WebKit (Safari Intelligent Tracking Prevention / ITP) completely blocks third-party cookies by default.
   - Google Chrome Privacy Sandbox and Firefox Enhanced Tracking Protection (ETP) partition or block unpartitioned cross-site cookies.
2. **Insecurity of `SameSite=None` Workarounds**:
   - Setting `SameSite=None; Secure` allows session cookies to be attached to cross-site requests, significantly weakening defense-in-depth against Cross-Site Request Forgery (CSRF).
   - Even with `SameSite=None`, browsers that block third-party cookies reject or drop the cookie, causing silent login failures, missing session headers, and broken state.
3. **Strict Policy Against Weakening Protections**:
   - Sentriq **strictly prohibits** relaxing CORS policies (e.g. wildcard origins or reflection), weakening cookie flags (`SameSite=None` or non-`HttpOnly`), or disabling Origin/Referer/CSRF token validation to "make login work" across disjoint domains.

---

### 2. Production Safety Policy

Until an approved same-site or same-origin deployment architecture is provisioned:
- **Production authentication MUST remain disabled** (`AUTH_ENABLED=False` or gated in production).
- When `AUTH_ENABLED=False`, all authentication entry and mutating endpoints (`/api/auth/login`, `/api/auth/register`, `/api/auth/github`, `/api/auth/github/callback`) fail closed with `HTTP 503 Service Unavailable`.
- The core Phase 2 platform capabilities (authorized website scans, passive diagnostics, risk scoring, finding lifecycle management) operate safely and deterministically without cross-site cookie dependencies.

---

### 3. Required Production Architectures

To securely enable authentication in production, Sentriq must be deployed using one of the following two approved architectural patterns:

#### Architecture Pattern A: Same-Origin Edge Gateway / Reverse Proxy (Recommended)

In this pattern, all frontend and backend traffic is routed through a single domain:

```
                          Client Browser
                                │
                                ▼
                   https://app.sentriq.io
                                │
        ┌───────────────────────┴───────────────────────┐
        │                                               │
   Path: /*                                      Path: /api/*
        │                                               │
        ▼                                               ▼
Vercel Frontend Static Build                   Render Backend Core
(sentriq-rouge.vercel.app)                  (sentriq.onrender.com)
```

**Implementation Details**:
- **Gateway**: Vercel Rewrites (`vercel.json`), Cloudflare Rules, or an AWS CloudFront distribution.
- **Vercel Rewrite Configuration** (`frontend/vercel.json`):
  ```json
  {
    "rewrites": [
      {
        "source": "/api/:path*",
        "destination": "https://sentriq.onrender.com/api/:path*"
      }
    ]
  }
  ```
- **Security Guarantees**:
  - All API calls are **strictly same-origin** (`https://app.sentriq.io/api/...`).
  - Session cookies use `SameSite=Lax` (or `Strict`), `HttpOnly=True`, and `Secure=True`.
  - Zero cross-site cookie partitioning or blocking across any browser.
  - Zero CORS preflight overhead for same-origin requests.

---

#### Architecture Pattern B: Unified Custom Domain with Common eTLD+1

In this pattern, both frontend and backend share an organizational root domain:

- **Frontend**: `https://app.sentriq.io`
- **Backend API**: `https://api.sentriq.io`
- **Root Domain**: `sentriq.io`

**Implementation Details**:
- **CORS Configuration**:
  ```env
  CORS_ORIGINS=https://app.sentriq.io
  ```
- **Cookie Scope**:
  - Cookies set by `api.sentriq.io` configure `Domain=.sentriq.io; SameSite=Lax; Secure; HttpOnly`.
  - Because `app.sentriq.io` and `api.sentriq.io` share the same eTLD+1 (`sentriq.io`), modern browsers classify the context as **same-site** rather than cross-site.
  - Requests from `app.sentriq.io` to `api.sentriq.io` include the session cookie without triggering third-party cookie restrictions.

---

### 4. Meaning and Limitations of PRODUCTION_AUTH_VERIFIED

The environment variable `PRODUCTION_AUTH_VERIFIED` is an **administrative acknowledgement toggle**, NOT automated proof of a working same-origin or same-site architecture.

- **Failsafe Enforcement**: Setting `PRODUCTION_AUTH_VERIFIED=true` in environment variables while still pointing to `*.vercel.app` or `*.onrender.com` will **still fail closed** (`AUTH_ENABLED=False`). The backend code strictly enforces that cross-site PSL domains cannot run with authentication enabled under any circumstances.
- **Operator Requirement**: An operator must **never** set `PRODUCTION_AUTH_VERIFIED=true` simply because tests pass or because a deployment builds. It may only be set to `true` after performing the exact browser-level verification protocol documented in Section 5 below against a deployed custom apex domain or reverse proxy setup.

---

### 5. Mandatory Browser-Level Verification Checklist

Before `AUTH_ENABLED=true` and `PRODUCTION_AUTH_VERIFIED=true` can be enabled in a production deployment, the engineering team must execute and sign off on this complete manual browser verification protocol across at least **Safari** (WebKit with ITP active), **Google Chrome** (standard & Incognito mode), and **Mozilla Firefox** (Enhanced Tracking Protection enabled).

#### Pre-requisite Architecture Check
- [ ] Backend is served under the same apex domain as frontend (e.g., `https://api.sentriq.io` and `https://app.sentriq.io`) or through a unified reverse proxy path (`https://app.sentriq.io/api/*`).
- [ ] Neither frontend nor backend uses uncustomized `*.vercel.app` or `*.onrender.com` domains.
- [ ] Backend `CORS_ORIGINS` strictly contains the trusted frontend origin (e.g., `https://app.sentriq.io`).

#### Step 1: Network & Cookie Inspection on Login
1. Open DevTools -> **Application** / **Storage** -> **Cookies**.
2. Navigate to the login page and submit valid credentials.
3. Inspect the `Set-Cookie` response header on `POST /api/auth/login`:
   - [ ] Cookie name is `sentriq_session`.
   - [ ] `HttpOnly` flag is present and marked `true` (cookie is inaccessible via `document.cookie` in JS console).
   - [ ] `Secure` flag is present and marked `true`.
   - [ ] `SameSite` attribute is strictly `Lax` (or `Strict`). It must **never** be `None`.
   - [ ] `Domain` attribute matches the root domain (e.g., `.sentriq.io`) if using Pattern B, or is host-only (omitted) if using Pattern A reverse proxy.
   - [ ] `sentriq_csrf` cookie is present with matching `SameSite` and `Secure` attributes.

#### Step 2: Session Persistence & Cross-Request Verification
1. Navigate between multiple protected pages and trigger state refreshes.
2. In DevTools -> **Network**, inspect subsequent authenticated calls (e.g., `GET /api/auth/me`):
   - [ ] Request headers explicitly contain `Cookie: sentriq_session=...`.
   - [ ] Response status is `200 OK`.
   - [ ] No CORS errors or missing cookie warnings appear in the DevTools Console.
3. Refresh the browser tab (`Ctrl+F5` / `Cmd+Shift+R`):
   - [ ] User remains authenticated without being redirected to `/login`.
   - [ ] Session is not lost.

#### Step 3: Apple Safari (ITP) & Firefox (ETP) Compatibility Verification
1. In macOS Safari or iOS Safari, ensure "Prevent Cross-Site Tracking" is enabled (default setting).
2. Perform login and refresh.
   - [ ] Login succeeds without cookie rejection.
   - [ ] Cookie is stored under first-party partition.
3. In Firefox, ensure "Enhanced Tracking Protection" is set to "Standard" or "Strict".
   - [ ] No shield icon warnings regarding blocked third-party cookies appear on API calls.

#### Step 4: OAuth Flow Verification (GitHub)
1. Initiate GitHub login (`GET /api/auth/github`).
2. Verify redirect to GitHub authorization page.
3. Complete GitHub authorization and follow callback redirect back to frontend.
   - [ ] Session cookie is successfully set upon callback completion.
   - [ ] User landing page shows authenticated user details.
   - [ ] Replay test: Copying and re-submitting the same OAuth callback URL into another tab or browser immediately returns `400 Bad Request` (state already consumed).

#### Step 5: Logout & Invalidation Check
1. Click "Sign Out" (`POST /api/auth/logout`).
   - [ ] Response sends `Set-Cookie: sentriq_session=; Max-Age=0; Expires=...`.
   - [ ] Subsequent calls to `GET /api/auth/me` return `401 Unauthorized`.
   - [ ] Attempting to replay the previous session token returns `401 Unauthorized` (database revocation verified).

---

### 6. Summary of Phase 3.3 Security Fixes

| Vulnerability / Area | Previous Risk | Phase 3.3 Resolution |
| :--- | :--- | :--- |
| **GitHub OAuth Replay Protection** | Stateless HMAC tokens could theoretically be replayed or submitted concurrently. | Server-side `OAuthState` model with cryptographic SHA-256 state hashing and atomic database consumption (`UPDATE ... WHERE consumed_at IS NULL AND expires_at > now`). Strictly rejects tampered, expired, already-used, and concurrent replay attempts. |
| **Account Lockout DoS** | Lockout backoff could multiply up to 24 hours, allowing an adversary to permanently lock out legitimate users by submitting failed logins. | Removed prolonged 24-hour account lockout. Legitimate users with correct passwords can always log in without lockout denial. Progressive throttling with `Retry-After` headers only throttles repeated wrong guesses. |
| **Login Retention & Maintenance** | Unbounded growth of `login_attempts` audit records without automated cleanup. | Scheduled async background worker `periodic_login_attempts_cleanup` runs hourly outside request lifecycle, guaranteeing zero request latency and safe 24-hour audit retention even if no users log in. |
| **Database Migration Ordering** | Base.metadata.create_all preempted migrations, or migrations lacked explicit table DDL. | Explicit dialect-aware migration runs on application startup inspecting existing schema before metadata sync, ensuring safe schema evolution for existing databases without data loss. |
| **Untrusted Proxy Rate Limiting** | Shared reverse proxy IP on platforms like Render could trigger shared flood rate limits. | Isolated `is_ip_eligible_for_flood_limit` requiring globally routable public IPs when proxy headers are untrusted, preventing accidental IP-wide lockouts. |
| **Session Lifecycle & Rotation** | Device session rotation and multi-device handling were ambiguously defined. | Session rotation explicitly scoped to the specific connecting client; unrelated sessions on other devices are preserved. Logout revokes the session in DB. Expired and revoked sessions strictly return 401. |
| **Production Safety** | Cross-site cookie blocking between Vercel and Render broke auth in production. | Production authentication gated (`AUTH_ENABLED`); setting `PRODUCTION_AUTH_VERIFIED=true` on default Vercel/Render domains fails closed. Documented required browser verification. |
