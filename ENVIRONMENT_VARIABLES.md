# Sentriq — Environment Variables Specification

Comprehensive configuration reference for both backend (FastAPI / Pydantic Settings) and frontend (Vite / React) environments.

---

## 1. Backend Environment Variables (`backend/.env`)

The backend loads configuration via `pydantic-settings` in `backend/app/config.py`. Values can be provided via environment variables or a local `.env` file (which is strictly ignored by Git).

### 1.1 Core Application & Security

| Variable | Type | Default Value | Production Recommended | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | string | `development` | `production` | Active runtime mode (`development`, `staging`, `production`). In production, strict security headers and error masking are enforced. |
| `DEBUG` | boolean | `false` | `false` | When `true`, enables verbose tracebacks. Must ALWAYS be `false` in production to prevent stack trace leakage. |
| `SECRET_KEY` | string | *(auto-generated)* | *(64-hex entropy)* | Cryptographic key used to sign session cookies, JWTs, CSRF tokens, and verification hashes. |
| `API_PREFIX` | string | `/api` | `/api` | Global routing prefix for all REST endpoints. |
| `APP_VERSION` | string | `1.0.0` | `1.0.0` | Semver identifier returned by health and diagnostics endpoints. |
| `FRONTEND_URL` | string | `http://localhost:5173` | `https://sentriq-rouge.vercel.app` | Base URL of the client application used when generating email verification links and password reset redirects. |

### 1.2 Database & Connection Pool

| Variable | Type | Default Value | Production Recommended | Description |
| :--- | :--- | :--- | :--- | :--- |
| `DATABASE_URL` | string | `sqlite+aiosqlite:///./sentriq.db` | `postgresql+asyncpg://...` | SQLAlchemy 2.0 async connection URI. Uses SQLite for local dev/testing; requires PostgreSQL via asyncpg in staging/production. |
| `DATABASE_POOL_SIZE` | integer | `5` | `10` | Base number of concurrent database connections in the async connection pool. |
| `DATABASE_MAX_OVERFLOW` | integer | `10` | `5` | Maximum number of connections that can be opened beyond `DATABASE_POOL_SIZE` during traffic bursts. |
| `DATABASE_POOL_TIMEOUT` | integer | `30` | `30` | Seconds to wait before timing out when acquiring a connection from the pool. |
| `DATABASE_ECHO` | boolean | `false` | `false` | If `true`, logs all raw SQL queries to stdout. Keep `false` in production. |

### 1.3 Authentication & Safeguards

| Variable | Type | Default Value | Production Recommended | Description |
| :--- | :--- | :--- | :--- | :--- |
| `AUTH_ENABLED` | boolean | `false` | `false` / `true`* | Master gate for enforcing route-level authentication. Kept `false` during staging validation; set `true` once production auth is approved. |
| `PRODUCTION_AUTH_VERIFIED` | boolean | `false` | `false` / `true`* | Safety interlock. Prevents enabling `AUTH_ENABLED=true` in `ENVIRONMENT=production` unless explicitly acknowledged. |
| `REGISTRATION_ENABLED` | boolean | `true` | `true` | Controls whether new user self-registration is allowed via `/api/auth/register`. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | integer | `60` | `60` | Lifespan of short-lived session access tokens. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | integer | `30` | `30` | Lifespan of rotating refresh tokens. |
| `SESSION_TIMEOUT_MINUTES` | integer | `120` | `120` | Idle timeout for active web sessions before re-authentication is required. |

### 1.4 HTTP Cookie Security

| Variable | Type | Default Value | Production Recommended | Description |
| :--- | :--- | :--- | :--- | :--- |
| `COOKIE_SECURE` | boolean | `false` | `true` | Enforces the `Secure` attribute on cookies so they are only transmitted over TLS/HTTPS. |
| `COOKIE_HTTPONLY` | boolean | `true` | `true` | Enforces `HttpOnly` to prevent JavaScript from reading session cookies, preventing XSS-based session hijacking. |
| `COOKIE_SAMESITE` | string | `lax` | `none` | Cross-site cookie attribute. For cross-domain architecture (Vercel to Render), `none` is required along with `COOKIE_SECURE=true`. |
| `COOKIE_DOMAIN` | string | `null` | `null` | Optional cookie domain constraint. Keep `null` unless sharing cookies across subdomains of the same apex domain. |

### 1.5 CORS (Cross-Origin Resource Sharing)

| Variable | Type | Default Value | Production Recommended | Description |
| :--- | :--- | :--- | :--- | :--- |
| `CORS_ORIGINS` | list / JSON | `["http://localhost:5173","http://127.0.0.1:5173"]` | `["https://sentriq-rouge.vercel.app"]` | Whitelisted browser origins allowed to perform cross-origin requests and read responses. |
| `CORS_ALLOW_CREDENTIALS` | boolean | `true` | `true` | Allows cookies and Authorization headers to be included in CORS requests. |

### 1.6 External Integrations & Notifications

| Variable | Type | Default Value | Production Recommended | Description |
| :--- | :--- | :--- | :--- | :--- |
| `RESEND_API_KEY` | string | `null` | `re_...` | API key for Resend email service for transactional emails (verification, alerts, password resets). |
| `EMAIL_FROM` | string | `noreply@sentriq.local` | `security@sentriq.io` | Sender email address appearing in transactional messages. |
| `GITHUB_CLIENT_ID` | string | `null` | `Iv...` | GitHub OAuth application client ID for social single sign-on. |
| `GITHUB_CLIENT_SECRET` | string | `null` | `...` | GitHub OAuth application client secret. Strictly confidential. |
| `GITHUB_REDIRECT_URI` | string | `null` | `https://sentriq.onrender.com/api/auth/github/callback` | Callback URI registered in the GitHub OAuth application settings. |

### 1.7 Scanner Engine & Rate Limiting

| Variable | Type | Default Value | Production Recommended | Description |
| :--- | :--- | :--- | :--- | :--- |
| `MAX_SCAN_CONCURRENCY` | integer | `5` | `5` | Maximum number of simultaneous scan routines allowed across the instance. |
| `DEFAULT_SCAN_TIMEOUT` | integer | `30` | `30` | Timeout in seconds for active HTTP vulnerability checks and SSL handshakes. |
| `SSRF_PROTECTION_ENABLED` | boolean | `true` | `true` | Blocks scan targets resolving to RFC 1918 private IP ranges, loopback (`127.0.0.1`), link-local, and AWS metadata endpoints (`169.254.169.254`). |
| `RATE_LIMIT_LOGIN_PER_MIN` | integer | `10` | `10` | Sliding window limit for authentication attempts per IP to defeat credential stuffing and brute-force attacks. |
| `RATE_LIMIT_GLOBAL_PER_MIN` | integer | `120` | `120` | Global burst limit per IP across general API routes. |

---

## 2. Frontend Environment Variables (`frontend/.env`)

Vite exposes environment variables prefixed with `VITE_` to client-side code via `import.meta.env`.

| Variable | Default Value | Production Value | Description |
| :--- | :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `http://localhost:8000` | `https://sentriq.onrender.com` | Base target URL where client Axios requests and PDF export triggers are sent. |
| `VITE_APP_ENV` | `development` | `production` | Environment flag used for UI badges and debugging tools. |

---

## 3. Secret Management & Compliance Rules

1. **No Hardcoded Secrets**: Secrets must never be committed to Git. `.gitignore` strictly protects `.env`, `.env.*`, and local SQLite `.db` files.
2. **Key Entropy**: `SECRET_KEY` should be generated using a cryptographically secure pseudorandom generator:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
3. **Log Sanitization**: Sentriq's logging middleware automatically scrubs sensitive keys (`token`, `password`, `secret`, `authorization`, `api_key`) from request and response logs.
4. **Zero Frontend Secret Exposure**: No private keys, database passwords, or third-party secret tokens should ever have the `VITE_` prefix, ensuring they are never bundled into client JavaScript.
