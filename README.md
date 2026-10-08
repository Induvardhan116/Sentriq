# Sentriq — Application Security Intelligence Platform

Sentriq is a production-grade, defensive cybersecurity platform designed to continuously assess, correlate, and score the security posture of web applications and source code repositories.

> **Responsible Security Notice**: Sentriq performs safe, authorized, non-destructive security checks (HTTPS/TLS configuration, response headers, cookie flags, CORS policies, information disclosure, and mixed-content analysis). It does **not** conduct exploitation, denial of service, brute force attacks, or intrusive testing. Users must explicitly confirm target ownership or authorization prior to testing.

---

## Current Status: Phase 2 Verified (Website Security Scanner)

Phase 2 introduces Sentriq's first core security capability: a safe, low-impact, bounded website security assessment engine backed by deterministic risk and posture scoring.

### Core Capabilities
1. **Target Authorization & Ownership Enforcement**: Every project requires explicit confirmation before scanning is allowed.
2. **SSRF & Safety Layer**: Prohibits dangerous schemes (`file://`, `ftp://`, `javascript:`, `data:`, `gopher://`) and restricts scans against private RFC 1918 networks, loopback addresses (`127.0.0.1`, `localhost`), and cloud instance metadata (`169.254.169.254`).
3. **Safe Bounded HTTP Client**: Enforces request timeouts, max response read size (2MB), limited redirects, and non-destructive HTTP methods (`GET`, `HEAD`).
4. **HTTPS / TLS Assessment**: Evaluates TLS availability, SSL certificate validity/expiration, certificate hostname matching, and HTTP-to-HTTPS redirect posture.
5. **Security Response Headers**: Evaluates `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Content-Type-Options`, `X-Frame-Options` (clickjacking protection), `Referrer-Policy`, and `Permissions-Policy`.
6. **Cookie Security & Privacy**: Evaluates `Secure`, `HttpOnly`, and `SameSite` flags. **Zero Raw Cookie Storage**: Cookie values are strictly redacted (`name=REDACTED`) in all logs, database records, and UI displays.
7. **CORS Configuration**: Evaluates wildcard origins (`*`), credentials combinations (`Access-Control-Allow-Credentials: true`), `null` origins, and arbitrary reflection.
8. **Information Exposure**: Detects detailed server software banners (`Server: Apache/2.4.52`), `X-Powered-By` runtime disclosures, active framework debug screens/stack traces, and public source map directives.
9. **Configuration Checks**: RFC 9116 `security.txt` verification, `robots.txt` discovery (marked as standard practice, not a vulnerability), and mixed-content resource detection.
10. **Explainable Risk Engine & Posture Scoring**: Computes deterministic 0-100 risk scores for findings and calculates overall posture scores with security caps.

---

## Architecture

```
Sentriq/
├── backend/                              # FastAPI Asynchronous Core
│   ├── app/
│   │   ├── api/                          # Modular API Routers
│   │   │   ├── system.py                 # GET /api/system/health
│   │   │   ├── projects.py               # POST/GET /api/projects, POST /api/projects/{id}/scans
│   │   │   ├── scans.py                  # GET /api/scans/{id}, GET /api/scans/{id}/findings, summary
│   │   │   └── findings.py               # PATCH /api/findings/{id}
│   │   ├── config.py                     # Pydantic Settings & SSRF safety controls
│   │   ├── database/                     # SQLAlchemy 2.0 Async Session (SQLite / PostgreSQL)
│   │   ├── models/                       # Project, Scan, Finding ORM models
│   │   ├── schemas/                      # Pydantic validation schemas
│   │   ├── risk/                         # Deterministic Risk & Posture Scoring Engine
│   │   └── scanners/                     # Modular Web Security Scanner
│   │       └── web/
│   │           ├── client.py             # Safe, bounded async HTTP client
│   │           ├── validator.py          # SSRF prevention & URL normalization
│   │           ├── scanner.py            # Website scanner orchestrator
│   │           └── checks/               # HTTPS, headers, cookies, cors, exposure, config
│   └── tests/                            # 23 Automated Async Tests
│
├── frontend/                             # Vite + React 18 + TypeScript Client
│   ├── src/
│   │   ├── components/                   # ProjectList, ScanDetailView, FindingDetailModal, Header, Sidebar
│   │   ├── services/                     # Typed API client for projects, scans, findings
│   │   ├── types/                        # Project, Scan, Finding TypeScript interfaces
│   │   └── index.css                     # Dark cybersecurity design system tokens
│
├── .env.example                          # Environment configuration template
└── .gitignore                            # Production git ignore rules
```

---

## Scoring Models

### Finding Risk Score (0–100)
Every finding is scored deterministically based on base severity weight and confidence factor:
- **Critical**: 90
- **High**: 75
- **Medium**: 55
- **Low**: 30
- **Informational**: 10

Formula: `risk_score = round(base_weight * clamp(confidence, 0.1, 1.0))`

### Overall Security Posture Score (0–100)
Starts at 100 with deductions:
- Each Critical finding: `-25` pts
- Each High finding: `-15` pts
- Each Medium finding: `-8` pts
- Each Low finding: `-3` pts
- Each Informational finding: `-1` pt (capped at 5 pts)

**Ceiling Caps**:
- If any Critical finding exists: Maximum posture score is capped at `49` ("Poor").
- If any High finding exists: Maximum posture score is capped at `74` ("Needs Improvement").

**Grade Tiers**:
- `90 - 100`: Excellent
- `75 - 89`: Good
- `50 - 74`: Needs Improvement
- `25 - 49`: Poor
- `0 - 24`: Critical

---

## API Endpoints (Phase 2)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/system/health` | Canonical system health & DB probe (`SELECT 1`) |
| `POST` | `/api/projects` | Create authorized project target (`authorization_confirmed` required) |
| `GET` | `/api/projects` | List projects with latest scan previews |
| `GET` | `/api/projects/{id}` | Get project detail and scan history |
| `POST` | `/api/projects/{id}/scans` | Launch safe background assessment scan |
| `GET` | `/api/scans/{id}` | Get scan status, score, grade, and counters |
| `GET` | `/api/scans/{id}/findings` | Get normalized findings sorted by risk score |
| `GET` | `/api/scans/{id}/summary` | Get severity & category breakdown with top risks |
| `PATCH` | `/api/findings/{id}` | Update status (`open`, `in_progress`, `resolved`, `false_positive`) |

---

## Running the Application

### 1. Setup Environment
```bash
cp .env.example .env
```

### 2. Run Backend
```bash
# Activate virtual environment
.\.venv\Scripts\activate   # Windows (or source .venv/bin/activate on Linux/macOS)

# Run test suite (23 tests)
python -m pytest backend/tests -v

# Start FastAPI server
uvicorn app.main:app --app-dir backend --reload --port 8000
```

### 3. Run Frontend
```bash
cd frontend
npm install
npm run build   # Type-check and production build
npm run dev     # Starts dev server on port 5173
```

---

## Incremental Roadmap

- [x] **Phase 1: Project Foundation** — FastAPI backend, React/Vite/TS frontend, SQLite/PostgreSQL async engine, canonical health endpoint.
- [x] **Phase 2: Website Security Scanner** — Authorized targets, non-destructive checks (HTTPS/TLS, headers, cookies, CORS, exposure), finding normalization & risk engine.
- [ ] **Phase 3: Authentication & GitHub OAuth** — User accounts, sessions, multi-tenant isolation.
- [ ] **Phase 4: Finding Normalization Hub** — Universal finding management.
- [ ] **Phase 5: Advanced Risk Correlation** — Multi-dimensional asset weighting and posture tracking.
- [ ] **Phase 6: Repository Security Analysis** — Semgrep CE, Gitleaks, OSV.dev dependency scanning.
- [ ] **Phase 7: Security Dashboard & Regression Detection** — Historical scans comparison.
- [ ] **Phase 8: AI Security Analyst** — Evidence-grounded explanations with deterministic fallback.
- [ ] **Phase 9: PDF Security Reporting** — Open-source report generation.
- [ ] **Phase 10: Production Deployment** — Vercel + Render + Supabase.
