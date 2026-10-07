# Sentriq — Application Security Intelligence Platform

Sentriq is a production-grade, defensive cybersecurity platform designed to continuously assess, correlate, and score the security posture of web applications and source code repositories.

> **Responsible Security Notice**: Sentriq performs safe, authorized, non-destructive security checks (HTTPS/TLS configuration, response headers, cookie flags, CORS policies, SAST, secret detection, and dependency vulnerabilities). It does **not** conduct exploitation, denial of service, brute force attacks, or intrusive testing. Users must verify target ownership or explicit authorization prior to testing.

---

## Architecture Overview (Phase 1 Foundation)

```
Sentriq/
├── backend/                  # FastAPI 0.110+ Asynchronous Core (Python 3.14 compatible)
│   ├── app/
│   │   ├── api/              # Modular API routers (Canonical: /api/system/health)
│   │   ├── config.py         # Pydantic v2 settings & environment manager
│   │   ├── database/         # SQLAlchemy 2.0 async engine (SQLite / PostgreSQL)
│   │   ├── models/           # Declarative base models & timestamp mixins
│   │   └── schemas/          # Pydantic data validation schemas
│   └── tests/                # Automated async pytest test suite
│
├── frontend/                 # Vite + React 18 + TypeScript Client
│   ├── src/
│   │   ├── components/       # Header, Sidebar, Diagnostics & Phase Roadmap
│   │   ├── services/         # API clients with real-time health telemetry
│   │   ├── types/            # System & diagnostic TypeScript definitions
│   │   └── index.css         # Dark cybersecurity design system tokens
│
├── .env.example              # Central configuration template
└── .gitignore                # Production ignore rules (secrets, venv, DB, build artifacts)
```

---

## Technology Stack

- **Backend**: Python 3.14, FastAPI, Uvicorn, SQLAlchemy 2.0 (asyncio + greenlet), Pydantic v2, aiosqlite, asyncpg-ready.
- **Frontend**: React 18, Vite, TypeScript, Lucide Icons, Vanilla CSS Design System.
- **Database**: SQLite (local development with zero external dependencies) / PostgreSQL (production, e.g., Supabase free tier).
- **Security Tools (Planned in Phases 3-6)**: Open-source Semgrep CE, Gitleaks, OSV.dev vulnerability database.

---

## Getting Started

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.14.7)
- Node.js 18+ (tested on v24.19.0)
- npm 9+

### 2. Environment Configuration
Copy the template configuration file:
```bash
cp .env.example .env
```

### 3. Backend Setup
```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Run automated tests
pytest backend/

# Start the backend server
uvicorn app.main:app --app-dir backend --reload --port 8000
```
The API is available at: `http://localhost:8000`
Canonical health endpoint: `http://localhost:8000/api/system/health`
Interactive Swagger documentation: `http://localhost:8000/api/docs`

### 4. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
The frontend dev server runs at: `http://localhost:5173` (proxies `/api` to the backend on port 8000).

To build the production bundle:
```bash
npm run build
```

---

## API Specifications (Canonical Phase 1 Endpoint)

### `GET /api/system/health`
Checks core system state and executes a `SELECT 1` query to verify active database connectivity.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "database": "connected",
  "app_name": "Sentriq",
  "version": "0.1.0",
  "environment": "development",
  "timestamp": "2026-10-07T18:15:00.000000Z"
}
```

---

## Incremental Engineering Roadmap

- [x] **Phase 1: Project Foundation** — FastAPI backend, React/Vite/TS frontend, SQLite/PostgreSQL async engine, canonical health endpoint, clean gitignore & environment configuration.
- [ ] **Phase 2: Authentication & Target Authorization** — User identity, GitHub OAuth, target authorization confirmation.
- [ ] **Phase 3: Defensive Website Security Scanner** — Non-destructive HTTPS/TLS, headers, cookies, CORS, and info disclosure.
- [ ] **Phase 4: Finding Normalization** — Unified finding model across web and code scanners.
- [ ] **Phase 5: Explainable Risk Engine** — Transparent 0-100 risk scoring & security posture calculation.
- [ ] **Phase 6: Repository Security Analysis** — Semgrep CE, Gitleaks, and OSV.dev dependency scanning.
- [ ] **Phase 7: Security Dashboard & Regression Tracking** — Historical posture trends and regression alerts.
- [ ] **Phase 8: Evidence-Grounded AI Security Analyst** — Deterministic fallback with optional local/free model guidance.
- [ ] **Phase 9: PDF Security Reporting** — Open-source report generation.
- [ ] **Phase 10: Production Deployment** — Vercel (Frontend) + Render (Backend) + Supabase (PostgreSQL).

---

## License

This project is licensed under the Apache 2.0 License.
