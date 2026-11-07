# Sentriq — Security Policy & Application Security Controls

> **Platform**: Sentriq Application Security Intelligence
> **Repository**: [https://github.com/Induvardhan116/Sentriq.git](https://github.com/Induvardhan116/Sentriq.git)
> **Security Contact**: `security@sentriq.io`
> **Compliance Alignment**: OWASP Top 10, OWASP API Security Top 10, CIS Cloud Benchmarks, RFC 9116

---

## 1. Responsible Security Notice & Ethical Boundaries

Sentriq is engineered exclusively as a **defensive, authorized cybersecurity intelligence platform**.
- It evaluates publicly observable security attributes: TLS/SSL certificates, HTTP response headers, cookie flags, CORS policies, information disclosure, static code patterns, OpenAPI schemas, and read-only cloud configurations.
- Sentriq **never executes destructive actions**: no exploitation, no fuzzing injections against unauthorized servers, no denial-of-service, no password brute forcing, and no data alteration.
- Target authorization (`authorization_confirmed=True`) is strictly enforced server-side before scans can execute.

---

## 2. Threat Modeling & Defense-in-Depth Guardrails

### 2.1 Server-Side Request Forgery (SSRF) Protection
- **Module**: `app.scanners.web.validator`
- **Mechanism**:
  1. Whitelisted schemes: Only `http://` and `https://` are permitted.
  2. DNS Resolution & IP Inspection: Hostnames are resolved to IP addresses prior to HTTP client dispatch.
  3. Private Subnet Rejection:
     - RFC 1918 Private IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
     - RFC 3927 Link-Local: `169.254.0.0/16`.
     - Loopbacks: `127.0.0.0/8`, `::1`.
     - Cloud Metadata Services: `169.254.169.254`, `metadata.google.internal`.
  4. Redirect Safety: Redirects are bounded (maximum 5), and each intermediate redirect destination is independently validated against SSRF rules.

### 2.2 Cryptographic Session & Identity Security
- **Password Hashing**: Argon2id cryptographic hashing with distinct salts. Verification runs in constant time. Dummy verification runs for non-existent users to prevent user enumeration via timing discrepancies.
- **Session Tokens**: 256-bit URL-safe tokens generated with `secrets.token_urlsafe(32)`.
- **Database Storage**: Only SHA-256 digests (`token_hash`) are stored in the database. Raw tokens are never logged or persisted.
- **Session Cookies**:
  - `HttpOnly`: Defends against JavaScript token theft via Cross-Site Scripting (XSS).
  - `SameSite=Lax`: Defends against Cross-Site Request Forgery (CSRF).
  - `Secure`: Forced in production (`Secure=True`) via hardcoded configuration enforcement.
- **Session Rotation**: Login triggers session rotation on the same client, invalidating stale tokens while preserving unrelated sessions on other devices.

### 2.3 Anti-CSRF Architecture
- State-mutating requests (`POST`, `PATCH`, `DELETE`) require a cryptographic CSRF token.
- Tokens are derived using `HMAC-SHA256(token_hash, SECRET_KEY)`.
- Replay and cross-origin attacks fail closed.

### 2.4 OAuth 2.0 Replay & State Tampering Prevention
- **Model**: `OAuthState`
- **Protection**:
  - State tokens are cryptographically hashed (`state_hash = SHA256(state)`).
  - State consumption is atomic (`UPDATE oauth_states SET consumed_at = NOW() WHERE consumed_at IS NULL`).
  - Replays, already-used tokens, tampered states, and expired states are rejected.

### 2.5 Denial-of-Service (DoS) & Brute Force Mitigation
- Avoids permanent account lockouts (which facilitate victim denial-of-service).
- Implements progressive throttling with bounded backoff delays (e.g. 1s to 8s).
- Rate limits IP flood attempts based on true client IP extracted from trusted proxies.

### 2.6 Concurrency Protection & Audit Immutability
- **Optimistic Concurrency Control (OCC)**: Finding updates require `expected_version`. If a concurrent change occurred, the server returns `HTTP 409 Conflict`.
- **Database Immutability Triggers**: `finding_status_events` and `workspace_audit_logs` are protected by database triggers that reject `UPDATE` and `DELETE` statements.

### 2.7 Zero Credential Leakage & Sensitive Data Masking
- **Source Code Secrets**: AWS keys, GitHub PATs, and private keys are masked (`AKIA****MPLE`, `ghp_****XXXX`).
- **Cloud IAM**: Role ARNs and secrets are masked (`arn:aws:iam::****:role/...`).
- **Web Cookies**: Cookie values in HTTP scan results are redacted (`name=REDACTED`).

### 2.8 Safe Sandboxing for Untrusted Code
- Static analysis of source code repositories and OpenAPI specifications is performed in text-only mode within bounded memory and file limits (`MAX_FILES_TO_SCAN = 500`, `MAX_FILE_SIZE = 2MB`).
- Repository code is never executed, evaluated, or compiled on the host application server.

### 2.9 Outbound Webhook Security
- Outbound webhook endpoints require HTTPS.
- SSRF validation blocks private internal networks.
- Every outgoing webhook request contains an `X-Sentriq-Signature` header calculated using `HMAC-SHA256(payload, secret_token)` allowing clients to verify authenticity.

### 2.10 Enterprise RBAC & Governance Protection
- Four standard RBAC roles: `owner`, `admin`, `analyst`, `auditor`.
- **Sole Owner Guardrail**: System forbids demoting or removing the sole remaining owner of a workspace.

---

## 3. Vulnerability Disclosure Policy

If you discover a security vulnerability in Sentriq:
1. Email `security@sentriq.io` with details, reproduction steps, and proof-of-concept.
2. Please allow up to 48 hours for an acknowledgment from our security engineering team.
3. We follow coordinated vulnerability disclosure. Please do not publicly disclose vulnerabilities before a fix is released.
