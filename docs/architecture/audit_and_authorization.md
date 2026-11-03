# Sentriq Phase 4.1 — Finding Model, Audit History, and Database Authorization

This document details the security architecture, authorization boundaries, audit immutability guarantees, and database migration designs implemented in **Sentriq Phase 4.1**.

---

## 1. Finding Schema Extensions & Optimistic Concurrency Control (OCC)

Phase 4.1 enhances the core `Finding` model to support enterprise audit workflows, structured triage justifications, and concurrent analyst safety:

### Model Attributes
- **`version`** (`INTEGER`, default `1`, not null): Monotonically increasing version counter enabling Optimistic Concurrency Control (OCC).
- **`justification`** (`TEXT`, nullable): Audit rationale capturing analyst justification when triaging findings.
- **`status`** (`VARCHAR(32)`, index): Extended lifecycle status values:
  - `open`: Finding detected and requiring triage.
  - `in_progress`: Finding undergoing remediation or active testing.
  - `resolved`: Vulnerability confirmed remediated.
  - `false_positive`: Finding verified as non-exploitable or safe.
  - `accepted_risk`: Business exception approved by security leadership.

### Concurrency and Justification Validation Rules
1. **Optimistic Concurrency Control**:
   - Clients updating a finding status provide `expected_version`.
   - If the current finding `version` in the database does not match `expected_version`, the API rejects the mutation with `HTTP 409 Conflict`.
   - On successful update, `version` is incremented by 1 (`version = version + 1`).
2. **Mandatory Justification**:
   - Transitioning a finding to `accepted_risk` strictly requires a non-empty `justification`.
   - Transitioning a finding to `false_positive` via OCC clients strictly requires a non-empty `justification`.
   - Whitespace-only or missing justifications fail closed with `HTTP 400 Bad Request`.
3. **Backward Compatibility**:
   - Unversioned legacy calls (Phase 2 and Phase 3 clients omitting `expected_version`) for standard status changes remain compatible without breaking existing workflows.

---

## 2. Immutable Finding Status Audit History

Every finding status transition is captured in an immutable audit ledger:

### `finding_status_events` Model
- **`id`** (`VARCHAR(36)`, Primary Key): UUID identifier for the audit event.
- **`finding_id`** (`VARCHAR(36)`, Foreign Key -> `findings.id`): Parent finding.
- **`user_id`** (`VARCHAR(36)`, Foreign Key -> `users.id` with `ON DELETE RESTRICT`): Actor who initiated the status transition. Nullified upon authorized GDPR/compliance account anonymization.
- **`previous_status`** (`VARCHAR(32)`): Lifecycle status prior to update.
- **`new_status`** (`VARCHAR(32)`): Lifecycle status after update.
- **`justification`** (`TEXT`, nullable): Captured rationale at the moment of change.
- **`created_at`** (`TIMESTAMPTZ`): Cryptographically reliable chronological event timestamp.

### Immutability Invariants
1. **Append-Only History**: Records in `finding_status_events` cannot be deleted while the parent finding exists. Direct `DELETE` queries are aborted by database triggers.
2. **Immutable Attributes**: Direct `UPDATE` queries on `id`, `finding_id`, `previous_status`, `new_status`, `justification`, or `created_at` are strictly prohibited by database triggers.
3. **Protected Anonymization**: The only permitted modification is setting `user_id = NULL` during an authorized anonymization procedure backed by an active `audit_anonymization_ticket`.

---

## 3. Database Authorization Boundaries: SQLite vs. PostgreSQL

The architecture accounts for fundamental structural differences between SQLite and PostgreSQL:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Sentriq Application Boundary                          │
│                                                                             │
│   FastAPI Endpoints ──► Security Dependencies ──► AdminAccountService       │
│                            (Session, CSRF,        (Role, Nonce, HMAC,       │
│                             Superuser Check)       OCC, Transaction)        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
┌───────────────────────────────┐     ┌───────────────────────────────────────┐
│     SQLite In-Process DB      │     │         PostgreSQL Database           │
├───────────────────────────────┤     ├───────────────────────────────────────┤
│ • In-process serverless engine│     │ • Client-server network architecture  │
│ • No separate OS/DB roles     │     │ • Role privileges (GRANT/REVOKE)      │
│ • No SECURITY DEFINER         │     │ • SECURITY DEFINER procedures         │
│ • Triggers block app errors   │     │ • Triggers enforce immutability       │
│ • Application layer is the    │     │ • Database provides independent       │
│   TRUSTED authorization       │     │   raw-SQL authorization boundary      │
│   boundary                    │     │                                       │
└───────────────────────────────┘     └───────────────────────────────────────┘
```

### SQLite Authorization Boundary
- **Technical Reality**: SQLite is an in-process, serverless library directly reading and writing a local database file. SQLite has no concept of database-level users, passwords, connection roles, or `SECURITY DEFINER` privileges. Any entity with raw SQL access to the SQLite file has full administrative authority and can manipulate any table (including inserting into `audit_anonymization_ticket`).
- **Enforcement Model**: SQLite **does not and cannot provide an independent raw-SQL authorization boundary**. Authorization for SQLite is enforced at the **authenticated application service layer** (`AdminAccountService`):
  1. Validates authenticated user session.
  2. Enforces superuser role (`is_superuser=True` and `is_active=True`).
  3. Prohibits self-anonymization (`caller.id == target.id`).
  4. Verifies constant-time HMAC signature and timestamp freshness.
  5. Enforces single-use persistent nonces.
  6. Executes the entire sequence atomically in a single ACID transaction.

### PostgreSQL Authorization Boundary
- **Technical Architecture**: PostgreSQL provides full database-level access controls and security contexts:
  1. **Stored Procedure (`sp_anonymize_user`)**: Executed with `SECURITY DEFINER` and `SET search_path = public, pg_temp` to prevent search_path spoofing.
  2. **Trigger (`trg_audit_events_immutable`)**: Blocks all direct `DELETE` and unauthorized `UPDATE` statements on `finding_status_events`.
  3. **Role Privileges**: Application role (`sentriq_app`) has rights revoked on `audit_anonymization_ticket` and `sentriq_internal_secrets`, preventing direct bypasses outside the `SECURITY DEFINER` procedure.

---

## 4. Cryptographic HMAC Verification & Session Isolation

### Avoiding Caller-Controlled Session Settings
- Storing cryptographic keys in PostgreSQL session variables (such as `SET sentriq.hmac_secret = '...'` or reading `current_setting(...)`) is insecure because any SQL session can inspect or manipulate session parameters.
- Sentriq isolates cryptographic keys:
  - **Application Service**: Secrets reside in hardened application memory/configuration (`settings.SECRET_KEY`), completely out of database reach.
  - **PostgreSQL Database**: When procedure-level verification is invoked, the key is queried from `sentriq_internal_secrets`, a table with all public permissions revoked.

### Constant-Time Verification
To prevent timing side-channel attacks where an attacker deduces valid signature bytes via comparison response times:
1. **Application Boundary (`verify_anonymization_hmac`)**:
   - Generates the expected HMAC-SHA256 signature.
   - Computes SHA-256 digests of both the received and expected signatures (`d1` and `d2`). Because digests are always 32 bytes, length differences cannot leak timing information.
   - Compares digests using `hmac.compare_digest(d1, d2)`, implemented in constant-time C.
2. **PostgreSQL Boundary (`constant_time_bytes_eq`)**:
   - Bitwise XOR accumulator function (`v_diff := v_diff | (get_byte(a, i) # get_byte(b, i))`) iterating through all 32 bytes without early exits.
   - Evaluates to true if and only if `v_diff == 0`.

---

## 5. Persistent Nonce Replay Prevention

To prevent replaying intercepted authorization payloads:
1. Every authorization ticket carries a cryptographic random nonce (`p_nonce` / `nonce`).
2. Before processing, the system checks the `audit_consumed_nonces` table.
3. If the nonce already exists, the request fails with `HTTP 400 Bad Request` / SQL error `23505`.
4. Upon consumption, the nonce is persistently committed to `audit_consumed_nonces` with timestamp and 24-hour expiration (`expires_at`), preventing both concurrent and future replays.

---

## 6. Migration Safety & Idempotency

All schema migrations in `backend/app/database/migrations.py` follow strict non-destructive principles:
1. **Pre-inspection**: Inspects tables and columns before altering schema.
2. **Safe Column Additions**: Adds `version` (default 1) and `justification` (nullable) to `findings` table without mutating existing scan findings.
3. **Safe Table Additions**: Creates `finding_status_events`, `audit_anonymization_ticket`, `audit_consumed_nonces`, and indexes with `IF NOT EXISTS`.
4. **Data Preservation**: Existing projects, scans, findings, users, user sessions, and OAuth states are fully preserved.
5. **Idempotency**: Running migrations repeatedly produces identical schema states with zero errors.

