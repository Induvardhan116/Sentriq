import logging
from sqlalchemy import inspect, text
from app.models.base import Base

logger = logging.getLogger("sentriq.database.migrations")

# SQL Trigger and Procedure Constants for Phase 4.1 Audit Protection

SQLITE_TRIGGER_NO_DELETE = """
CREATE TRIGGER IF NOT EXISTS trg_audit_events_no_delete
BEFORE DELETE ON finding_status_events
WHEN EXISTS (SELECT 1 FROM findings WHERE id = OLD.finding_id)
BEGIN
    SELECT RAISE(ABORT, 'Audit records are append-only: DELETE prohibited.');
END;
"""

SQLITE_TRIGGER_PROTECT_UPDATE = """
CREATE TRIGGER IF NOT EXISTS trg_audit_events_protect_update
BEFORE UPDATE ON finding_status_events
WHEN NOT (
    OLD.user_id IS NOT NULL
    AND NEW.user_id IS NULL
    AND OLD.id = NEW.id
    AND OLD.finding_id = NEW.finding_id
    AND OLD.previous_status = NEW.previous_status
    AND OLD.new_status = NEW.new_status
    AND ((OLD.justification IS NULL AND NEW.justification IS NULL) OR (OLD.justification = NEW.justification))
    AND OLD.created_at = NEW.created_at
    AND EXISTS (SELECT 1 FROM audit_anonymization_ticket t WHERE t.user_id = OLD.user_id)
)
BEGIN
    SELECT RAISE(ABORT, 'Audit records are immutable: Unauthorized UPDATE prohibited.');
END;
"""

PG_FUNCTION_CONSTANT_TIME_BYTES_EQ = """
CREATE OR REPLACE FUNCTION constant_time_bytes_eq(a BYTEA, b BYTEA)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_diff INT := 0;
    i INT;
    len INT;
BEGIN
    IF a IS NULL OR b IS NULL THEN
        RETURN FALSE;
    END IF;
    IF octet_length(a) <> octet_length(b) THEN
        RETURN FALSE;
    END IF;
    len := octet_length(a);
    FOR i IN 0..(len - 1) LOOP
        v_diff := v_diff | (get_byte(a, i) # get_byte(b, i));
    END LOOP;
    RETURN v_diff = 0;
END;
$$;
"""

PG_FUNCTION_AUDIT_PROTECT_UPDATE = """
CREATE OR REPLACE FUNCTION trg_enforce_audit_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM findings WHERE id = OLD.finding_id) THEN
            RAISE EXCEPTION 'Audit records are append-only. DELETE operations are prohibited.'
                USING ERRCODE = '23505';
        END IF;
        RETURN OLD;
    END IF;

    IF (OLD.user_id IS NOT NULL AND NEW.user_id IS NULL)
       AND (OLD.id = NEW.id)
       AND (OLD.finding_id = NEW.finding_id)
       AND (OLD.previous_status = NEW.previous_status)
       AND (OLD.new_status = NEW.new_status)
       AND (OLD.justification IS NOT DISTINCT FROM NEW.justification)
       AND (OLD.created_at = NEW.created_at)
       AND EXISTS (SELECT 1 FROM audit_anonymization_ticket t WHERE t.user_id = OLD.user_id) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'Audit records are append-only. Unauthorized UPDATE operations are prohibited.'
        USING ERRCODE = '23514';
END;
$$;
"""

PG_TRIGGER_AUDIT_DROP = """
DROP TRIGGER IF EXISTS trg_audit_events_immutable ON finding_status_events;
"""

PG_TRIGGER_AUDIT_CREATE = """
CREATE TRIGGER trg_audit_events_immutable
BEFORE UPDATE OR DELETE ON finding_status_events
FOR EACH ROW
EXECUTE FUNCTION trg_enforce_audit_immutability();
"""

# Backward compatibility aliases
PG_TRIGGER_AUDIT_NO_DELETE = PG_TRIGGER_AUDIT_CREATE
PG_TRIGGER_AUDIT_PROTECT_UPDATE = PG_TRIGGER_AUDIT_CREATE

PG_FUNCTION_ANONYMIZE_USER = """
CREATE OR REPLACE PROCEDURE sp_anonymize_user(
    p_target_user_id VARCHAR(36),
    p_admin_user_id VARCHAR(36),
    p_nonce VARCHAR(64),
    p_signature BYTEA
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_secret BYTEA;
    v_computed_sig BYTEA;
    v_ticket_id VARCHAR(36);
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_admin_user_id AND is_superuser = TRUE AND is_active = TRUE) THEN
        RAISE EXCEPTION 'Access Denied: Superuser privilege required for anonymization.' USING ERRCODE = '42501';
    END IF;

    IF p_admin_user_id = p_target_user_id THEN
        RAISE EXCEPTION 'Safety Violation: Administrators cannot anonymize their own active account.' USING ERRCODE = '22023';
    END IF;

    IF EXISTS (SELECT 1 FROM audit_consumed_nonces WHERE nonce = p_nonce) THEN
        RAISE EXCEPTION 'Security Violation: Authorization nonce has already been consumed.' USING ERRCODE = '23505';
    END IF;

    SELECT secret_value INTO v_secret FROM sentriq_internal_secrets WHERE key_name = 'anonymization_hmac_secret';
    IF v_secret IS NOT NULL THEN
        v_computed_sig := hmac((p_target_user_id || ':' || p_admin_user_id || ':' || p_nonce)::bytea, v_secret, 'sha256');
        IF NOT constant_time_bytes_eq(digest(p_signature, 'sha256'), digest(v_computed_sig, 'sha256')) THEN
            RAISE EXCEPTION 'Cryptographic verification failed: invalid authorization signature.' USING ERRCODE = '28000';
        END IF;
    END IF;

    INSERT INTO audit_consumed_nonces (nonce, consumed_by, consumed_at, expires_at)
    VALUES (p_nonce, p_admin_user_id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '24 hours');

    v_ticket_id := gen_random_uuid()::text;
    INSERT INTO audit_anonymization_ticket (ticket_id, user_id, authorized_by, nonce, created_at)
    VALUES (v_ticket_id, p_target_user_id, p_admin_user_id, p_nonce, CURRENT_TIMESTAMP);

    UPDATE finding_status_events SET user_id = NULL WHERE user_id = p_target_user_id;

    DELETE FROM audit_anonymization_ticket WHERE ticket_id = v_ticket_id;

    DELETE FROM users WHERE id = p_target_user_id;
END;
$$;
"""

PG_RESTRICTED_PRIVILEGES = """
DO $$
BEGIN
    -- Revoke public access to sensitive audit tickets and internal secrets
    REVOKE ALL ON TABLE audit_anonymization_ticket FROM PUBLIC;
    REVOKE ALL ON TABLE sentriq_internal_secrets FROM PUBLIC;

    -- If the application database role exists, configure least privilege
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentriq_app') THEN
        GRANT SELECT, INSERT ON TABLE finding_status_events TO sentriq_app;
        GRANT UPDATE (user_id) ON TABLE finding_status_events TO sentriq_app;
        GRANT SELECT, INSERT ON TABLE audit_consumed_nonces TO sentriq_app;
        REVOKE ALL ON TABLE audit_anonymization_ticket FROM sentriq_app;
        REVOKE ALL ON TABLE sentriq_internal_secrets FROM sentriq_app;
    END IF;
END $$;
"""



def run_migrations(connection) -> None:
    """Safely apply schema migrations for existing and fresh databases without breaking user data.

    Preservation & Safety Guarantees:
    1. Idempotent: Can be run repeatedly without error.
    2. Dialect-aware: Handles both SQLite and PostgreSQL syntax appropriately.
    3. Transaction-safe: Executed inside an active connection transaction.
    4. Non-destructive: Existing rows in 'projects', 'scans', 'findings', and 'users' are preserved.
    5. Phase 4.1: Adds OCC version, justification, finding_status_events, audit tickets, nonces, and triggers.
    """
    dialect_name = connection.dialect.name

    # 1. First ensure all newly defined metadata tables exist (users, user_sessions, findings, etc.)
    Base.metadata.create_all(connection)

    inspector = inspect(connection)
    tables = inspector.get_table_names()

    # 2. Check 'findings' table for columns (Phase 2 fingerprint, Phase 4.1 version & justification)
    if "findings" in tables:
        finding_columns = [c["name"] for c in inspector.get_columns("findings")]

        # Phase 2: fingerprint
        if "fingerprint" not in finding_columns:
            logger.info("Migrating database: adding 'fingerprint' column to findings table.")
            if dialect_name == "sqlite":
                connection.execute(text("ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64)"))
            else:
                connection.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings(fingerprint)"))

        # Phase 4.1: version
        if "version" not in finding_columns:
            logger.info("Migrating database: adding 'version' column to findings table.")
            if dialect_name == "sqlite":
                connection.execute(text("ALTER TABLE findings ADD COLUMN version INTEGER NOT NULL DEFAULT 1"))
            else:
                connection.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1"))

        # Phase 4.1: justification
        if "justification" not in finding_columns:
            logger.info("Migrating database: adding 'justification' column to findings table.")
            if dialect_name == "sqlite":
                connection.execute(text("ALTER TABLE findings ADD COLUMN justification TEXT"))
            else:
                connection.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS justification TEXT"))

        # Composite indexes on findings
        if "risk_score" in finding_columns:
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_scan_risk ON findings(scan_id, risk_score)"))

    # 3. Check 'projects' table for 'owner_id' column (Phase 3 migration)
    if "projects" in tables:
        project_columns = [c["name"] for c in inspector.get_columns("projects")]
        if "owner_id" not in project_columns:
            logger.info("Migrating database: adding nullable 'owner_id' column to projects table.")
            if dialect_name == "sqlite":
                connection.execute(
                    text("ALTER TABLE projects ADD COLUMN owner_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL")
                )
            else:
                connection.execute(
                    text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS owner_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL")
                )
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_projects_owner_id ON projects(owner_id)"))

    # 4. Check 'users' table for 'is_verified' column
    if "users" in tables:
        user_columns = [c["name"] for c in inspector.get_columns("users")]
        if "is_verified" not in user_columns:
            logger.info("Migrating database: adding 'is_verified' column to users table.")
            if dialect_name == "sqlite":
                connection.execute(text("ALTER TABLE users ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT 1"))
            else:
                connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT TRUE"))

    # 5. Explicit fallback migration for 'oauth_states' table and indexes (Phase 3.3)
    if "oauth_states" not in tables:
        logger.info("Migrating database: creating 'oauth_states' table and indexes.")
        if dialect_name == "sqlite":
            create_oauth_states_sql = text("""
                CREATE TABLE IF NOT EXISTS oauth_states (
                    id VARCHAR(36) PRIMARY KEY,
                    state_hash VARCHAR(64) NOT NULL UNIQUE,
                    nonce VARCHAR(64) NOT NULL,
                    redirect_path VARCHAR(512) NOT NULL DEFAULT '/overview',
                    expires_at TIMESTAMP NOT NULL,
                    consumed_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            create_oauth_states_sql = text("""
                CREATE TABLE IF NOT EXISTS oauth_states (
                    id VARCHAR(36) PRIMARY KEY,
                    state_hash VARCHAR(64) NOT NULL UNIQUE,
                    nonce VARCHAR(64) NOT NULL,
                    redirect_path VARCHAR(512) NOT NULL DEFAULT '/overview',
                    expires_at TIMESTAMPTZ NOT NULL,
                    consumed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        connection.execute(create_oauth_states_sql)

        indexes_sql = [
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_oauth_states_state_hash ON oauth_states(state_hash)",
            "CREATE INDEX IF NOT EXISTS ix_oauth_states_nonce ON oauth_states(nonce)",
            "CREATE INDEX IF NOT EXISTS ix_oauth_states_expires_at ON oauth_states(expires_at)",
            "CREATE INDEX IF NOT EXISTS ix_oauth_states_consumed_at ON oauth_states(consumed_at)",
        ]
        for idx_sql in indexes_sql:
            connection.execute(text(idx_sql))

    # 5. Phase 4.1: Explicit verification for 'finding_status_events' table and indexes
    if "finding_status_events" not in tables:
        logger.info("Migrating database: creating 'finding_status_events' table.")
        if dialect_name == "sqlite":
            create_events_sql = text("""
                CREATE TABLE IF NOT EXISTS finding_status_events (
                    id VARCHAR(36) PRIMARY KEY,
                    finding_id VARCHAR(36) NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
                    user_id VARCHAR(36) REFERENCES users(id) ON DELETE RESTRICT,
                    previous_status VARCHAR(32) NOT NULL,
                    new_status VARCHAR(32) NOT NULL,
                    justification TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            create_events_sql = text("""
                CREATE TABLE IF NOT EXISTS finding_status_events (
                    id VARCHAR(36) PRIMARY KEY,
                    finding_id VARCHAR(36) NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
                    user_id VARCHAR(36) REFERENCES users(id) ON DELETE RESTRICT,
                    previous_status VARCHAR(32) NOT NULL,
                    new_status VARCHAR(32) NOT NULL,
                    justification TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        connection.execute(create_events_sql)

    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_finding_status_events_finding_id ON finding_status_events(finding_id)")
    )
    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_finding_status_events_created_at ON finding_status_events(created_at)")
    )

    # 6. Phase 4.1: Explicit verification for 'audit_anonymization_ticket' table
    if "audit_anonymization_ticket" not in tables:
        logger.info("Migrating database: creating 'audit_anonymization_ticket' table.")
        if dialect_name == "sqlite":
            create_ticket_sql = text("""
                CREATE TABLE IF NOT EXISTS audit_anonymization_ticket (
                    ticket_id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    authorized_by VARCHAR(36) NOT NULL,
                    nonce VARCHAR(64) UNIQUE,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            create_ticket_sql = text("""
                CREATE TABLE IF NOT EXISTS audit_anonymization_ticket (
                    ticket_id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    authorized_by VARCHAR(36) NOT NULL,
                    nonce VARCHAR(64) UNIQUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        connection.execute(create_ticket_sql)

    # 7. Phase 4.1: Explicit verification for 'audit_consumed_nonces' table
    if "audit_consumed_nonces" not in tables:
        logger.info("Migrating database: creating 'audit_consumed_nonces' table.")
        if dialect_name == "sqlite":
            create_nonces_sql = text("""
                CREATE TABLE IF NOT EXISTS audit_consumed_nonces (
                    nonce VARCHAR(64) PRIMARY KEY,
                    consumed_by VARCHAR(36) NOT NULL,
                    consumed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
        else:
            create_nonces_sql = text("""
                CREATE TABLE IF NOT EXISTS audit_consumed_nonces (
                    nonce VARCHAR(64) PRIMARY KEY,
                    consumed_by VARCHAR(36) NOT NULL,
                    consumed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMPTZ NOT NULL
                )
            """)
        connection.execute(create_nonces_sql)
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_audit_consumed_nonces_expires_at ON audit_consumed_nonces(expires_at)")
        )

    # 8. Email Verification Tokens migration
    if "email_verification_tokens" not in tables:
        logger.info("Migrating database: creating 'email_verification_tokens' table.")
        if dialect_name == "sqlite":
            create_verify_sql = text("""
                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash VARCHAR(64) NOT NULL UNIQUE,
                    expires_at TIMESTAMP NOT NULL,
                    consumed_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            create_verify_sql = text("""
                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash VARCHAR(64) NOT NULL UNIQUE,
                    expires_at TIMESTAMPTZ NOT NULL,
                    consumed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        connection.execute(create_verify_sql)

    connection.execute(
        text("CREATE UNIQUE INDEX IF NOT EXISTS ix_email_verification_tokens_token_hash ON email_verification_tokens(token_hash)")
    )
    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_email_verification_tokens_user_id ON email_verification_tokens(user_id)")
    )
    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_email_verification_tokens_expires_at ON email_verification_tokens(expires_at)")
    )
    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_email_verification_tokens_consumed_at ON email_verification_tokens(consumed_at)")
    )

    # 9. Password Reset Tokens migration
    if "password_reset_tokens" not in tables:
        logger.info("Migrating database: creating 'password_reset_tokens' table.")
        if dialect_name == "sqlite":
            create_reset_sql = text("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash VARCHAR(64) NOT NULL UNIQUE,
                    expires_at TIMESTAMP NOT NULL,
                    consumed_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            create_reset_sql = text("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash VARCHAR(64) NOT NULL UNIQUE,
                    expires_at TIMESTAMPTZ NOT NULL,
                    consumed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        connection.execute(create_reset_sql)

    connection.execute(
        text("CREATE UNIQUE INDEX IF NOT EXISTS ix_password_reset_tokens_token_hash ON password_reset_tokens(token_hash)")
    )
    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_user_id ON password_reset_tokens(user_id)")
    )
    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_expires_at ON password_reset_tokens(expires_at)")
    )
    connection.execute(
        text("CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_consumed_at ON password_reset_tokens(consumed_at)")
    )

    # 10. Phase 4.1: Dialect-Specific Immutability Triggers
    if dialect_name == "sqlite":
        connection.execute(text(SQLITE_TRIGGER_NO_DELETE))
        connection.execute(text(SQLITE_TRIGGER_PROTECT_UPDATE))

    elif dialect_name == "postgresql":
        connection.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto;"))
        connection.execute(text(PG_FUNCTION_CONSTANT_TIME_BYTES_EQ))
        connection.execute(text(PG_FUNCTION_AUDIT_PROTECT_UPDATE))
        connection.execute(text(PG_TRIGGER_AUDIT_DROP.strip()))
        connection.execute(text(PG_TRIGGER_AUDIT_CREATE.strip()))
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS sentriq_internal_secrets (
                key_name VARCHAR(64) PRIMARY KEY,
                secret_value BYTEA NOT NULL,
                rotated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """))
        connection.execute(text(PG_FUNCTION_ANONYMIZE_USER))
        connection.execute(text(PG_RESTRICTED_PRIVILEGES))

    # 11. Phase 6: Repositories and Code Security Tables
    if "repositories" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS repositories (
                    id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    full_name VARCHAR(255) NOT NULL,
                    clone_url VARCHAR(1024) NOT NULL,
                    default_branch VARCHAR(64) NOT NULL DEFAULT 'main',
                    languages VARCHAR(512),
                    is_private BOOLEAN NOT NULL DEFAULT 0,
                    authorization_confirmed BOOLEAN NOT NULL DEFAULT 1,
                    owner_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL,
                    last_scanned_at TIMESTAMP,
                    latest_posture_score INTEGER NOT NULL DEFAULT 100,
                    latest_risk_score INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS repositories (
                    id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    full_name VARCHAR(255) NOT NULL,
                    clone_url VARCHAR(1024) NOT NULL,
                    default_branch VARCHAR(64) NOT NULL DEFAULT 'main',
                    languages VARCHAR(512),
                    is_private BOOLEAN NOT NULL DEFAULT FALSE,
                    authorization_confirmed BOOLEAN NOT NULL DEFAULT TRUE,
                    owner_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL,
                    last_scanned_at TIMESTAMPTZ,
                    latest_posture_score INTEGER NOT NULL DEFAULT 100,
                    latest_risk_score INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    if "repo_scans" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS repo_scans (
                    id VARCHAR(36) PRIMARY KEY,
                    repository_id VARCHAR(36) NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                    branch VARCHAR(64) NOT NULL DEFAULT 'main',
                    commit_hash VARCHAR(64),
                    status VARCHAR(32) NOT NULL DEFAULT 'queued',
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    posture_score INTEGER NOT NULL DEFAULT 100,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    secret_count INTEGER NOT NULL DEFAULT 0,
                    sast_count INTEGER NOT NULL DEFAULT 0,
                    sca_count INTEGER NOT NULL DEFAULT 0,
                    critical_count INTEGER NOT NULL DEFAULT 0,
                    high_count INTEGER NOT NULL DEFAULT 0,
                    medium_count INTEGER NOT NULL DEFAULT 0,
                    low_count INTEGER NOT NULL DEFAULT 0,
                    error_message TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS repo_scans (
                    id VARCHAR(36) PRIMARY KEY,
                    repository_id VARCHAR(36) NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                    branch VARCHAR(64) NOT NULL DEFAULT 'main',
                    commit_hash VARCHAR(64),
                    status VARCHAR(32) NOT NULL DEFAULT 'queued',
                    started_at TIMESTAMPTZ,
                    completed_at TIMESTAMPTZ,
                    posture_score INTEGER NOT NULL DEFAULT 100,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    secret_count INTEGER NOT NULL DEFAULT 0,
                    sast_count INTEGER NOT NULL DEFAULT 0,
                    sca_count INTEGER NOT NULL DEFAULT 0,
                    critical_count INTEGER NOT NULL DEFAULT 0,
                    high_count INTEGER NOT NULL DEFAULT 0,
                    medium_count INTEGER NOT NULL DEFAULT 0,
                    low_count INTEGER NOT NULL DEFAULT 0,
                    error_message TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    if "repo_findings" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS repo_findings (
                    id VARCHAR(36) PRIMARY KEY,
                    scan_id VARCHAR(36) NOT NULL REFERENCES repo_scans(id) ON DELETE CASCADE,
                    scan_type VARCHAR(32) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    risk_score INTEGER NOT NULL DEFAULT 50,
                    file_path VARCHAR(1024) NOT NULL,
                    line_number INTEGER,
                    rule_id VARCHAR(128) NOT NULL,
                    cwe VARCHAR(64),
                    cve VARCHAR(64),
                    snippet TEXT,
                    remediation TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'open',
                    justification TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS repo_findings (
                    id VARCHAR(36) PRIMARY KEY,
                    scan_id VARCHAR(36) NOT NULL REFERENCES repo_scans(id) ON DELETE CASCADE,
                    scan_type VARCHAR(32) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    risk_score INTEGER NOT NULL DEFAULT 50,
                    file_path VARCHAR(1024) NOT NULL,
                    line_number INTEGER,
                    rule_id VARCHAR(128) NOT NULL,
                    cwe VARCHAR(64),
                    cve VARCHAR(64),
                    snippet TEXT,
                    remediation TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'open',
                    justification TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_repositories_owner_id ON repositories(owner_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_repo_scans_repository_id ON repo_scans(repository_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_repo_scans_status ON repo_scans(status)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_repo_findings_scan_id ON repo_findings(scan_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_repo_findings_scan_type ON repo_findings(scan_type)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_repo_findings_severity ON repo_findings(severity)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_repo_findings_status ON repo_findings(status)"))

    # 12. Phase 7: API Security Tables
    if "api_specs" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS api_specs (
                    id VARCHAR(36) PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    version VARCHAR(64) NOT NULL DEFAULT '1.0.0',
                    description TEXT,
                    base_url VARCHAR(1024),
                    spec_format VARCHAR(32) NOT NULL DEFAULT 'openapi_3',
                    raw_spec TEXT NOT NULL,
                    endpoint_count INTEGER NOT NULL DEFAULT 0,
                    posture_score INTEGER NOT NULL DEFAULT 100,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    last_scanned_at TIMESTAMP,
                    owner_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS api_specs (
                    id VARCHAR(36) PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    version VARCHAR(64) NOT NULL DEFAULT '1.0.0',
                    description TEXT,
                    base_url VARCHAR(1024),
                    spec_format VARCHAR(32) NOT NULL DEFAULT 'openapi_3',
                    raw_spec TEXT NOT NULL,
                    endpoint_count INTEGER NOT NULL DEFAULT 0,
                    posture_score INTEGER NOT NULL DEFAULT 100,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    last_scanned_at TIMESTAMPTZ,
                    owner_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    if "api_endpoints" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS api_endpoints (
                    id VARCHAR(36) PRIMARY KEY,
                    spec_id VARCHAR(36) NOT NULL REFERENCES api_specs(id) ON DELETE CASCADE,
                    path VARCHAR(1024) NOT NULL,
                    method VARCHAR(16) NOT NULL,
                    summary VARCHAR(255),
                    auth_required BOOLEAN NOT NULL DEFAULT 0,
                    auth_type VARCHAR(64) NOT NULL DEFAULT 'none',
                    parameters_count INTEGER NOT NULL DEFAULT 0,
                    has_request_body BOOLEAN NOT NULL DEFAULT 0,
                    tags VARCHAR(255),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS api_endpoints (
                    id VARCHAR(36) PRIMARY KEY,
                    spec_id VARCHAR(36) NOT NULL REFERENCES api_specs(id) ON DELETE CASCADE,
                    path VARCHAR(1024) NOT NULL,
                    method VARCHAR(16) NOT NULL,
                    summary VARCHAR(255),
                    auth_required BOOLEAN NOT NULL DEFAULT FALSE,
                    auth_type VARCHAR(64) NOT NULL DEFAULT 'none',
                    parameters_count INTEGER NOT NULL DEFAULT 0,
                    has_request_body BOOLEAN NOT NULL DEFAULT FALSE,
                    tags VARCHAR(255),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    if "api_findings" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS api_findings (
                    id VARCHAR(36) PRIMARY KEY,
                    spec_id VARCHAR(36) NOT NULL REFERENCES api_specs(id) ON DELETE CASCADE,
                    endpoint_id VARCHAR(36),
                    path VARCHAR(1024),
                    method VARCHAR(16),
                    owasp_category VARCHAR(64) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    risk_score INTEGER NOT NULL DEFAULT 50,
                    remediation TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'open',
                    justification TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS api_findings (
                    id VARCHAR(36) PRIMARY KEY,
                    spec_id VARCHAR(36) NOT NULL REFERENCES api_specs(id) ON DELETE CASCADE,
                    endpoint_id VARCHAR(36),
                    path VARCHAR(1024),
                    method VARCHAR(16),
                    owasp_category VARCHAR(64) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    risk_score INTEGER NOT NULL DEFAULT 50,
                    remediation TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'open',
                    justification TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_api_specs_owner_id ON api_specs(owner_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_api_endpoints_spec_id ON api_endpoints(spec_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_api_endpoints_path ON api_endpoints(path)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_api_endpoints_method ON api_endpoints(method)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_api_findings_spec_id ON api_findings(spec_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_api_findings_owasp_category ON api_findings(owasp_category)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_api_findings_severity ON api_findings(severity)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_api_findings_status ON api_findings(status)"))

    if "cloud_accounts" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS cloud_accounts (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                    provider VARCHAR(32) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    account_identifier VARCHAR(128) NOT NULL,
                    role_arn_or_ref VARCHAR(255) NOT NULL,
                    region VARCHAR(64) NOT NULL DEFAULT 'us-east-1',
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    posture_score INTEGER NOT NULL DEFAULT 100,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    last_scanned_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS cloud_accounts (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                    provider VARCHAR(32) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    account_identifier VARCHAR(128) NOT NULL,
                    role_arn_or_ref VARCHAR(255) NOT NULL,
                    region VARCHAR(64) NOT NULL DEFAULT 'us-east-1',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    posture_score INTEGER NOT NULL DEFAULT 100,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    last_scanned_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    if "cloud_findings" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS cloud_findings (
                    id VARCHAR(36) PRIMARY KEY,
                    account_id VARCHAR(36) NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
                    service VARCHAR(64) NOT NULL,
                    resource_id VARCHAR(255) NOT NULL,
                    resource_type VARCHAR(64) NOT NULL,
                    benchmark_ref VARCHAR(64) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    risk_score INTEGER NOT NULL DEFAULT 50,
                    remediation TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'open',
                    justification TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS cloud_findings (
                    id VARCHAR(36) PRIMARY KEY,
                    account_id VARCHAR(36) NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
                    service VARCHAR(64) NOT NULL,
                    resource_id VARCHAR(255) NOT NULL,
                    resource_type VARCHAR(64) NOT NULL,
                    benchmark_ref VARCHAR(64) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    risk_score INTEGER NOT NULL DEFAULT 50,
                    remediation TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'open',
                    justification TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_cloud_accounts_user_id ON cloud_accounts(user_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_cloud_accounts_provider ON cloud_accounts(provider)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_cloud_findings_account_id ON cloud_findings(account_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_cloud_findings_service ON cloud_findings(service)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_cloud_findings_benchmark_ref ON cloud_findings(benchmark_ref)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_cloud_findings_severity ON cloud_findings(severity)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_cloud_findings_status ON cloud_findings(status)"))

    if "webhook_endpoints" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS webhook_endpoints (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                    name VARCHAR(255) NOT NULL,
                    target_url VARCHAR(1024) NOT NULL,
                    secret_token VARCHAR(255) NOT NULL,
                    event_types VARCHAR(255) NOT NULL DEFAULT 'scan.completed,finding.critical,posture.degraded',
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    last_dispatched_at TIMESTAMP,
                    last_status_code INTEGER,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS webhook_endpoints (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                    name VARCHAR(255) NOT NULL,
                    target_url VARCHAR(1024) NOT NULL,
                    secret_token VARCHAR(255) NOT NULL,
                    event_types VARCHAR(255) NOT NULL DEFAULT 'scan.completed,finding.critical,posture.degraded',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    last_dispatched_at TIMESTAMPTZ,
                    last_status_code INTEGER,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    if "scan_schedules" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                    target_type VARCHAR(32) NOT NULL,
                    target_id VARCHAR(36) NOT NULL,
                    target_name VARCHAR(255) NOT NULL,
                    frequency VARCHAR(32) NOT NULL DEFAULT 'weekly',
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    last_run_at TIMESTAMP,
                    next_run_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                    target_type VARCHAR(32) NOT NULL,
                    target_id VARCHAR(36) NOT NULL,
                    target_name VARCHAR(255) NOT NULL,
                    frequency VARCHAR(32) NOT NULL DEFAULT 'weekly',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    last_run_at TIMESTAMPTZ,
                    next_run_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_webhook_endpoints_user_id ON webhook_endpoints(user_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_schedules_user_id ON scan_schedules(user_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_schedules_target_id ON scan_schedules(target_id)"))

    if "workspaces" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS workspaces (
                    id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    slug VARCHAR(128) UNIQUE NOT NULL,
                    owner_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS workspaces (
                    id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    slug VARCHAR(128) UNIQUE NOT NULL,
                    owner_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    if "workspace_members" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS workspace_members (
                    id VARCHAR(36) PRIMARY KEY,
                    workspace_id VARCHAR(36) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    role VARCHAR(32) NOT NULL DEFAULT 'analyst',
                    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_workspace_member UNIQUE (workspace_id, user_id)
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS workspace_members (
                    id VARCHAR(36) PRIMARY KEY,
                    workspace_id VARCHAR(36) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    role VARCHAR(32) NOT NULL DEFAULT 'analyst',
                    joined_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_workspace_member UNIQUE (workspace_id, user_id)
                )
            """))

    if "workspace_audit_logs" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS workspace_audit_logs (
                    id VARCHAR(36) PRIMARY KEY,
                    workspace_id VARCHAR(36) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    actor_id VARCHAR(36) NOT NULL,
                    actor_email VARCHAR(255) NOT NULL,
                    action VARCHAR(64) NOT NULL,
                    resource_type VARCHAR(64) NOT NULL,
                    resource_id VARCHAR(36),
                    details TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS workspace_audit_logs (
                    id VARCHAR(36) PRIMARY KEY,
                    workspace_id VARCHAR(36) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    actor_id VARCHAR(36) NOT NULL,
                    actor_email VARCHAR(255) NOT NULL,
                    action VARCHAR(64) NOT NULL,
                    resource_type VARCHAR(64) NOT NULL,
                    resource_id VARCHAR(36),
                    details TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    if "user_settings" not in tables:
        if dialect_name == "sqlite":
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS user_settings (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                    scanner_timeout_seconds INTEGER NOT NULL DEFAULT 30,
                    scanner_max_redirects INTEGER NOT NULL DEFAULT 5,
                    scanner_verify_ssl BOOLEAN NOT NULL DEFAULT 1,
                    scanner_strict_headers BOOLEAN NOT NULL DEFAULT 1,
                    notify_email_scan_completed BOOLEAN NOT NULL DEFAULT 1,
                    notify_email_critical_finding BOOLEAN NOT NULL DEFAULT 1,
                    notify_webhook_enabled BOOLEAN NOT NULL DEFAULT 1,
                    default_scan_cadence VARCHAR(32) NOT NULL DEFAULT 'weekly',
                    theme VARCHAR(32) NOT NULL DEFAULT 'dark',
                    session_timeout_minutes INTEGER NOT NULL DEFAULT 10080,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS user_settings (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                    scanner_timeout_seconds INTEGER NOT NULL DEFAULT 30,
                    scanner_max_redirects INTEGER NOT NULL DEFAULT 5,
                    scanner_verify_ssl BOOLEAN NOT NULL DEFAULT TRUE,
                    scanner_strict_headers BOOLEAN NOT NULL DEFAULT TRUE,
                    notify_email_scan_completed BOOLEAN NOT NULL DEFAULT TRUE,
                    notify_email_critical_finding BOOLEAN NOT NULL DEFAULT TRUE,
                    notify_webhook_enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    default_scan_cadence VARCHAR(32) NOT NULL DEFAULT 'weekly',
                    theme VARCHAR(32) NOT NULL DEFAULT 'dark',
                    session_timeout_minutes INTEGER NOT NULL DEFAULT 10080,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_user_settings_user_id ON user_settings(user_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_workspaces_owner_id ON workspaces(owner_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_workspaces_slug ON workspaces(slug)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_workspace_members_workspace_id ON workspace_members(workspace_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_workspace_members_user_id ON workspace_members(user_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_workspace_audit_logs_workspace_id ON workspace_audit_logs(workspace_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_workspace_audit_logs_actor_id ON workspace_audit_logs(actor_id)"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_workspace_audit_logs_action ON workspace_audit_logs(action)"))

    logger.info("Database schema migrations completed successfully.")
