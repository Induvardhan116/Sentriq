import logging
from sqlalchemy import inspect, text
from app.models.base import Base

logger = logging.getLogger("sentriq.database.migrations")


def run_migrations(connection) -> None:
    """Safely apply schema migrations for existing databases without breaking user data.

    Preservation & Safety Guarantees:
    1. Idempotent: Can be run repeatedly without error.
    2. Dialect-aware: Handles both SQLite and PostgreSQL syntax appropriately.
    3. Transaction-safe: Executed inside an active connection transaction.
    4. Non-destructive: Existing rows in 'projects', 'scans', and 'findings' are preserved.
    """
    # 1. First ensure all newly defined metadata tables (users, user_sessions, oauth_accounts, etc.) exist
    Base.metadata.create_all(connection)

    inspector = inspect(connection)
    tables = inspector.get_table_names()

    # 2. Check 'findings' table for 'fingerprint' column (Phase 2 migration)
    if "findings" in tables:
        columns = [c["name"] for c in inspector.get_columns("findings")]
        if "fingerprint" not in columns:
            logger.info("Migrating database: adding 'fingerprint' column to findings table.")
            try:
                connection.execute(text("ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64)"))
            except Exception as e:
                logger.warning("Could not add fingerprint column (it may already exist): %s", e)

            try:
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings(fingerprint)"))
            except Exception as e:
                logger.debug("Index creation note (ix_findings_fingerprint): %s", e)

    # 3. Check 'projects' table for 'owner_id' column (Phase 3 migration)
    # The 'users' table is guaranteed to exist from step 1, ensuring foreign key creation succeeds on PostgreSQL.
    if "projects" in tables:
        columns = [c["name"] for c in inspector.get_columns("projects")]
        if "owner_id" not in columns:
            logger.info("Migrating database: adding nullable 'owner_id' column to projects table.")
            try:
                if connection.dialect.name == "sqlite":
                    connection.execute(
                        text("ALTER TABLE projects ADD COLUMN owner_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL")
                    )
                else:
                    connection.execute(
                        text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS owner_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL")
                    )
            except Exception as e:
                logger.warning("Could not add owner_id column (it may already exist): %s", e)

            try:
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_projects_owner_id ON projects(owner_id)"))
            except Exception as e:
                logger.debug("Index creation note (ix_projects_owner_id): %s", e)

    # 4. Explicit fallback migration for 'oauth_states' table and indexes (Phase 3.3 replay protection)
    if "oauth_states" not in tables:
        logger.info("Migrating database: creating 'oauth_states' table and indexes.")
        if connection.dialect.name == "sqlite":
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
            # PostgreSQL dialect-aware DDL with timezone-aware timestamps
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

        try:
            connection.execute(create_oauth_states_sql)
        except Exception as e:
            logger.warning("Could not create oauth_states table: %s", e)

        indexes_sql = [
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_oauth_states_state_hash ON oauth_states(state_hash)",
            "CREATE INDEX IF NOT EXISTS ix_oauth_states_nonce ON oauth_states(nonce)",
            "CREATE INDEX IF NOT EXISTS ix_oauth_states_expires_at ON oauth_states(expires_at)",
            "CREATE INDEX IF NOT EXISTS ix_oauth_states_consumed_at ON oauth_states(consumed_at)",
        ]
        for idx_sql in indexes_sql:
            try:
                connection.execute(text(idx_sql))
            except Exception as e:
                logger.debug("Index creation note for oauth_states: %s", e)



