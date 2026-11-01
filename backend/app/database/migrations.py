import logging
from sqlalchemy import inspect, text

logger = logging.getLogger("sentriq.database.migrations")


def run_migrations(connection) -> None:
    """Safely apply schema migrations for existing databases without breaking user data."""
    inspector = inspect(connection)
    tables = inspector.get_table_names()

    if "findings" in tables:
        columns = [c["name"] for c in inspector.get_columns("findings")]
        if "fingerprint" not in columns:
            logger.info("Migrating database: adding 'fingerprint' column to findings table.")
            try:
                connection.execute(text("ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64)"))
            except Exception as e:
                logger.warning("Could not add fingerprint column (it may already exist): %s", e)

            try:
                if connection.dialect.name == "sqlite":
                    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings(fingerprint)"))
                else:
                    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings(fingerprint)"))
            except Exception as e:
                logger.debug("Index creation note: %s", e)
