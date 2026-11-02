import uuid
import sqlite3
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine, inspect, text, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.models.base import Base
from app.models.user import User, OAuthAccount, UserSession, LoginAttempt, OAuthState
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.database.migrations import run_migrations



def test_fresh_database_creation_includes_all_tables_and_indexes():
    """Verify that a fresh database creates all models, foreign keys, and indexes."""
    engine = create_engine("sqlite:///:memory:")
    with engine.connect() as conn:
        run_migrations(conn)
        conn.commit()

        inspector = inspect(conn)
        tables = set(inspector.get_table_names())
        expected_tables = {
            "users",
            "oauth_accounts",
            "user_sessions",
            "login_attempts",
            "oauth_states",
            "projects",
            "scans",
            "findings",
        }
        assert expected_tables.issubset(tables), f"Missing tables: {expected_tables - tables}"

        # Verify columns on projects
        project_cols = {c["name"] for c in inspector.get_columns("projects")}
        assert "owner_id" in project_cols

        # Verify index on projects.owner_id
        project_indexes = {idx["name"] for idx in inspector.get_indexes("projects")}
        assert "ix_projects_owner_id" in project_indexes

        # Verify user_sessions indexes
        session_indexes = {idx["name"] for idx in inspector.get_indexes("user_sessions")}
        assert "ix_user_sessions_token_hash" in session_indexes
        assert "ix_user_sessions_user_id" in session_indexes

        # Verify login_attempts compound indexes
        login_indexes = {idx["name"] for idx in inspector.get_indexes("login_attempts")}
        assert "ix_login_attempts_email_attempted_at" in login_indexes
        assert "ix_login_attempts_ip_attempted_at" in login_indexes

        # Verify oauth_states indexes
        oauth_state_indexes = {idx["name"] for idx in inspector.get_indexes("oauth_states")}
        assert "ix_oauth_states_state_hash" in oauth_state_indexes



def test_migration_against_legacy_database_preserves_records(tmp_path):
    """Test that running migrations on a legacy database preserves projects, scans, and findings."""
    db_file = tmp_path / "legacy.db"
    raw_conn = sqlite3.connect(str(db_file))
    cur = raw_conn.cursor()

    # Simulate legacy schema without owner_id
    cur.execute("""
        CREATE TABLE projects (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            target_url VARCHAR(1024) NOT NULL,
            authorization_confirmed BOOLEAN NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE scans (
            id VARCHAR(36) PRIMARY KEY,
            project_id VARCHAR(36) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            status VARCHAR(32) NOT NULL,
            posture_score INTEGER,
            grade VARCHAR(2),
            target_url VARCHAR(1024) NOT NULL,
            started_at TIMESTAMP NOT NULL,
            completed_at TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE findings (
            id VARCHAR(36) PRIMARY KEY,
            scan_id VARCHAR(36) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            title VARCHAR(255) NOT NULL,
            severity VARCHAR(32) NOT NULL,
            status VARCHAR(32) NOT NULL,
            fingerprint VARCHAR(64)
        )
    """)

    # Insert legacy records
    proj_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    finding_id = str(uuid.uuid4())
    now_str = datetime.now(timezone.utc).isoformat()

    cur.execute(
        "INSERT INTO projects VALUES (?, ?, ?, ?, ?, ?)",
        (proj_id, "Legacy Mission Critical", "https://legacy.example.com", 1, now_str, now_str),
    )
    cur.execute(
        "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, proj_id, "completed", 95, "A", "https://legacy.example.com", now_str, now_str),
    )
    cur.execute(
        "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?)",
        (finding_id, scan_id, "TLS Certificate Valid", "low", "open", "fp-12345"),
    )
    raw_conn.commit()
    raw_conn.close()

    # Apply migration using Sentriq engine
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.connect() as conn:
        run_migrations(conn)
        conn.commit()

        # Check that owner_id column exists
        inspector = inspect(conn)
        cols = {c["name"] for c in inspector.get_columns("projects")}
        assert "owner_id" in cols

        # Query legacy project: owner_id must be None, data intact
        row = conn.execute(
            text("SELECT id, name, target_url, owner_id FROM projects WHERE id = :pid"),
            {"pid": proj_id},
        ).fetchone()
        assert row is not None
        assert row[0] == proj_id
        assert row[1] == "Legacy Mission Critical"
        assert row[2] == "https://legacy.example.com"
        assert row[3] is None, "Legacy projects must have owner_id as NULL"

        # Query related scans and findings: preserved completely
        scan_row = conn.execute(
            text("SELECT id, project_id, status FROM scans WHERE id = :sid"),
            {"sid": scan_id},
        ).fetchone()
        assert scan_row is not None
        assert scan_row[1] == proj_id

        finding_row = conn.execute(
            text("SELECT id, scan_id, title FROM findings WHERE id = :fid"),
            {"fid": finding_id},
        ).fetchone()
        assert finding_row is not None
        assert finding_row[1] == scan_id


def test_migrations_are_idempotent(tmp_path):
    """Running migrations multiple times consecutively causes no errors or duplicate schema changes."""
    db_file = tmp_path / "idempotent.db"
    engine = create_engine(f"sqlite:///{db_file}")

    with engine.connect() as conn:
        run_migrations(conn)
        conn.commit()

    # Second pass
    with engine.connect() as conn:
        run_migrations(conn)
        conn.commit()

    # Third pass
    with engine.connect() as conn:
        run_migrations(conn)
        conn.commit()

    inspector = inspect(engine)
    assert "owner_id" in {c["name"] for c in inspector.get_columns("projects")}


def test_user_model_constraints_and_uniqueness():
    """Verify unique email constraint on User model."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        u1 = User(
            id=str(uuid.uuid4()),
            email="security@sentriq.io",
            full_name="Lead Analyst",
            is_active=True,
        )
        session.add(u1)
        session.commit()

        # Duplicate email must raise IntegrityError
        u2 = User(
            id=str(uuid.uuid4()),
            email="security@sentriq.io",
            full_name="Duplicate User",
            is_active=True,
        )
        session.add(u2)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_oauth_account_uniqueness_constraint():
    """Verify compound uniqueness (provider, provider_account_id)."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        user = User(
            id=str(uuid.uuid4()),
            email="github-user@sentriq.io",
            is_active=True,
        )
        session.add(user)
        session.commit()

        oa1 = OAuthAccount(
            id=str(uuid.uuid4()),
            user_id=user.id,
            provider="github",
            provider_account_id="123456",
            provider_username="gh-dev",
        )
        session.add(oa1)
        session.commit()

        # Same provider + provider_account_id must fail even for different user
        user2 = User(
            id=str(uuid.uuid4()),
            email="another@sentriq.io",
            is_active=True,
        )
        session.add(user2)
        session.commit()

        oa2 = OAuthAccount(
            id=str(uuid.uuid4()),
            user_id=user2.id,
            provider="github",
            provider_account_id="123456",
        )
        session.add(oa2)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_user_session_token_hash_uniqueness_and_active_helper():
    """Verify session token hash uniqueness and is_active logic."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        user = User(id=str(uuid.uuid4()), email="test-sess@sentriq.io")
        session.add(user)
        session.commit()

        now = datetime.now(timezone.utc)
        token_hash = "a" * 64
        sess = UserSession(
            id=str(uuid.uuid4()),
            user_id=user.id,
            token_hash=token_hash,
            expires_at=now + timedelta(days=7),
        )
        session.add(sess)
        session.commit()
        assert sess.is_active is True

        # Expired session is not active
        expired_sess = UserSession(
            id=str(uuid.uuid4()),
            user_id=user.id,
            token_hash="b" * 64,
            expires_at=now - timedelta(seconds=10),
        )
        session.add(expired_sess)
        session.commit()
        assert expired_sess.is_active is False

        # Revoked session is not active
        revoked_sess = UserSession(
            id=str(uuid.uuid4()),
            user_id=user.id,
            token_hash="c" * 64,
            expires_at=now + timedelta(days=7),
            revoked_at=now,
        )
        session.add(revoked_sess)
        session.commit()
        assert revoked_sess.is_active is False

        # Duplicate token_hash raises IntegrityError
        dup_sess = UserSession(
            id=str(uuid.uuid4()),
            user_id=user.id,
            token_hash=token_hash,
            expires_at=now + timedelta(days=7),
        )
        session.add(dup_sess)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_project_owner_relationship_and_set_null_on_delete():
    """Verify that deleting a User sets Project.owner_id to NULL without deleting the Project."""
    # SQLite requires PRAGMA foreign_keys=ON to enforce foreign key actions
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.execute("PRAGMA foreign_keys = ON")

    engine = create_engine("sqlite://", creator=lambda: raw_conn)
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        user = User(id=str(uuid.uuid4()), email="project-owner@sentriq.io")
        session.add(user)
        session.commit()

        project = Project(
            id=str(uuid.uuid4()),
            name="Assigned Security Project",
            target_url="https://target.sentriq.io",
            authorization_confirmed=True,
            owner_id=user.id,
        )
        session.add(project)
        session.commit()

        # Query project back
        p = session.scalar(select(Project).where(Project.id == project.id))
        assert p is not None
        assert p.owner_id == user.id
        assert p.owner.email == "project-owner@sentriq.io"

        # Delete user
        session.delete(user)
        session.commit()

        # Project MUST still exist, with owner_id set to NULL (ondelete="SET NULL")
        p_after = session.scalar(select(Project).where(Project.id == project.id))
        assert p_after is not None
        assert p_after.owner_id is None
        assert p_after.owner is None


def test_user_cascade_deletes_sessions_and_oauth_accounts():
    """Verify deleting a User cascades to their sessions and OAuth accounts."""
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.execute("PRAGMA foreign_keys = ON")

    engine = create_engine("sqlite://", creator=lambda: raw_conn)
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        user = User(id=str(uuid.uuid4()), email="user-to-delete@sentriq.io")
        session.add(user)
        session.commit()

        sess = UserSession(
            id=str(uuid.uuid4()),
            user_id=user.id,
            token_hash="d" * 64,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        oauth = OAuthAccount(
            id=str(uuid.uuid4()),
            user_id=user.id,
            provider="github",
            provider_account_id="99999",
        )
        session.add_all([sess, oauth])
        session.commit()

        session.delete(user)
        session.commit()

        # Sessions and OAuth accounts deleted via cascade
        s_count = session.query(UserSession).filter_by(user_id=user.id).count()
        o_count = session.query(OAuthAccount).filter_by(user_id=user.id).count()
        assert s_count == 0
        assert o_count == 0


def test_login_attempts_audit_model():
    """Verify LoginAttempt records can be inserted and queried with compound indexes."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        attempt1 = LoginAttempt(
            id=str(uuid.uuid4()),
            ip_address="203.0.113.10",
            email="analyst@sentriq.io",
            success=False,
        )
        attempt2 = LoginAttempt(
            id=str(uuid.uuid4()),
            ip_address="203.0.113.10",
            email="analyst@sentriq.io",
            success=True,
        )
        session.add_all([attempt1, attempt2])
        session.commit()

        rows = session.scalars(
            select(LoginAttempt).where(LoginAttempt.ip_address == "203.0.113.10")
        ).all()
        assert len(rows) == 2
        assert {r.success for r in rows} == {True, False}


def test_migration_failure_rollback():
    """Verify transaction rollback when a migration operation fails."""
    # SQLite with Python 3.12+ PEP 249 autocommit=False supports full transactional DDL rollback
    raw_conn = sqlite3.connect(":memory:", autocommit=False)
    cur = raw_conn.cursor()
    cur.execute("CREATE TABLE projects (id VARCHAR(36) PRIMARY KEY, name TEXT)")
    cur.execute("INSERT INTO projects VALUES ('p1', 'Sensitive Target')")
    raw_conn.commit()

    # Simulate an error within a transaction block
    try:
        cur.execute("ALTER TABLE projects ADD COLUMN owner_id VARCHAR(36)")
        cur.execute("INSERT INTO non_existent_table VALUES (1)")
        raw_conn.commit()
    except Exception:
        raw_conn.rollback()

    # Verify that the schema change rolled back
    cur.execute("PRAGMA table_info(projects)")
    cols = {r[1] for r in cur.fetchall()}
    assert "owner_id" not in cols, "Failed transaction must roll back schema alterations"

    cur.execute("SELECT id, name FROM projects")
    row = cur.fetchone()
    assert row is not None
    assert row[0] == "p1"


def test_project_deletion_does_not_delete_user():
    """Verify deleting a Project leaves the owner User and other projects intact."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        user = User(id=str(uuid.uuid4()), email="analyst@sentriq.io")
        p1 = Project(
            id=str(uuid.uuid4()),
            name="Project 1",
            target_url="https://p1.sentriq.io",
            owner_id=user.id,
        )
        p2 = Project(
            id=str(uuid.uuid4()),
            name="Project 2",
            target_url="https://p2.sentriq.io",
            owner_id=user.id,
        )
        session.add_all([user, p1, p2])
        session.commit()

        # Delete Project 1
        session.delete(p1)
        session.commit()

        # User and Project 2 MUST remain
        u = session.scalar(select(User).where(User.id == user.id))
        assert u is not None
        assert u.email == "analyst@sentriq.io"

        remaining_projects = session.scalars(
            select(Project).where(Project.owner_id == user.id)
        ).all()
        assert len(remaining_projects) == 1
        assert remaining_projects[0].id == p2.id


def test_user_model_superuser_defaults_to_false():
    """Verify that is_superuser defaults to False on the persisted User entity."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        u = User(id=str(uuid.uuid4()), email="test@sentriq.io")
        session.add(u)
        session.commit()
        session.refresh(u)
        assert u.is_superuser is False
        assert u.is_active is True
        assert u.failed_login_attempts == 0
        assert u.locked_until is None


def test_legacy_projects_isolation_from_authenticated_user_queries():
    """Verify legacy projects with owner_id = NULL are strictly isolated from user queries."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        user = User(id=str(uuid.uuid4()), email="regular@sentriq.io")
        owned_proj = Project(
            id=str(uuid.uuid4()),
            name="Owned Project",
            target_url="https://owned.sentriq.io",
            owner_id=user.id,
        )
        legacy_proj = Project(
            id=str(uuid.uuid4()),
            name="Unassigned Legacy Project",
            target_url="https://legacy.sentriq.io",
            owner_id=None,  # Legacy
        )
        session.add_all([user, owned_proj, legacy_proj])
        session.commit()

        # When querying by owner_id == user.id, legacy projects NEVER appear
        user_projects = session.scalars(
            select(Project).where(Project.owner_id == user.id)
        ).all()
        assert len(user_projects) == 1
        assert user_projects[0].name == "Owned Project"
        assert legacy_proj.id not in [p.id for p in user_projects]


def test_migration_creates_oauth_states_table_on_legacy_database(tmp_path):
    """Test that running migrations on a legacy database explicitly creates oauth_states table and indexes."""
    db_file = tmp_path / "legacy_oauth.db"
    raw_conn = sqlite3.connect(str(db_file))
    cur = raw_conn.cursor()

    # Create only legacy tables without oauth_states
    cur.execute("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL)")
    cur.execute("CREATE TABLE projects (id VARCHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, target_url VARCHAR(1024) NOT NULL)")
    raw_conn.commit()
    raw_conn.close()

    # Run migrations
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.connect() as conn:
        run_migrations(conn)
        conn.commit()

        inspector = inspect(conn)
        tables = set(inspector.get_table_names())
        assert "oauth_states" in tables

        columns = {c["name"] for c in inspector.get_columns("oauth_states")}
        expected_cols = {"id", "state_hash", "nonce", "redirect_path", "expires_at", "consumed_at", "created_at", "updated_at"}
        assert expected_cols.issubset(columns)

        indexes = {idx["name"] for idx in inspector.get_indexes("oauth_states")}
        assert "ix_oauth_states_state_hash" in indexes
        assert "ix_oauth_states_nonce" in indexes
        assert "ix_oauth_states_expires_at" in indexes
        assert "ix_oauth_states_consumed_at" in indexes

    # Verify inserting and querying OAuthState record works on migrated database
    with Session(engine) as session:
        now = datetime.now(timezone.utc)
        record = OAuthState(
            id=str(uuid.uuid4()),
            state_hash="sha256-hash-value-1234567890abcdef1234567890abcdef1234567890abcdef",
            nonce="nonce-12345",
            redirect_path="/overview",
            expires_at=now + timedelta(minutes=10),
            consumed_at=None,
        )
        session.add(record)
        session.commit()

        fetched = session.scalar(select(OAuthState).where(OAuthState.nonce == "nonce-12345"))
        assert fetched is not None
        assert fetched.redirect_path == "/overview"
        assert fetched.is_consumed is False


def test_postgresql_ddl_syntax_validity():
    """Verify that the PostgreSQL dialect DDL for oauth_states compiles correctly without dialect errors."""
    compiled_ddl = str(CreateTable(OAuthState.__table__).compile(dialect=postgresql.dialect()))
    assert "oauth_states" in compiled_ddl
    assert "VARCHAR(64)" in compiled_ddl
    assert "TIMESTAMP WITH TIME ZONE" in compiled_ddl


def test_startup_migration_path_executes_explicit_oauth_states_migration(tmp_path):
    """Verify that the normal application startup path runs explicit migrations without shadowing by create_all."""
    db_file = tmp_path / "startup_test.db"
    raw_conn = sqlite3.connect(str(db_file))
    cur = raw_conn.cursor()
    # Create existing tables with legacy data
    cur.execute("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL)")
    cur.execute("INSERT INTO users (id, email) VALUES ('u-1', 'existing@sentriq.io')")
    raw_conn.commit()
    raw_conn.close()

    engine = create_engine(f"sqlite:///{db_file}")

    # Simulate exact startup sequence from main.py: lifespan
    with engine.connect() as conn:
        run_migrations(conn)
        conn.commit()

        inspector = inspect(conn)
        tables = set(inspector.get_table_names())
        # oauth_states must have been created
        assert "oauth_states" in tables
        # Preexisting users must be preserved
        user_rows = conn.execute(text("SELECT email FROM users WHERE id = 'u-1'")).fetchall()
        assert len(user_rows) == 1
        assert user_rows[0][0] == "existing@sentriq.io"

        # Explicit migration indexes must exist
        indexes = {idx["name"] for idx in inspector.get_indexes("oauth_states")}
        assert "ix_oauth_states_state_hash" in indexes
        assert "ix_oauth_states_nonce" in indexes
        assert "ix_oauth_states_expires_at" in indexes
        assert "ix_oauth_states_consumed_at" in indexes

    # Verify idempotency by running migrations again
    with engine.connect() as conn:
        run_migrations(conn)
        conn.commit()
        # Verify existing data still preserved
        user_rows = conn.execute(text("SELECT email FROM users WHERE id = 'u-1'")).fetchall()
        assert len(user_rows) == 1



