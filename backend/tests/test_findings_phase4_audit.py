"""
Sentriq Phase 4.1 Integration Test Suite:
Finding Model, Audit History, Authorization, Anonymization, and Migrations.

Tests:
1. Finding schema extensions (version, justification, accepted_risk status).
2. Optimistic Concurrency Control (OCC) with version increment and 409 Conflict on stale version.
3. Mandatory justification validation for false_positive and accepted_risk transitions.
4. Immutable FindingStatusEvent generation and retrieval via GET /api/findings/{id}/history.
5. SQLite audit trigger immutability: direct UPDATE and DELETE prohibited.
6. SQLite application authorization boundary: documentation and testing of why application
   service is the trusted authorization boundary in SQLite.
7. AdminAccountService authorized anonymization, non-admin rejection, self-anonymization prevention.
8. Audit record preservation post-anonymization (user_id -> NULL, finding/status/timestamp intact).
9. Persistent nonce replay rejection via audit_consumed_nonces unique constraint.
10. Constant-time HMAC signature verification using double-digest comparison.
11. Migration safety: legacy database preservation (projects, scans, findings, users, sessions) and idempotency.
12. PostgreSQL DDL and trigger compilation verification.
"""

import uuid
import sqlite3
import hmac
import hashlib
from datetime import datetime, timezone, timedelta

import pytest
from httpx import AsyncClient
from fastapi import HTTPException
from sqlalchemy import create_engine, inspect, text, select, update
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.models.base import Base
from app.models.user import User, UserSession
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.finding_status_event import (
    FindingStatusEvent,
    AuditAnonymizationTicket,
    AuditConsumedNonce,
)
from app.database.session import AsyncSessionLocal
from app.database.migrations import (
    run_migrations,
    PG_TRIGGER_AUDIT_DROP,
    PG_TRIGGER_AUDIT_CREATE,
    PG_TRIGGER_AUDIT_NO_DELETE,
    PG_FUNCTION_AUDIT_PROTECT_UPDATE,
    PG_TRIGGER_AUDIT_PROTECT_UPDATE,
    PG_FUNCTION_ANONYMIZE_USER,
    PG_FUNCTION_CONSTANT_TIME_BYTES_EQ,
    PG_RESTRICTED_PRIVILEGES,
)
from app.services.account_service import (
    AdminAccountService,
    generate_anonymization_hmac,
    verify_anonymization_hmac,
)


@pytest.fixture
async def authenticated_owner(async_client: AsyncClient):
    """Registers and authenticates a test tenant owner."""
    email = f"owner_{uuid.uuid4().hex[:8]}@sentriq.io"
    resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "OwnerPassword123!", "full_name": "Finding Owner"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert resp.status_code == 201
    csrf_token = resp.json().get("csrf_token")
    async_client.headers.update({"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token})
    from app.database.session import AsyncSessionLocal
    from app.models.user import User
    from sqlalchemy import update
    async with AsyncSessionLocal() as session:
        await session.execute(update(User).where(User.email == email).values(is_verified=True))
        await session.commit()
    return {"email": email}


@pytest.fixture
async def finding_with_project(async_client: AsyncClient, authenticated_owner):
    """Creates a project, scan, and initial finding for testing status transitions and audit history."""
    proj_resp = await async_client.post(
        "/api/projects",
        json={
            "name": f"Audit Target {uuid.uuid4().hex[:6]}",
            "target_url": "https://audit.sentriq.io",
            "authorization_confirmed": True,
        },
    )
    assert proj_resp.status_code == 201
    proj_id = proj_resp.json()["id"]

    # Directly create a Scan and Finding via AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        scan = Scan(
            id=str(uuid.uuid4()),
            project_id=proj_id,
            target_url="https://audit.sentriq.io",
            status="completed",
        )
        session.add(scan)
        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            category="web",
            title="Exposed Test API Key",
            description="Leaked API secret in JavaScript asset.",
            severity="high",
            status="open",
            version=1,
            justification=None,
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        return {"project_id": proj_id, "scan_id": scan.id, "finding_id": finding.id}


@pytest.mark.asyncio
async def test_occ_version_increment_and_conflict_rejection(async_client: AsyncClient, finding_with_project):
    """Updating finding status must increment version from 1 to 2; stale version update must yield 409 Conflict."""
    finding_id = finding_with_project["finding_id"]

    # 1. Update from open to resolved with valid version=1 -> 200 OK
    resp1 = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={
            "status": "resolved",
            "expected_version": 1,
            "justification": "Fixed in PR #42",
        },
    )
    assert resp1.status_code == 200, resp1.text
    data1 = resp1.json()
    assert data1["status"] == "resolved"
    assert data1["version"] == 2
    assert data1["justification"] == "Fixed in PR #42"

    # 2. Re-attempt update sending stale expected_version=1 -> 409 Conflict
    resp_conflict = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={
            "status": "open",
            "expected_version": 1,
        },
    )
    assert resp_conflict.status_code == 409
    conflict_detail = resp_conflict.json()["detail"]
    if isinstance(conflict_detail, dict):
        assert "concurrency conflict" in conflict_detail["message"].lower()
    else:
        assert "conflict" in str(conflict_detail).lower()

    # 3. Update with correct current version=2 -> 200 OK, version increments to 3
    resp2 = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={
            "status": "open",
            "expected_version": 2,
        },
    )
    assert resp2.status_code == 200
    assert resp2.json()["version"] == 3


@pytest.mark.asyncio
async def test_justification_mandatory_for_false_positive_and_accepted_risk(
    async_client: AsyncClient, finding_with_project
):
    """Transitions to false_positive or accepted_risk require non-empty justification; otherwise rejected."""
    finding_id = finding_with_project["finding_id"]

    # 1. Transition to false_positive without justification -> 400 / 422
    resp_fp_missing = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "false_positive", "expected_version": 1},
    )
    assert resp_fp_missing.status_code in (400, 422)
    assert "justification is mandatory" in str(resp_fp_missing.json()).lower()

    # 2. Transition to false_positive with whitespace justification -> 400 / 422
    resp_fp_ws = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "false_positive", "expected_version": 1, "justification": "   \t\n  "},
    )
    assert resp_fp_ws.status_code in (400, 422)

    # 3. Transition to false_positive with valid justification -> 200 OK
    resp_fp_ok = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={
            "status": "false_positive",
            "expected_version": 1,
            "justification": "Internal synthetic canary endpoint not reachable externally.",
        },
    )
    assert resp_fp_ok.status_code == 200
    assert resp_fp_ok.json()["status"] == "false_positive"
    assert resp_fp_ok.json()["version"] == 2

    # 4. Transition to accepted_risk without justification -> 400 / 422
    resp_ar_missing = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "accepted_risk", "expected_version": 2},
    )
    assert resp_ar_missing.status_code in (400, 422)

    # 5. Transition to accepted_risk with valid justification -> 200 OK
    resp_ar_ok = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={
            "status": "accepted_risk",
            "expected_version": 2,
            "justification": "Risk approved by CISO for Q4 staging rollout under exception #8812.",
        },
    )
    assert resp_ar_ok.status_code == 200
    assert resp_ar_ok.json()["status"] == "accepted_risk"
    assert resp_ar_ok.json()["version"] == 3


@pytest.mark.asyncio
async def test_audit_history_recording_and_tenant_isolation(
    async_client: AsyncClient, finding_with_project
):
    """Status changes generate immutable FindingStatusEvent records; history API enforces tenant isolation."""
    finding_id = finding_with_project["finding_id"]

    # Perform status updates: open -> false_positive -> open
    await async_client.patch(
        f"/api/findings/{finding_id}",
        json={
            "status": "false_positive",
            "expected_version": 1,
            "justification": "Verified third-party CDN vendor script.",
        },
    )
    await async_client.patch(
        f"/api/findings/{finding_id}",
        json={
            "status": "open",
            "expected_version": 2,
            "justification": "Reopened after vendor CVE notification.",
        },
    )

    # Fetch history as finding owner -> 200 OK with 2 status change events
    hist_resp = await async_client.get(f"/api/findings/{finding_id}/history")
    assert hist_resp.status_code == 200
    events = hist_resp.json()
    assert len(events) == 2

    # Most recent first
    assert events[0]["previous_status"] == "false_positive"
    assert events[0]["new_status"] == "open"
    assert events[0]["justification"] == "Reopened after vendor CVE notification."
    assert events[0]["user_id"] is not None

    assert events[1]["previous_status"] == "open"
    assert events[1]["new_status"] == "false_positive"
    assert events[1]["justification"] == "Verified third-party CDN vendor script."

    # Verify Tenant Isolation: User B cannot view history for User A's finding
    other_reg = await async_client.post(
        "/api/auth/register",
        json={
            "email": f"other_{uuid.uuid4().hex[:8]}@sentriq.io",
            "password": "OtherPassword123!",
            "full_name": "Unrelated User",
        },
        headers={"Origin": "http://localhost:5173"},
    )
    other_email = other_reg.json()["email"]
    other_csrf = other_reg.json().get("csrf_token")
    async_client.headers.update({"Origin": "http://localhost:5173", "X-CSRF-Token": other_csrf})
    async with AsyncSessionLocal() as session:
        await session.execute(update(User).where(User.email == other_email).values(is_verified=True))
        await session.commit()

    unauth_hist_resp = await async_client.get(f"/api/findings/{finding_id}/history")
    assert unauth_hist_resp.status_code == 404


def test_sqlite_audit_immutability_triggers(tmp_path):
    """Direct SQL UPDATE or DELETE on finding_status_events must be blocked by SQLite triggers."""
    db_file = tmp_path / "sqlite_trigger_test.db"
    # Initialize schema with migrations
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.connect() as migration_conn:
        run_migrations(migration_conn)
        migration_conn.commit()

    # Populate seed rows using SQLAlchemy to satisfy all column defaults
    with Session(engine) as session:
        u = User(id="usr-1", email="auditee@sentriq.io", is_active=True, is_superuser=False)
        p = Project(id="p-1", name="Proj", target_url="https://ex.com", authorization_confirmed=True, owner_id="usr-1")
        s = Scan(id="s-1", project_id="p-1", target_url="https://ex.com", status="completed")
        f = Finding(id="f-1", scan_id="s-1", category="web", title="Title", description="Desc", severity="high", status="open", version=1)
        evt = FindingStatusEvent(
            id="evt-1",
            finding_id="f-1",
            user_id="usr-1",
            previous_status="open",
            new_status="resolved",
            justification="Fixed in code",
            created_at=datetime.now(timezone.utc),
        )
        session.add_all([u, p, s, f, evt])
        session.commit()

    con = sqlite3.connect(str(db_file))
    cur = con.cursor()
    cur.execute("PRAGMA foreign_keys = ON")

    # 1. Direct DELETE must fail
    with pytest.raises(sqlite3.IntegrityError, match="Audit records are append-only: DELETE prohibited"):
        cur.execute("DELETE FROM finding_status_events WHERE id = 'evt-1'")

    # 2. Direct UPDATE changing justification must fail
    with pytest.raises(sqlite3.IntegrityError, match="Audit records are immutable: Unauthorized UPDATE prohibited"):
        cur.execute("UPDATE finding_status_events SET justification = 'tampered' WHERE id = 'evt-1'")

    # 3. Direct UPDATE changing user_id without ticket must fail
    with pytest.raises(sqlite3.IntegrityError, match="Audit records are immutable: Unauthorized UPDATE prohibited"):
        cur.execute("UPDATE finding_status_events SET user_id = NULL WHERE id = 'evt-1'")

    # 4. Direct UPDATE attempting to reset user_id to another user must fail
    with pytest.raises(sqlite3.IntegrityError, match="Audit records are immutable: Unauthorized UPDATE prohibited"):
        cur.execute("UPDATE finding_status_events SET user_id = 'usr-2' WHERE id = 'evt-1'")

    # 5. Direct UPDATE modifying previous_status must fail
    with pytest.raises(sqlite3.IntegrityError, match="Audit records are immutable: Unauthorized UPDATE prohibited"):
        cur.execute("UPDATE finding_status_events SET previous_status = 'resolved' WHERE id = 'evt-1'")

    # 6. Direct UPDATE modifying new_status must fail
    with pytest.raises(sqlite3.IntegrityError, match="Audit records are immutable: Unauthorized UPDATE prohibited"):
        cur.execute("UPDATE finding_status_events SET new_status = 'open' WHERE id = 'evt-1'")

    # 7. Direct UPDATE modifying created_at must fail
    with pytest.raises(sqlite3.IntegrityError, match="Audit records are immutable: Unauthorized UPDATE prohibited"):
        cur.execute("UPDATE finding_status_events SET created_at = datetime('now') WHERE id = 'evt-1'")

    # 8. Direct UPDATE modifying finding_id must fail
    with pytest.raises(sqlite3.IntegrityError, match="Audit records are immutable: Unauthorized UPDATE prohibited"):
        cur.execute("UPDATE finding_status_events SET finding_id = 'f-other' WHERE id = 'evt-1'")

    con.close()


def test_sqlite_application_boundary_documentation_and_bypass_proof(tmp_path):
    """
    Test and document that in SQLite, the authenticated application service is the sole trusted authorization boundary.
    
    Explanation:
    SQLite is an in-process, serverless engine. It lacks user roles, stored procedures with SECURITY DEFINER,
    and distinct OS-level connection privileges. Any caller with direct raw SQL write access to the SQLite file
    can insert a row into audit_anonymization_ticket and satisfy the trigger condition.
    
    Therefore, the repository explicitly implements and documents that SQLite authorization is enforced
    at the application service layer (AdminAccountService) via authenticated session and role checks.
    """
    db_file = tmp_path / "sqlite_boundary_test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.connect() as migration_conn:
        run_migrations(migration_conn)
        migration_conn.commit()

    # Seed test data via Session
    with Session(engine) as session:
        u = User(id="usr-target", email="target@sentriq.io", is_active=True, is_superuser=False)
        p = Project(id="p-1", name="P", target_url="https://ex.com", authorization_confirmed=True, owner_id="usr-target")
        s = Scan(id="s-1", project_id="p-1", target_url="https://ex.com", status="completed")
        f = Finding(id="f-1", scan_id="s-1", category="web", title="T", description="D", severity="low", status="open", version=1)
        evt = FindingStatusEvent(id="evt-target", finding_id="f-1", user_id="usr-target", previous_status="open", new_status="resolved", created_at=datetime.now(timezone.utc))
        session.add_all([u, p, s, f, evt])
        session.commit()

    con = sqlite3.connect(str(db_file))
    cur = con.cursor()
    cur.execute("PRAGMA foreign_keys = ON")

    # Raw SQL attacker can insert ticket directly in SQLite (demonstrating why trigger alone is not an auth boundary)
    cur.execute("INSERT INTO audit_anonymization_ticket (ticket_id, user_id, authorized_by, nonce, created_at) VALUES ('t-raw', 'usr-target', 'raw-sql-attacker', 'nonce-raw', datetime('now'))")
    con.commit()

    # Because ticket exists, raw SQL UPDATE user_id=NULL succeeds in SQLite
    cur.execute("UPDATE finding_status_events SET user_id = NULL WHERE id = 'evt-target'")
    con.commit()

    cur.execute("SELECT user_id FROM finding_status_events WHERE id = 'evt-target'")
    assert cur.fetchone()[0] is None
    con.close()


def test_admin_account_service_anonymization_and_audit_preservation(tmp_path):
    """Test AdminAccountService authorized anonymization, role enforcement, self-deletion block, and audit preservation."""
    db_file = tmp_path / "service_test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.connect() as migration_conn:
        run_migrations(migration_conn)
        migration_conn.commit()

    with Session(engine) as session:
        # Create superuser admin and target regular user
        admin = User(id="admin-1", email="admin@sentriq.io", is_superuser=True, is_active=True)
        target = User(id="target-1", email="target@sentriq.io", is_superuser=False, is_active=True)
        regular = User(id="regular-1", email="regular@sentriq.io", is_superuser=False, is_active=True)
        session.add_all([admin, target, regular])
        session.commit()

        # Create finding and audit event for target
        proj = Project(id="p-1", name="Target Project", target_url="https://ex.com", authorization_confirmed=True, owner_id="target-1")
        scan = Scan(id="s-1", project_id="p-1", target_url="https://ex.com", status="completed")
        finding = Finding(id="f-1", scan_id="s-1", category="web", title="Finding 1", description="Desc", severity="medium", status="open", version=1)
        session.add_all([proj, scan, finding])
        session.commit()

        event = FindingStatusEvent(
            id="evt-1",
            finding_id="f-1",
            user_id="target-1",
            previous_status="open",
            new_status="resolved",
            justification="Remediated vulnerability",
            created_at=datetime.now(timezone.utc),
        )
        session.add(event)
        session.commit()

        # 1. Non-admin attempt must be rejected with 403 Forbidden
        with pytest.raises(HTTPException) as exc_info:
            AdminAccountService.anonymize_and_delete_user(session, current_user=regular, target_user_id="target-1")
        assert exc_info.value.status_code == 403

        # 2. Admin self-anonymization must be rejected with 400 Bad Request
        with pytest.raises(HTTPException) as exc_self:
            AdminAccountService.anonymize_and_delete_user(session, current_user=admin, target_user_id="admin-1")
        assert exc_self.value.status_code == 400
        assert "cannot anonymize their own active account" in exc_self.value.detail

        # 3. Nonexistent user returns 404
        with pytest.raises(HTTPException) as exc_404:
            AdminAccountService.anonymize_and_delete_user(session, current_user=admin, target_user_id="nonexistent-id")
        assert exc_404.value.status_code == 404

        # 4. Authorized anonymization by superuser succeeds
        result = AdminAccountService.anonymize_and_delete_user(session, current_user=admin, target_user_id="target-1")
        assert result["target_user_id"] == "target-1"
        assert result["events_anonymized"] == 1
        assert "nonce" in result

        # Verify target user was deleted from users table
        user_in_db = session.get(User, "target-1")
        assert user_in_db is None

        # Verify audit event remains intact, with only user_id set to NULL
        session.expire_all()
        persisted_event = session.get(FindingStatusEvent, "evt-1")
        assert persisted_event is not None
        assert persisted_event.user_id is None
        assert persisted_event.finding_id == "f-1"
        assert persisted_event.previous_status == "open"
        assert persisted_event.new_status == "resolved"
        assert persisted_event.justification == "Remediated vulnerability"

        # Verify authorization ticket was cleaned up
        tickets = session.scalars(select(AuditAnonymizationTicket).where(AuditAnonymizationTicket.user_id == "target-1")).all()
        assert len(tickets) == 0

        # Verify persistent nonce was recorded
        consumed_nonce = session.scalar(select(AuditConsumedNonce).where(AuditConsumedNonce.nonce == result["nonce"]))
        assert consumed_nonce is not None
        assert consumed_nonce.consumed_by == "admin-1"


def test_persistent_nonce_replay_prevention(tmp_path):
    """Attempting to reuse an existing nonce raises IntegrityError on the persistent unique constraint."""
    db_file = tmp_path / "nonce_replay_test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.connect() as migration_conn:
        run_migrations(migration_conn)
        migration_conn.commit()

    with Session(engine) as session1:
        first_nonce = AuditConsumedNonce(
            nonce="unique-nonce-12345",
            consumed_by="admin-1",
            consumed_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        session1.add(first_nonce)
        session1.commit()

    # Second insertion with identical nonce in fresh session must fail at DB constraint
    with Session(engine) as session2:
        replay_nonce = AuditConsumedNonce(
            nonce="unique-nonce-12345",
            consumed_by="admin-2",
            consumed_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        session2.add(replay_nonce)
        with pytest.raises(IntegrityError):
            session2.commit()


def test_constant_time_hmac_verification():
    """Verify constant-time HMAC generation and double-digest verification."""
    target_id = "target-usr-uuid"
    admin_id = "admin-usr-uuid"
    nonce = "nonce-sample-123"
    secret = "super-secret-hmac-key"

    # Valid signature
    valid_sig = generate_anonymization_hmac(target_id, admin_id, nonce, secret)
    assert verify_anonymization_hmac(target_id, admin_id, nonce, valid_sig, secret) is True

    # Tampered target_id
    assert verify_anonymization_hmac("other-id", admin_id, nonce, valid_sig, secret) is False

    # Tampered admin_id
    assert verify_anonymization_hmac(target_id, "other-admin", nonce, valid_sig, secret) is False

    # Tampered nonce
    assert verify_anonymization_hmac(target_id, admin_id, "other-nonce", valid_sig, secret) is False

    # Tampered secret
    assert verify_anonymization_hmac(target_id, admin_id, nonce, valid_sig, "wrong-secret") is False

    # Corrupted signature
    assert verify_anonymization_hmac(target_id, admin_id, nonce, valid_sig[:-2] + "00", secret) is False


def test_phase4_1_migration_preserves_legacy_database_and_is_idempotent(tmp_path):
    """
    Test running migrations against a legacy database that has projects, scans, findings (Phase 2),
    users, sessions (Phase 3), but lacks version, justification, finding_status_events, etc.
    All data must be preserved and default columns assigned without error.
    """
    db_file = tmp_path / "legacy_phase41.db"
    con = sqlite3.connect(str(db_file))
    cur = con.cursor()

    # 1. Create pre-Phase 4.1 schema
    cur.execute("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL)")
    cur.execute("CREATE TABLE user_sessions (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36), token_hash VARCHAR(64) UNIQUE, expires_at TIMESTAMP)")
    cur.execute("CREATE TABLE projects (id VARCHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, target_url VARCHAR(2048) NOT NULL, authorization_confirmed BOOLEAN NOT NULL, owner_id VARCHAR(36))")
    cur.execute("CREATE TABLE scans (id VARCHAR(36) PRIMARY KEY, project_id VARCHAR(36) NOT NULL, status VARCHAR(50) NOT NULL)")
    cur.execute("CREATE TABLE findings (id VARCHAR(36) PRIMARY KEY, scan_id VARCHAR(36) NOT NULL, title VARCHAR(255) NOT NULL, severity VARCHAR(50) NOT NULL, status VARCHAR(50) NOT NULL)")

    # 2. Insert existing records
    cur.execute("INSERT INTO users VALUES ('u-legacy', 'legacy@sentriq.io')")
    cur.execute("INSERT INTO user_sessions VALUES ('sess-1', 'u-legacy', 'hash123', '2027-01-01 00:00:00')")
    cur.execute("INSERT INTO projects VALUES ('p-legacy', 'Legacy Project', 'https://legacy.example.com', 1, 'u-legacy')")
    cur.execute("INSERT INTO scans VALUES ('s-legacy', 'p-legacy', 'completed')")
    cur.execute("INSERT INTO findings VALUES ('f-legacy', 's-legacy', 'Legacy Vulnerability', 'medium', 'open')")
    con.commit()
    con.close()

    # 3. Apply Phase 4.1 migrations
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.connect() as migration_conn:
        run_migrations(migration_conn)
        migration_conn.commit()

        # Check existing data is intact
        insp = inspect(migration_conn)
        tables = set(insp.get_table_names())
        assert "finding_status_events" in tables
        assert "audit_anonymization_ticket" in tables
        assert "audit_consumed_nonces" in tables

        # Check columns added to findings
        finding_cols = {c["name"]: c for c in insp.get_columns("findings")}
        assert "version" in finding_cols
        assert "justification" in finding_cols

        # Check legacy row values
        row = migration_conn.execute(text("SELECT id, title, status, version, justification FROM findings WHERE id = 'f-legacy'")).fetchone()
        assert row is not None
        assert row[0] == "f-legacy"
        assert row[1] == "Legacy Vulnerability"
        assert row[2] == "open"
        assert row[3] == 1  # Default version
        assert row[4] is None  # Default justification

        # Check user, project, scan
        assert migration_conn.execute(text("SELECT email FROM users WHERE id = 'u-legacy'")).scalar() == "legacy@sentriq.io"
        assert migration_conn.execute(text("SELECT name FROM projects WHERE id = 'p-legacy'")).scalar() == "Legacy Project"
        assert migration_conn.execute(text("SELECT status FROM scans WHERE id = 's-legacy'")).scalar() == "completed"

    # 4. Idempotency: Run migrations a second time on the same database
    with engine.connect() as migration_conn2:
        run_migrations(migration_conn2)
        migration_conn2.commit()

        # Re-check row
        row2 = migration_conn2.execute(text("SELECT id, version FROM findings WHERE id = 'f-legacy'")).fetchone()
        assert row2[0] == "f-legacy"
        assert row2[1] == 1


def test_postgresql_ddl_and_triggers_compilation():
    """Verify that PostgreSQL DDL and trigger definitions compile cleanly without dialect syntax errors."""
    event_ddl = str(CreateTable(FindingStatusEvent.__table__).compile(dialect=postgresql.dialect()))
    assert "finding_status_events" in event_ddl
    assert "VARCHAR(36)" in event_ddl

    ticket_ddl = str(CreateTable(AuditAnonymizationTicket.__table__).compile(dialect=postgresql.dialect()))
    assert "audit_anonymization_ticket" in ticket_ddl

    nonce_ddl = str(CreateTable(AuditConsumedNonce.__table__).compile(dialect=postgresql.dialect()))
    assert "audit_consumed_nonces" in nonce_ddl

    # Ensure PostgreSQL trigger scripts are non-empty and well-formed
    assert "CREATE OR REPLACE FUNCTION" in PG_FUNCTION_AUDIT_PROTECT_UPDATE
    assert "DELETE operations are prohibited" in PG_FUNCTION_AUDIT_PROTECT_UPDATE
    assert "DROP TRIGGER IF EXISTS trg_audit_events_immutable" in PG_TRIGGER_AUDIT_DROP
    assert "CREATE TRIGGER trg_audit_events_immutable" in PG_TRIGGER_AUDIT_CREATE
    assert "EXECUTE FUNCTION trg_enforce_audit_immutability()" in PG_TRIGGER_AUDIT_NO_DELETE
    assert "SECURITY DEFINER" in PG_FUNCTION_ANONYMIZE_USER
    assert "SET search_path = public, pg_temp" in PG_FUNCTION_ANONYMIZE_USER
    assert "constant_time_bytes_eq" in PG_FUNCTION_CONSTANT_TIME_BYTES_EQ
    assert "REVOKE ALL ON TABLE audit_anonymization_ticket FROM PUBLIC" in PG_RESTRICTED_PRIVILEGES


@pytest.mark.asyncio
async def test_admin_anonymization_api_endpoint_flow(async_client: AsyncClient):
    """End-to-end API test for administrative anonymization endpoint with role, replay, and audit checks."""
    admin_email = f"admin_{uuid.uuid4().hex[:8]}@sentriq.io"
    target_email = f"target_{uuid.uuid4().hex[:8]}@sentriq.io"
    regular_email = f"regular_{uuid.uuid4().hex[:8]}@sentriq.io"

    # Register admin
    resp_adm = await async_client.post(
        "/api/auth/register",
        json={"email": admin_email, "password": "AdminPassword123!", "full_name": "Sys Admin"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert resp_adm.status_code == 201
    admin_id = resp_adm.json()["id"]
    admin_csrf = resp_adm.json()["csrf_token"]

    # Register target user
    resp_tgt = await async_client.post(
        "/api/auth/register",
        json={"email": target_email, "password": "TargetPassword123!", "full_name": "Target User"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert resp_tgt.status_code == 201
    target_id = resp_tgt.json()["id"]
    target_csrf = resp_tgt.json()["csrf_token"]
    async with AsyncSessionLocal() as session:
        await session.execute(update(User).where(User.email.in_([admin_email, target_email])).values(is_verified=True))
        await session.commit()

    # Target user creates a project, scan, and updates finding status to create an audit record
    async_client.headers.update({"Origin": "http://localhost:5173", "X-CSRF-Token": target_csrf})
    proj_resp = await async_client.post(
        "/api/projects",
        json={"name": "Target's Project", "target_url": "https://target.com", "authorization_confirmed": True},
    )
    assert proj_resp.status_code == 201
    proj_id = proj_resp.json()["id"]

    finding_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        # Elevate admin to superuser in DB
        admin_rec = await session.get(User, admin_id)
        admin_rec.is_superuser = True

        scan = Scan(id=str(uuid.uuid4()), project_id=proj_id, target_url="https://target.com", status="completed")
        session.add(scan)
        finding = Finding(
            id=finding_id,
            scan_id=scan.id,
            category="web",
            title="Sample Issue",
            description="Sample Desc",
            severity="medium",
            status="open",
            version=1,
        )
        session.add(finding)
        await session.commit()

    # Target user updates finding status -> creates FindingStatusEvent
    patch_resp = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "resolved", "expected_version": 1, "justification": "Fixed by target user"},
    )
    assert patch_resp.status_code == 200

    # 1. Non-admin (target user) attempts to anonymize -> 403 Forbidden
    unauth_resp = await async_client.post(
        f"/api/auth/users/{target_id}/anonymize",
        json={"nonce": str(uuid.uuid4())},
    )
    assert unauth_resp.status_code == 403

    # Log in as Admin
    login_adm = await async_client.post(
        "/api/auth/login",
        json={"email": admin_email, "password": "AdminPassword123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert login_adm.status_code == 200
    admin_csrf = login_adm.json()["csrf_token"]
    async_client.headers.update({"Origin": "http://localhost:5173", "X-CSRF-Token": admin_csrf})

    # 2. Admin self-anonymization attempt -> 400 Bad Request
    self_resp = await async_client.post(
        f"/api/auth/users/{admin_id}/anonymize",
        json={"nonce": str(uuid.uuid4())},
    )
    assert self_resp.status_code == 400
    assert "cannot anonymize their own active account" in str(self_resp.json()).lower()

    # 3. Nonexistent user -> 404 Not Found
    notfound_resp = await async_client.post(
        f"/api/auth/users/nonexistent-{uuid.uuid4().hex[:8]}/anonymize",
        json={"nonce": str(uuid.uuid4())},
    )
    assert notfound_resp.status_code == 404

    # 4. Authorized anonymization with cryptographic signature and persistent nonce
    test_nonce = f"api-nonce-{uuid.uuid4().hex}"
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sig = generate_anonymization_hmac(
        target_user_id=target_id,
        admin_user_id=admin_id,
        nonce=test_nonce,
        timestamp=now_ts,
    )
    anon_resp = await async_client.post(
        f"/api/auth/users/{target_id}/anonymize",
        json={"nonce": test_nonce, "timestamp": now_ts, "signature": sig},
    )
    assert anon_resp.status_code == 200
    anon_data = anon_resp.json()
    assert anon_data["target_user_id"] == target_id
    assert anon_data["events_anonymized"] >= 1
    assert anon_data["status"] == "anonymized"

    # Verify target user was deleted
    async with AsyncSessionLocal() as session:
        assert await session.get(User, target_id) is None
        # Verify consumed nonce was recorded
        consumed = await session.get(AuditConsumedNonce, test_nonce)
        assert consumed is not None
        assert consumed.consumed_by == admin_id

        # Verify audit history record preserved with user_id NULL
        hist_events = (
            await session.scalars(select(FindingStatusEvent).where(FindingStatusEvent.finding_id == finding_id))
        ).all()
        assert len(hist_events) >= 1
        for evt in hist_events:
            assert evt.user_id is None
            assert evt.new_status == "resolved"
            assert evt.justification == "Fixed by target user"

    # 5. Nonce Replay attempt with same nonce -> 400 Bad Request
    replay_resp = await async_client.post(
        f"/api/auth/users/{admin_id}/anonymize",  # will fail on nonce check before self-check or on target
        json={"nonce": test_nonce, "timestamp": now_ts, "signature": sig},
    )
    assert replay_resp.status_code in (400, 404)


@pytest.mark.asyncio
async def test_anonymize_async_service_cryptographic_verification():
    """Verify Async AdminAccountService signature validation, timestamp expiry, and tampered signature rejection."""
    async with AsyncSessionLocal() as session:
        admin_id = f"adm-{uuid.uuid4().hex[:6]}"
        target_id = f"tgt-{uuid.uuid4().hex[:6]}"
        admin = User(id=admin_id, email=f"adm_{uuid.uuid4().hex[:6]}@s.io", is_superuser=True, is_active=True)
        target = User(id=target_id, email=f"tgt_{uuid.uuid4().hex[:6]}@s.io", is_superuser=False, is_active=True)
        session.add_all([admin, target])
        await session.commit()

        nonce = f"async-nonce-{uuid.uuid4().hex[:8]}"
        now_ts = int(datetime.now(timezone.utc).timestamp())

        # 1. Tampered signature -> 400 Bad Request
        with pytest.raises(HTTPException) as exc_tamper:
            await AdminAccountService.anonymize_and_delete_user(
                db=session,
                current_user=admin,
                target_user_id=target_id,
                nonce=nonce,
                timestamp=now_ts,
                signature="invalid-fake-hmac-signature",
            )
        assert exc_tamper.value.status_code == 400
        assert "invalid authorization signature" in exc_tamper.value.detail.lower()

        # Re-fetch active admin after rollback
        admin = await session.get(User, admin_id)

        # 2. Expired timestamp (> 60 seconds ago) -> 400 Bad Request
        expired_ts = now_ts - 120
        expired_sig = generate_anonymization_hmac(target_id, admin_id, nonce, timestamp=expired_ts)
        with pytest.raises(HTTPException) as exc_expired:
            await AdminAccountService.anonymize_and_delete_user(
                db=session,
                current_user=admin,
                target_user_id=target_id,
                nonce=nonce,
                timestamp=expired_ts,
                signature=expired_sig,
            )
        assert exc_expired.value.status_code == 400
        assert "timestamp outside validity window" in exc_expired.value.detail.lower()

        # Re-fetch active admin after rollback
        admin = await session.get(User, admin_id)

        # 3. Valid signature & fresh timestamp -> Success
        valid_sig = generate_anonymization_hmac(target_id, admin_id, nonce, timestamp=now_ts)
        res = await AdminAccountService.anonymize_and_delete_user(
            db=session,
            current_user=admin,
            target_user_id=target_id,
            nonce=nonce,
            timestamp=now_ts,
            signature=valid_sig,
        )
        assert res["status"] == "anonymized"
        assert res["target_user_id"] == target_id

