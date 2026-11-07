import pytest
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient

from app.config import get_settings
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.user import User, UserSession
from app.database.session import AsyncSessionLocal
from app.security.hasher import hash_password
from app.security.session import generate_session_token, hash_session_token
from app.security.csrf import generate_session_csrf_token

settings = get_settings()


async def create_test_tenant(email: str, is_superuser: bool = False):
    """Helper to create an authenticated tenant user and session."""
    async with AsyncSessionLocal() as session:
        user = User(
            id=str(uuid.uuid4()),
            email=email.strip().lower(),
            hashed_password=hash_password("AnalyticsPass123!"),
            full_name=f"User {email}",
            is_active=True,
            is_verified=True,
            is_superuser=is_superuser,
        )
        session.add(user)
        await session.flush()

        raw_session_token = generate_session_token()
        token_hash = hash_session_token(raw_session_token)
        csrf_token = generate_session_csrf_token(token_hash, settings.SECRET_KEY)

        user_session = UserSession(
            user_id=user.id,
            token_hash=token_hash,
            ip_address="127.0.0.1",
            user_agent="Sentriq-Analytics-Test",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            revoked_at=None,
        )
        session.add(user_session)
        await session.commit()

        return {
            "id": user.id,
            "email": email,
            "token": raw_session_token,
            "csrf": csrf_token,
            "headers": {"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token},
            "cookies": {settings.SESSION_COOKIE_NAME: raw_session_token},
        }


@pytest.mark.asyncio
async def test_analytics_risk_summary_empty(async_client: AsyncClient):
    """When no projects exist for tenant, risk summary returns pristine 100/100 baseline."""
    tenant = await create_test_tenant("analyst_empty@sentriq.io")
    res = await async_client.get("/api/analytics/risk-summary", cookies=tenant["cookies"])
    assert res.status_code == 200
    data = res.json()
    assert data["overall_posture_score"] == 100
    assert data["grade"] == "Excellent"
    assert data["total_projects"] == 0
    assert data["total_scans"] == 0
    assert data["total_findings"] == 0
    assert data["active_findings"] == 0
    assert data["remediation_metrics"]["remediation_rate_percent"] == 100.0


@pytest.mark.asyncio
async def test_analytics_risk_summary_with_findings(async_client: AsyncClient):
    """When projects have active findings, risk summary computes score, deductions, caps, and domains."""
    tenant = await create_test_tenant("analyst_active@sentriq.io")
    now = datetime.now(timezone.utc)
    proj_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    async with AsyncSessionLocal() as session:
        proj = Project(
            id=proj_id,
            name="Production E-Commerce",
            target_url="https://shop.example.com",
            authorization_confirmed=True,
            owner_id=tenant["id"],
            created_at=now,
            updated_at=now,
        )
        scan = Scan(
            id=scan_id,
            project_id=proj_id,
            target_url="https://shop.example.com",
            status="completed",
            overall_score=45,
            started_at=now,
            completed_at=now,
            created_at=now,
            updated_at=now,
        )
        f1 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            source="web",
            category="headers",
            title="Missing HSTS Header",
            description="Strict-Transport-Security header missing",
            severity="high",
            confidence=1.0,
            risk_score=75,
            status="open",
            version=1,
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        f2 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            source="web",
            category="cookies",
            title="Missing HttpOnly",
            description="Cookie missing HttpOnly",
            severity="medium",
            confidence=0.9,
            risk_score=50,
            status="resolved",
            version=2,
            created_at=now - timedelta(days=5),
            updated_at=now - timedelta(days=1),
        )
        session.add_all([proj, scan, f1, f2])
        await session.commit()

    res = await async_client.get("/api/analytics/risk-summary", cookies=tenant["cookies"])
    assert res.status_code == 200
    data = res.json()
    assert data["total_projects"] == 1
    assert data["total_scans"] == 1
    assert data["total_findings"] == 2
    assert data["active_findings"] == 1
    assert data["severity_distribution"]["high"] == 1
    assert data["status_distribution"]["open"] == 1
    assert data["status_distribution"]["resolved"] == 1

    # Active high finding triggers High Ceiling Cap (max 74)
    assert data["overall_posture_score"] <= 74
    assert len(data["active_caps_applied"]) > 0

    # Remediation metrics
    assert data["remediation_metrics"]["remediation_rate_percent"] == 50.0
    assert data["remediation_metrics"]["mean_time_to_remediate_days"] is not None


@pytest.mark.asyncio
async def test_analytics_posture_trends(async_client: AsyncClient):
    """Posture trends should return chronological data points and trend direction."""
    tenant = await create_test_tenant("analyst_trends@sentriq.io")
    now = datetime.now(timezone.utc)
    proj_id = str(uuid.uuid4())

    async with AsyncSessionLocal() as session:
        proj = Project(
            id=proj_id,
            name="API Gateway",
            target_url="https://api.example.com",
            authorization_confirmed=True,
            owner_id=tenant["id"],
            created_at=now - timedelta(days=10),
            updated_at=now,
        )
        scan1 = Scan(
            id=str(uuid.uuid4()),
            project_id=proj_id,
            target_url="https://api.example.com",
            status="completed",
            overall_score=60,
            created_at=now - timedelta(days=5),
            updated_at=now - timedelta(days=5),
        )
        scan2 = Scan(
            id=str(uuid.uuid4()),
            project_id=proj_id,
            target_url="https://api.example.com",
            status="completed",
            overall_score=85,
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        session.add_all([proj, scan1, scan2])
        await session.commit()

    res = await async_client.get(
        f"/api/analytics/posture-trends?project_id={proj_id}&days=30",
        cookies=tenant["cookies"],
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total_points"] == 2
    assert data["data_points"][0]["posture_score"] == 60
    assert data["data_points"][1]["posture_score"] == 85
    assert data["trend_direction"] == "improving"
    assert data["score_delta"] == 25


@pytest.mark.asyncio
async def test_analytics_project_rankings(async_client: AsyncClient):
    """Project rankings should sort projects by highest risk first."""
    tenant = await create_test_tenant("analyst_rankings@sentriq.io")
    now = datetime.now(timezone.utc)
    p1_id = str(uuid.uuid4())
    p2_id = str(uuid.uuid4())

    async with AsyncSessionLocal() as session:
        # P1: Healthy project (score 95)
        p1 = Project(
            id=p1_id,
            name="Low Risk App",
            target_url="https://safe.example.com",
            authorization_confirmed=True,
            owner_id=tenant["id"],
        )
        s1 = Scan(
            id=str(uuid.uuid4()),
            project_id=p1_id,
            target_url="https://safe.example.com",
            status="completed",
            overall_score=95,
            created_at=now,
        )

        # P2: High risk project (score 40)
        p2 = Project(
            id=p2_id,
            name="Vulnerable App",
            target_url="https://vuln.example.com",
            authorization_confirmed=True,
            owner_id=tenant["id"],
        )
        s2 = Scan(
            id=str(uuid.uuid4()),
            project_id=p2_id,
            target_url="https://vuln.example.com",
            status="completed",
            overall_score=40,
            created_at=now,
        )

        session.add_all([p1, s1, p2, s2])
        await session.commit()

    res = await async_client.get("/api/analytics/project-rankings", cookies=tenant["cookies"])
    assert res.status_code == 200
    data = res.json()
    assert data["total_projects"] == 2
    # P2 should be ranked #1 because its risk index is higher (100 - 40 = 60 vs 100 - 95 = 5)
    assert data["rankings"][0]["project_id"] == p2_id
    assert data["rankings"][0]["rank"] == 1
    assert data["rankings"][0]["risk_index"] == 60
    assert data["rankings"][1]["project_id"] == p1_id
    assert data["rankings"][1]["rank"] == 2


@pytest.mark.asyncio
async def test_analytics_tenant_isolation(async_client: AsyncClient):
    """Tenant A must never see Tenant B's analytics data."""
    tenant_a = await create_test_tenant("tenant_a@sentriq.io")
    tenant_b = await create_test_tenant("tenant_b@sentriq.io")
    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as session:
        proj_b = Project(
            id=str(uuid.uuid4()),
            name="Tenant B Secret App",
            target_url="https://b.example.com",
            authorization_confirmed=True,
            owner_id=tenant_b["id"],
        )
        scan_b = Scan(
            id=str(uuid.uuid4()),
            project_id=proj_b.id,
            target_url="https://b.example.com",
            status="completed",
            overall_score=20,
            created_at=now,
        )
        session.add_all([proj_b, scan_b])
        await session.commit()

    # Query from Tenant A
    res_a = await async_client.get("/api/analytics/risk-summary", cookies=tenant_a["cookies"])
    assert res_a.status_code == 200
    data_a = res_a.json()
    # Tenant A has 0 projects, should not see Tenant B's data
    assert data_a["total_projects"] == 0
    assert data_a["overall_posture_score"] == 100
