import pytest
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient

from app.config import get_settings
from app.models.user import User, UserSession
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
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
            hashed_password=hash_password("ReportPass123!"),
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
            user_agent="Sentriq-Report-Test",
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
async def test_executive_report_html_and_summary(async_client: AsyncClient):
    """Should generate executive HTML report and JSON summary."""
    tenant = await create_test_tenant("executive_ciso@sentriq.io")

    # Seed a project
    async with AsyncSessionLocal() as session:
        proj = Project(
            id=str(uuid.uuid4()),
            owner_id=tenant["id"],
            name="Executive Portal",
            target_url="https://portal.sentriq.io",
            authorization_confirmed=True,
        )
        session.add(proj)
        await session.flush()

        scan = Scan(
            id=str(uuid.uuid4()),
            project_id=proj.id,
            target_url=proj.target_url,
            overall_score=85,
            status="completed",
        )
        session.add(scan)
        await session.flush()

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            title="Missing Content-Security-Policy",
            description="No CSP header was detected on HTTP response.",
            severity="medium",
            category="Headers",
            risk_score=40,
            status="open",
            remediation="Add strict CSP header",
        )
        session.add(finding)
        await session.commit()

    # 1. Summary
    sum_res = await async_client.get(
        "/api/reports/summary",
        cookies=tenant["cookies"],
    )
    assert sum_res.status_code == 200
    summary = sum_res.json()
    assert summary["assets"]["projects_count"] >= 1
    assert summary["findings_summary"]["open"] >= 1
    assert "posture" in summary

    # 2. Executive HTML
    exec_res = await async_client.get(
        "/api/reports/executive",
        cookies=tenant["cookies"],
    )
    assert exec_res.status_code == 200
    assert "text/html" in exec_res.headers["content-type"]
    assert "SENTRIQ" in exec_res.text
    assert "Executive Posture Scorecard" in exec_res.text
    assert "Missing Content-Security-Policy" in exec_res.text

    # 3. Downloadable PDF Export
    pdf_res = await async_client.get(
        "/api/reports/export/pdf?report_type=executive",
        cookies=tenant["cookies"],
    )
    assert pdf_res.status_code == 200
    assert "application/pdf" in pdf_res.headers["content-type"]
    assert 'attachment; filename="sentriq_executive_report.pdf"' in pdf_res.headers["content-disposition"]
    assert pdf_res.content.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_res.content


@pytest.mark.asyncio
async def test_export_csv_and_json_bundle(async_client: AsyncClient):
    """Should download UTF-8 CSV with BOM and JSON posture bundle."""
    tenant = await create_test_tenant("compliance_officer@sentriq.io")

    # 1. CSV Export
    csv_res = await async_client.get(
        "/api/reports/export/csv",
        cookies=tenant["cookies"],
    )
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert "attachment; filename=sentriq_findings_export.csv" in csv_res.headers["content-disposition"]
    # Check UTF-8 BOM
    assert csv_res.text.startswith("\ufeff")
    assert "Finding ID,Source Type,Asset Name" in csv_res.text

    # 2. JSON Export
    json_res = await async_client.get(
        "/api/reports/export/json",
        cookies=tenant["cookies"],
    )
    assert json_res.status_code == 200
    assert "application/json" in json_res.headers["content-type"]
    assert "attachment; filename=sentriq_posture_bundle.json" in json_res.headers["content-disposition"]
    bundle = json_res.json()
    assert "compliance_mappings" in bundle
    assert "owasp_top_10_web" in bundle["compliance_mappings"]


@pytest.mark.asyncio
async def test_report_tenant_isolation(async_client: AsyncClient):
    """Tenant A's report must never contain Tenant B's sensitive project or finding data."""
    tenant_a = await create_test_tenant("report_tenant_a@sentriq.io")
    tenant_b = await create_test_tenant("report_tenant_b@sentriq.io")

    async with AsyncSessionLocal() as session:
        proj_b = Project(
            id=str(uuid.uuid4()),
            owner_id=tenant_b["id"],
            name="Confidential Project B",
            target_url="https://secret-b.internal",
            authorization_confirmed=True,
        )
        session.add(proj_b)
        await session.flush()

        scan_b = Scan(
            id=str(uuid.uuid4()),
            project_id=proj_b.id,
            target_url=proj_b.target_url,
            overall_score=50,
            status="completed",
        )
        session.add(scan_b)
        await session.flush()

        finding_b = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_b.id,
            title="Tenant B Secret Exposure",
            description="Private secret token discovered in source.",
            severity="critical",
            category="Exposure",
            risk_score=95,
            status="open",
        )
        session.add(finding_b)
        await session.commit()

    # Tenant A requests CSV export
    csv_a = await async_client.get(
        "/api/reports/export/csv",
        cookies=tenant_a["cookies"],
    )
    assert csv_a.status_code == 200
    assert "Confidential Project B" not in csv_a.text
    assert "Tenant B Secret Exposure" not in csv_a.text
