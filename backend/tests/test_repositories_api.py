import pytest
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient

from app.config import get_settings
from app.models.repository import Repository, RepoScan, RepoFinding
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
            hashed_password=hash_password("RepoPass123!"),
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
            user_agent="Sentriq-Repo-Test",
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
async def test_create_repository_success(async_client: AsyncClient):
    """Should successfully register repository with valid public HTTPS clone URL."""
    tenant = await create_test_tenant("repo_owner@sentriq.io")
    payload = {
        "name": "Sentriq Core",
        "full_name": "sentriq-org/sentriq-core",
        "clone_url": "https://github.com/sentriq-org/sentriq-core.git",
        "default_branch": "main",
        "languages": "TypeScript, Python",
        "is_private": False,
        "authorization_confirmed": True,
    }

    res = await async_client.post(
        "/api/repositories",
        json=payload,
        cookies=tenant["cookies"],
        headers=tenant["headers"],
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Sentriq Core"
    assert data["full_name"] == "sentriq-org/sentriq-core"
    assert data["latest_posture_score"] == 100


@pytest.mark.asyncio
async def test_create_repository_ssrf_protection(async_client: AsyncClient):
    """Should reject internal loopback or metadata clone URLs."""
    tenant = await create_test_tenant("repo_ssrf@sentriq.io")
    payload = {
        "name": "Internal Service",
        "full_name": "internal/service",
        "clone_url": "http://127.0.0.1:8080/repo.git",
        "default_branch": "main",
    }

    res = await async_client.post(
        "/api/repositories",
        json=payload,
        cookies=tenant["cookies"],
        headers=tenant["headers"],
    )
    assert res.status_code == 400
    assert "Security violation" in res.json()["detail"]


@pytest.mark.asyncio
async def test_run_repo_scan_with_secrets_sast_and_sca(async_client: AsyncClient):
    """Scan should detect hardcoded secrets (with masking), SAST patterns, and vulnerable dependencies."""
    tenant = await create_test_tenant("repo_scanner@sentriq.io")

    # 1. Register repo
    reg_res = await async_client.post(
        "/api/repositories",
        json={
            "name": "Vulnerable Demo App",
            "full_name": "sentriq-demo/vuln-app",
            "clone_url": "https://github.com/sentriq-demo/vuln-app.git",
        },
        cookies=tenant["cookies"],
        headers=tenant["headers"],
    )
    assert reg_res.status_code == 201
    repo_id = reg_res.json()["id"]

    # 2. Virtual files containing:
    # - Secret: AWS key
    # - SAST: os.system with command injection
    # - SCA: lodash: "4.17.20" in package.json
    virtual_files = {
        "config.py": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
        "utils.py": 'import os\ndef ping(ip):\n    os.system(f"ping {ip}")\n',
        "package.json": '{\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}\n',
    }

    scan_res = await async_client.post(
        f"/api/repositories/{repo_id}/scan",
        json=virtual_files,
        cookies=tenant["cookies"],
        headers=tenant["headers"],
    )
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["status"] == "completed"
    assert scan_data["findings_count"] >= 3
    assert scan_data["secret_count"] >= 1
    assert scan_data["sast_count"] >= 1
    assert scan_data["sca_count"] >= 1
    assert scan_data["posture_score"] < 100

    # 3. Retrieve findings
    find_res = await async_client.get(
        f"/api/repositories/{repo_id}/findings",
        cookies=tenant["cookies"],
    )
    assert find_res.status_code == 200
    findings = find_res.json()
    assert len(findings) >= 3

    # Verify secret is masked (zero raw secret storage)
    secret_f = next(f for f in findings if f["scan_type"] == "secret")
    assert "AKIAIOSFODNN7EXAMPLE" not in secret_f["snippet"]
    assert "AKIA****MPLE" in secret_f["snippet"] or "****" in secret_f["snippet"]


@pytest.mark.asyncio
async def test_update_repo_finding_status(async_client: AsyncClient):
    """Updating finding status to accepted_risk must require non-empty justification."""
    tenant = await create_test_tenant("repo_triage@sentriq.io")

    # Create repo & run scan
    reg_res = await async_client.post(
        "/api/repositories",
        json={"name": "Triage App", "full_name": "org/triage", "clone_url": "https://github.com/org/triage.git"},
        cookies=tenant["cookies"],
        headers=tenant["headers"],
    )
    repo_id = reg_res.json()["id"]

    scan_res = await async_client.post(
        f"/api/repositories/{repo_id}/scan",
        json={"app.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'},
        cookies=tenant["cookies"],
        headers=tenant["headers"],
    )
    find_res = await async_client.get(f"/api/repositories/{repo_id}/findings", cookies=tenant["cookies"])
    finding_id = find_res.json()[0]["id"]

    # Fails without justification
    fail_res = await async_client.patch(
        f"/api/repositories/findings/{finding_id}",
        json={"status": "accepted_risk", "justification": ""},
        cookies=tenant["cookies"],
        headers=tenant["headers"],
    )
    assert fail_res.status_code == 400

    # Succeeds with justification
    succ_res = await async_client.patch(
        f"/api/repositories/findings/{finding_id}",
        json={"status": "accepted_risk", "justification": "Compensating IAM boundary applied"},
        cookies=tenant["cookies"],
        headers=tenant["headers"],
    )
    assert succ_res.status_code == 200
    assert succ_res.json()["status"] == "accepted_risk"


@pytest.mark.asyncio
async def test_repository_tenant_isolation(async_client: AsyncClient):
    """Tenant A must not be able to view or delete Tenant B's repository."""
    tenant_a = await create_test_tenant("user_a@sentriq.io")
    tenant_b = await create_test_tenant("user_b@sentriq.io")

    reg_b = await async_client.post(
        "/api/repositories",
        json={"name": "Tenant B Code", "full_name": "b/code", "clone_url": "https://github.com/b/code.git"},
        cookies=tenant_b["cookies"],
        headers=tenant_b["headers"],
    )
    repo_b_id = reg_b.json()["id"]

    # Tenant A attempts to get Tenant B's repo -> 404
    get_res = await async_client.get(f"/api/repositories/{repo_b_id}", cookies=tenant_a["cookies"])
    assert get_res.status_code == 404

    # Tenant A attempts to delete Tenant B's repo -> 404
    del_res = await async_client.delete(
        f"/api/repositories/{repo_b_id}",
        cookies=tenant_a["cookies"],
        headers=tenant_a["headers"],
    )
    assert del_res.status_code == 404
