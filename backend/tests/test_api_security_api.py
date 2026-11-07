import pytest
import uuid
import json
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient

from app.config import get_settings
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
            hashed_password=hash_password("ApiSecPass123!"),
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
            user_agent="Sentriq-ApiSec-Test",
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


SAMPLE_OPENAPI_JSON = json.dumps({
    "openapi": "3.0.0",
    "info": {
        "title": "Payment Gateway API",
        "version": "1.0.0",
        "description": "Production payment microservice"
    },
    "servers": [
        {"url": "http://api.insecure-payments.internal/v1"}
    ],
    "paths": {
        "/users": {
            "get": {
                "summary": "List all users without pagination",
                "responses": {
                    "200": {
                        "description": "List of users",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "email": {"type": "string"},
                                            "password_hash": {"type": "string"},
                                            "api_token": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/charge": {
            "post": {
                "summary": "Execute credit card charge without authentication",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "amount": {"type": "number"},
                                    "currency": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Charge successful"}
                }
            }
        },
        "/debug/dump-env": {
            "get": {
                "summary": "Internal environment dump route",
                "responses": {
                    "200": {"description": "Environment dumped"}
                }
            }
        }
    }
})


@pytest.mark.asyncio
async def test_import_openapi_spec_and_scan(async_client: AsyncClient):
    """Should parse OpenAPI 3.0 schema, extract endpoints, and identify API vulnerabilities."""
    tenant = await create_test_tenant("apisec_owner@sentriq.io")

    payload = {
        "title": "Payment Gateway",
        "raw_spec": SAMPLE_OPENAPI_JSON,
    }

    response = await async_client.post(
        "/api/api-security/specs",
        json=payload,
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert response.status_code == 201
    spec_data = response.json()
    assert spec_data["title"] == "Payment Gateway"
    assert spec_data["endpoint_count"] == 3
    spec_id = spec_data["id"]

    # Verify listing specs
    list_res = await async_client.get(
        "/api/api-security/specs",
        cookies=tenant["cookies"],
    )
    assert list_res.status_code == 200
    specs = list_res.json()
    assert any(s["id"] == spec_id for s in specs)

    # Verify fetching endpoints
    endpoints_res = await async_client.get(
        f"/api/api-security/specs/{spec_id}/endpoints",
        cookies=tenant["cookies"],
    )
    assert endpoints_res.status_code == 200
    endpoints = endpoints_res.json()
    assert len(endpoints) == 3
    paths = [ep["path"] for ep in endpoints]
    assert "/users" in paths
    assert "/charge" in paths
    assert "/debug/dump-env" in paths

    # Verify findings
    findings_res = await async_client.get(
        f"/api/api-security/specs/{spec_id}/findings",
        cookies=tenant["cookies"],
    )
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) > 0


@pytest.mark.asyncio
async def test_api_security_tenant_isolation(async_client: AsyncClient):
    """Tenant B should not have access to Tenant A's imported API specs or findings."""
    tenant_a = await create_test_tenant("tenant_a@sentriq.io")
    tenant_b = await create_test_tenant("tenant_b@sentriq.io")

    # Tenant A imports spec
    res_a = await async_client.post(
        "/api/api-security/specs",
        json={
            "title": "Tenant A Secret API",
            "raw_spec": SAMPLE_OPENAPI_JSON,
        },
        headers=tenant_a["headers"],
        cookies=tenant_a["cookies"],
    )
    assert res_a.status_code == 201
    spec_id = res_a.json()["id"]

    # Tenant B tries to view Tenant A's spec
    res_b = await async_client.get(
        f"/api/api-security/specs/{spec_id}",
        cookies=tenant_b["cookies"],
    )
    assert res_b.status_code == 404

    # Tenant B lists specs - should not include Tenant A's spec
    list_b = await async_client.get(
        "/api/api-security/specs",
        cookies=tenant_b["cookies"],
    )
    assert list_b.status_code == 200
    b_ids = [s["id"] for s in list_b.json()]
    assert spec_id not in b_ids


@pytest.mark.asyncio
async def test_api_security_finding_triage(async_client: AsyncClient):
    """Should update finding status with reason and validation."""
    tenant = await create_test_tenant("triage_auditor@sentriq.io")

    import_res = await async_client.post(
        "/api/api-security/specs",
        json={
            "title": "Triage Target API",
            "raw_spec": SAMPLE_OPENAPI_JSON,
        },
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert import_res.status_code == 201
    spec_id = import_res.json()["id"]

    findings_res = await async_client.get(
        f"/api/api-security/specs/{spec_id}/findings",
        cookies=tenant["cookies"],
    )
    findings = findings_res.json()
    assert len(findings) > 0
    first_finding = findings[0]
    finding_id = first_finding["id"]

    # Update status to accepted_risk
    update_res = await async_client.patch(
        f"/api/api-security/findings/{finding_id}",
        json={
            "status": "accepted_risk",
            "justification": "Approved risk mitigation by Chief Security Officer for internal legacy network."
        },
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert update_res.status_code == 200
    updated_finding = update_res.json()
    assert updated_finding["status"] == "accepted_risk"
    assert "Chief Security Officer" in updated_finding["justification"]
