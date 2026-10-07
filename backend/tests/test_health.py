import pytest
from httpx import AsyncClient
from app.database.session import ping_database


@pytest.mark.asyncio
async def test_ping_database():
    """Verify that the database connectivity probe succeeds."""
    connected = await ping_database()
    assert connected is True


@pytest.mark.asyncio
async def test_system_health_endpoint(async_client: AsyncClient):
    """Verify that the canonical GET /api/system/health endpoint returns 200 and healthy status."""
    response = await async_client.get("/api/system/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["app_name"] == "Sentriq"
    assert "version" in data
    assert "environment" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_root_index_endpoint(async_client: AsyncClient):
    """Verify that the root endpoint returns basic platform metadata."""
    response = await async_client.get("/")
    assert response.status_code == 200

    data = response.json()
    assert data["name"] == "Sentriq"
    assert data["status"] == "online"
