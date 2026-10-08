import pytest
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.session import engine
from app.models.base import Base


@pytest.fixture(autouse=True)
async def init_test_db():
    """Ensure database tables exist for test execution."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Provides an asynchronous test client bound to the FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
