from datetime import datetime, timezone
from fastapi import APIRouter
from app.config import get_settings
from app.database.session import ping_database
from app.schemas.health import SystemHealthResponse

router = APIRouter(prefix="/system", tags=["System"])
settings = get_settings()


@router.get("/health", response_model=SystemHealthResponse)
async def get_system_health() -> SystemHealthResponse:
    """Canonical system health check endpoint probing app state and database connectivity."""
    db_connected = await ping_database()
    return SystemHealthResponse(
        status="healthy" if db_connected else "degraded",
        database="connected" if db_connected else "disconnected",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
    )
