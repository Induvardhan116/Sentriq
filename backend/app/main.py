import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.database.session import engine, ping_database
from app.models.base import Base
import asyncio
from app.database.migrations import run_migrations
from app.security.rate_limiter import periodic_login_attempts_cleanup
from app.api.router import api_router

logger = logging.getLogger("sentriq")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager initializing database tables and closing connections."""
    logger.info("Initializing Sentriq application [%s]", settings.ENVIRONMENT)

    # Initialize tables and run migrations (safe idempotent creation)
    async with engine.begin() as conn:
        await conn.run_sync(run_migrations)

    # Check connection
    db_ok = await ping_database()
    if db_ok:
        logger.info("Database connection established successfully.")
    else:
        logger.warning("Database connection failed or degraded.")

    # Start scheduled background maintenance for rate-limiting audit log retention (1h interval)
    cleanup_task = asyncio.create_task(periodic_login_attempts_cleanup(interval_seconds=3600))

    yield

    # Clean shutdown: cancel background maintenance worker
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

    logger.info("Disposing database connections.")
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Application Security Intelligence Platform - Core API",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
)

# Cross-Origin Resource Sharing (CORS) Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount primary API router under /api
app.include_router(api_router, prefix="/api")


@app.get("/", tags=["Root"])
async def root():
    """Root platform index."""
    return {
        "name": settings.APP_NAME,
        "description": "Application Security Intelligence Platform",
        "version": settings.APP_VERSION,
        "status": "online",
        "docs": "/api/docs" if settings.DEBUG else "disabled",
    }
