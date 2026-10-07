import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.database.session import engine, ping_database
from app.models.base import Base
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

    # Initialize tables (safe idempotent creation)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Check connection
    db_ok = await ping_database()
    if db_ok:
        logger.info("Database connection established successfully.")
    else:
        logger.warning("Database connection failed or degraded.")

    yield

    # Clean shutdown
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
