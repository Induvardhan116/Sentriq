from functools import lru_cache
from pathlib import Path
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Locate root .env relative to this file (backend/app/config.py -> root is ../..)
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
ENV_FILE = ROOT_DIR / ".env"


class Settings(BaseSettings):
    """Core application settings loaded from environment or .env file."""

    APP_NAME: str = "Sentriq"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Server settings
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # CORS configuration
    # Includes the production Vercel frontend origin so requests are allowed
    # even when CORS_ORIGINS is not explicitly overridden in Render's env vars.
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://sentriq-rouge.vercel.app",
    ]

    # Database configuration (defaults to async SQLite)
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentriq.db"

    # Scanner safety & limits
    ALLOW_INTERNAL_TARGETS: bool = False
    SCANNER_TIMEOUT_SECONDS: float = 10.0
    SCANNER_MAX_RESPONSE_SIZE: int = 2097152  # 2MB
    SCANNER_USER_AGENT: str = "Sentriq-Security-Scanner/0.2.0 (+https://github.com/Induvardhan116/Sentriq; security-assessment)"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_database_url(cls, v: str) -> str:
        # Transparently convert standard postgresql:// to async postgresql+asyncpg://
        if v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        if v.startswith("postgres://"):
            return v.replace("postgres://", "postgresql+asyncpg://", 1)
        return v

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE) if ENV_FILE.exists() else None,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()
