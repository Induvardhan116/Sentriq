from functools import lru_cache
from pathlib import Path
from typing import List, Union, Optional
from pydantic import field_validator, model_validator
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

    # Authentication Safety & Architecture Policy (Phase 3.3)
    # In production, authentication is DISABLED by default until same-origin/same-site routing is established.
    # Enabling in production requires explicit AUTH_ENABLED=true in the deployment environment.
    AUTH_ENABLED: Optional[bool] = None
    SECRET_KEY: str = "sentriq-dev-secret-key-32-byte-hex-entropy-change-in-prod"
    SESSION_COOKIE_NAME: str = "sentriq_session"
    SESSION_EXPIRE_DAYS: int = 7
    CSRF_COOKIE_NAME: str = "sentriq_csrf"
    SESSION_COOKIE_SECURE: bool = False
    SESSION_COOKIE_SAMESITE: str = "lax"  # Strictly "lax" or "strict"; never weakened to "none"
    FRONTEND_URL: str = "http://localhost:5173"



    # Rate limiting & Account Lockout
    AUTH_MAX_FAILED_ATTEMPTS: int = 5
    AUTH_LOCKOUT_MINUTES: int = 15

    # GitHub OAuth 2.0 Credentials
    GITHUB_CLIENT_ID: Union[str, None] = None
    GITHUB_CLIENT_SECRET: Union[str, None] = None
    GITHUB_REDIRECT_URI: Union[str, None] = None

    # Reverse Proxy & Trusted Proxy Configuration
    # NOTE: Render deploys dynamic edge routing where internal proxy IPs are not static or narrowly scoped.
    # To prevent IP spoofing, do NOT trust broad CIDRs (e.g., 10.0.0.0/8 or 172.16.0.0/12) without verified justification.
    # Unless a verified, narrowly scoped proxy peer (e.g. 127.0.0.1) is present, TRUST_PROXY_HEADERS must remain False.
    TRUST_PROXY_HEADERS: bool = False
    TRUSTED_PROXIES: Union[List[str], str] = ["127.0.0.1", "::1"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("TRUSTED_PROXIES", mode="before")
    @classmethod
    def assemble_trusted_proxies(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [proxy.strip() for proxy in v.split(",") if proxy.strip()]
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

    # Production Architecture Verification Flag
    # In production, setting AUTH_ENABLED=true requires administrative acknowledgement that
    # live browser-level verification of same-origin or same-site domain architecture was completed (PRODUCTION_AUTH_VERIFIED=true).
    # NOTE: PRODUCTION_AUTH_VERIFIED is NOT proof of a working architecture. To prevent accidental misconfiguration,
    # the system strictly fails closed to AUTH_ENABLED=False if unverified OR if cross-site PSL domains
    # (*.vercel.app / *.onrender.com) remain configured in CORS_ORIGINS or FRONTEND_URL.
    PRODUCTION_AUTH_VERIFIED: bool = False

    @model_validator(mode="after")
    def resolve_auth_enabled(self) -> "Settings":
        """Resolve AUTH_ENABLED based on explicit setting, architecture verification, and environment.

        Policy (Phase 3.3):
        - In production (ENVIRONMENT == 'production'), authentication MUST be disabled by default (AUTH_ENABLED=False).
        - An explicit AUTH_ENABLED=true in production must not silently bypass deployment requirements.
          Enabling in production requires:
          1. AUTH_ENABLED=true
          2. PRODUCTION_AUTH_VERIFIED=true
          3. Replacement of default cross-site PSL domains (*.vercel.app and *.onrender.com) with
             a unified apex custom domain or same-origin reverse proxy gateway.
          If any condition is not met, the system fails closed to AUTH_ENABLED=False.
        - In non-production environments (development, test), authentication defaults to enabled (AUTH_ENABLED=True)
          for developer and testing usability, unless explicitly set to false.
        """
        is_prod = str(self.ENVIRONMENT).strip().lower() == "production"
        if is_prod:
            origins = self.CORS_ORIGINS if isinstance(self.CORS_ORIGINS, list) else [str(self.CORS_ORIGINS)]
            is_cross_site_or_unsupported = any(
                "vercel.app" in str(origin).lower()
                or "onrender.com" in str(origin).lower()
                or "localhost" in str(origin).lower()
                or "127.0.0.1" in str(origin).lower()
                for origin in origins
            ) or (
                "vercel.app" in str(self.FRONTEND_URL).lower()
                or "onrender.com" in str(self.FRONTEND_URL).lower()
                or "localhost" in str(self.FRONTEND_URL).lower()
                or "127.0.0.1" in str(self.FRONTEND_URL).lower()
            )

            if is_cross_site_or_unsupported or not self.AUTH_ENABLED or not self.PRODUCTION_AUTH_VERIFIED:
                self.AUTH_ENABLED = False
            else:
                self.AUTH_ENABLED = True
        else:
            if self.AUTH_ENABLED is None:
                self.AUTH_ENABLED = True
        return self


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
