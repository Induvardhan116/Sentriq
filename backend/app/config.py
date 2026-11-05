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

    # Email Delivery (Resend HTTPS API)
    RESEND_API_KEY: Optional[str] = None
    EMAIL_FROM: str = "Sentriq Security <onboarding@resend.dev>"



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
    # the system strictly fails closed to AUTH_ENABLED=False if unverified, if localhost/unencrypted HTTP origins remain,
    # or if an unsupported/arbitrary origin is configured.
    PRODUCTION_AUTH_VERIFIED: bool = False

    @model_validator(mode="after")
    def resolve_auth_enabled(self) -> "Settings":
        """Resolve AUTH_ENABLED based on explicit setting, architecture verification, and environment.

        Policy (Production Gate):
        - In production (ENVIRONMENT == 'production'), authentication MUST be disabled by default (AUTH_ENABLED=False).
        - An explicit AUTH_ENABLED=true in production requires:
          1. AUTH_ENABLED=true
          2. PRODUCTION_AUTH_VERIFIED=true
          3. Valid same-origin reverse proxy gateway (the sanctioned https://sentriq-rouge.vercel.app)
             or a verified custom apex domain (e.g., https://app.sentriq.io).
          4. No localhost, 127.0.0.1, non-HTTPS, or direct onrender.com frontend origins.
          5. Arbitrary, unapproved *.vercel.app origins remain strictly rejected.
          If any condition is not met, the system fails closed to AUTH_ENABLED=False.
        - In non-production environments (development, test), authentication defaults to enabled (AUTH_ENABLED=True)
          for developer and testing usability, unless explicitly set to false.
        """
        is_prod = str(self.ENVIRONMENT).strip().lower() == "production"
        if is_prod:
            origins = self.CORS_ORIGINS if isinstance(self.CORS_ORIGINS, list) else [str(self.CORS_ORIGINS)]
            frontend_str = str(self.FRONTEND_URL).strip().lower()

            SANCTIONED_VERCEL_GATEWAY = "https://sentriq-rouge.vercel.app"

            def is_insecure_or_unsupported(origin: str) -> bool:
                s = origin.strip().lower()
                # 1. Reject local/private dev addresses in production
                if "localhost" in s or "127.0.0.1" in s or "0.0.0.0" in s:
                    return True
                # 2. Reject Render backend hostname as frontend (Render is API only)
                if "onrender.com" in s:
                    return True
                # 3. Require HTTPS in production
                if not s.startswith("https://"):
                    return True
                # 4. Reject arbitrary *.vercel.app domains (only the sanctioned proxy gateway is allowed)
                if "vercel.app" in s and s != SANCTIONED_VERCEL_GATEWAY:
                    return True
                return False

            has_insecure = any(is_insecure_or_unsupported(orig) for orig in origins) or is_insecure_or_unsupported(frontend_str)

            if has_insecure or not self.AUTH_ENABLED or not self.PRODUCTION_AUTH_VERIFIED:
                self.AUTH_ENABLED = False
            else:
                self.AUTH_ENABLED = True
                # Production Session Cookie Security Enforcement:
                # When production authentication is successfully enabled, strictly force
                # SESSION_COOKIE_SECURE=True. An environment variable explicitly set to
                # SESSION_COOKIE_SECURE=false must NOT override this requirement.
                self.SESSION_COOKIE_SECURE = True
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
