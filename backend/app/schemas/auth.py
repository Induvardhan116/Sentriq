import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict


class UserRegisterRequest(BaseModel):
    """Payload for user self-registration."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., description="User's unique primary email address")
    password: str = Field(
        ...,
        min_length=10,
        max_length=128,
        description="Password (minimum 10 characters with mixed character classes)",
    )
    full_name: Optional[str] = Field(
        None, min_length=1, max_length=255, description="User's optional display name"
    )

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("Password must be at least 10 characters long.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r"[0-9\W_]", v):
            raise ValueError("Password must contain at least one number or special character.")
        return v

    @field_validator("full_name")
    @classmethod
    def sanitize_full_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            clean = v.strip()
            return clean if clean else None
        return None


class UserLoginRequest(BaseModel):
    """Payload for password authentication."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., description="Account email address")
    password: str = Field(..., min_length=1, max_length=128, description="Account password")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class UserProfileUpdateRequest(BaseModel):
    """Payload for updating user profile metadata."""

    model_config = ConfigDict(extra="forbid")

    full_name: Optional[str] = Field(
        None, min_length=1, max_length=255, description="Updated display name"
    )
    avatar_url: Optional[str] = Field(
        None, min_length=4, max_length=1024, description="Updated avatar URL"
    )

    @field_validator("full_name")
    @classmethod
    def sanitize_full_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            clean = v.strip()
            return clean if clean else None
        return None

    @field_validator("avatar_url")
    @classmethod
    def validate_avatar_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            clean = v.strip()
            if not clean:
                return None
            if not (clean.startswith("https://") or clean.startswith("http://")):
                raise ValueError("Avatar URL must begin with http:// or https://")
            return clean
        return None


class UserResponse(BaseModel):
    """User profile response. NEVER exposes session tokens or password hashes."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    created_at: datetime
    csrf_token: Optional[str] = Field(
        None, description="Session-bound anti-CSRF token held in React memory"
    )


class CSRFTokenResponse(BaseModel):
    """CSRF token payload for pre-auth or refreshing tokens."""

    csrf_token: str


class AuthMessageResponse(BaseModel):
    """Standard message response for auth operations."""

    message: str
    detail: Optional[str] = None


class UserAnonymizeRequest(BaseModel):
    """Payload for authorized administrative user anonymization."""

    model_config = ConfigDict(extra="forbid")

    nonce: Optional[str] = Field(None, max_length=64, description="Cryptographic nonce for replay prevention")
    timestamp: Optional[int] = Field(None, description="Unix timestamp of authorization generation")
    signature: Optional[str] = Field(None, description="HMAC-SHA256 authorization signature")


class UserAnonymizeResponse(BaseModel):
    """Response payload for completed user anonymization."""

    target_user_id: str
    events_anonymized: int
    nonce: str
    status: str


class PasswordResetRequest(BaseModel):
    """Payload for requesting a password reset email."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., description="Account email address")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class PasswordResetConfirmRequest(BaseModel):
    """Payload for completing password reset with token."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(..., min_length=16, max_length=128, description="Password reset token")
    new_password: str = Field(
        ...,
        min_length=10,
        max_length=128,
        description="New password (minimum 10 characters with mixed character classes)",
    )

    @field_validator("token")
    @classmethod
    def clean_token(cls, v: str) -> str:
        return v.strip()

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("Password must be at least 10 characters long.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r"[0-9\W_]", v):
            raise ValueError("Password must contain at least one number or special character.")
        return v


class EmailVerificationRequest(BaseModel):
    """Payload for requesting email verification."""

    model_config = ConfigDict(extra="forbid")

    email: Optional[EmailStr] = Field(None, description="Optional email address if unauthenticated")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: Optional[str]) -> Optional[str]:
        return v.strip().lower() if v else None


class EmailVerificationConfirmRequest(BaseModel):
    """Payload for confirming email verification with token."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(..., min_length=16, max_length=128, description="Email verification token")

    @field_validator("token")
    @classmethod
    def clean_token(cls, v: str) -> str:
        return v.strip()


