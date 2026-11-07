from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class UserProfileUpdate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=128, description="User full display name")


class UserProfileResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    is_active: bool
    is_verified: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=8, description="Existing user password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New strong password")


class UserSessionItem(BaseModel):
    id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime
    expires_at: datetime
    is_current: bool = False

    model_config = {"from_attributes": True}


class UserSettingsResponse(BaseModel):
    id: str
    user_id: str
    scanner_timeout_seconds: int = 30
    scanner_max_redirects: int = 5
    scanner_verify_ssl: bool = True
    scanner_strict_headers: bool = True
    notify_email_scan_completed: bool = True
    notify_email_critical_finding: bool = True
    notify_webhook_enabled: bool = True
    default_scan_cadence: str = "weekly"
    theme: str = "dark"
    session_timeout_minutes: int = 10080
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserSettingsUpdate(BaseModel):
    scanner_timeout_seconds: Optional[int] = Field(None, ge=5, le=120)
    scanner_max_redirects: Optional[int] = Field(None, ge=0, le=20)
    scanner_verify_ssl: Optional[bool] = None
    scanner_strict_headers: Optional[bool] = None
    notify_email_scan_completed: Optional[bool] = None
    notify_email_critical_finding: Optional[bool] = None
    notify_webhook_enabled: Optional[bool] = None
    default_scan_cadence: Optional[str] = Field(None, pattern="^(daily|weekly|monthly)$")
    theme: Optional[str] = Field(None, pattern="^(dark|light|system)$")
    session_timeout_minutes: Optional[int] = Field(None, ge=15, le=43200)
