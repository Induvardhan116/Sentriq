import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.schemas.integration import (
    WebhookCreate,
    WebhookResponse,
    WebhookTestResult,
    ScanScheduleCreate,
    ScanScheduleResponse,
    SiemLogItem,
)
from app.services.integration_service import IntegrationService
from app.security.deps import (
    get_authenticated_user_or_dev_mode,
    require_verified_user,
    require_csrf_if_auth_enabled,
)

logger = logging.getLogger("sentriq.api.integrations")
router = APIRouter(prefix="/integrations", tags=["Integrations & Automation"])


@router.post("/webhooks", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    payload: WebhookCreate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Register an outbound webhook with SSRF validation and HMAC signing."""
    return await IntegrationService.create_webhook(db=db, payload=payload, user=user)


@router.get("/webhooks", response_model=List[WebhookResponse])
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List registered outbound webhooks for the tenant."""
    return await IntegrationService.list_webhooks(db=db, user=user)


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Delete an outbound webhook endpoint."""
    await IntegrationService.delete_webhook(db=db, webhook_id=webhook_id, user=user)


@router.post("/webhooks/{webhook_id}/test", response_model=WebhookTestResult)
async def test_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Dispatch a test alert payload to verify webhook connectivity and signature."""
    return await IntegrationService.test_webhook(db=db, webhook_id=webhook_id, user=user)


@router.post("/schedules", response_model=ScanScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScanScheduleCreate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Create an automated recurring scan schedule."""
    return await IntegrationService.create_schedule(db=db, payload=payload, user=user)


@router.get("/schedules", response_model=List[ScanScheduleResponse])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List active scan schedules for the tenant."""
    return await IntegrationService.list_schedules(db=db, user=user)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Delete a recurring scan schedule."""
    await IntegrationService.delete_schedule(db=db, schedule_id=schedule_id, user=user)


@router.post("/schedules/{schedule_id}/run")
async def run_schedule_now(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Trigger execution of a scheduled recurring scan immediately."""
    return await IntegrationService.execute_schedule(db=db, schedule_id=schedule_id, user=user)


@router.get("/siem/events", response_model=List[SiemLogItem])
async def get_siem_events(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve security events formatted in Common Event Format (CEF) and JSON for SIEM ingestion."""
    return await IntegrationService.generate_siem_events(db=db, user=user)
