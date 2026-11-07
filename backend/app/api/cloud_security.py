import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.schemas.cloud_security import (
    CloudAccountCreate,
    CloudAccountResponse,
    CloudFindingResponse,
    CloudScanTrigger,
    CloudFindingStatusUpdate,
)
from app.services.cloud_security_service import CloudSecurityService
from app.security.deps import (
    get_authenticated_user_or_dev_mode,
    require_verified_user,
    require_csrf_if_auth_enabled,
)

logger = logging.getLogger("sentriq.api.cloud_security")
router = APIRouter(prefix="/cloud-security", tags=["Cloud Security (CSPM)"])


@router.post("/accounts", response_model=CloudAccountResponse, status_code=status.HTTP_201_CREATED)
async def create_account(
    payload: CloudAccountCreate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Register a new cloud environment or PaaS tenant for CSPM posture assessment."""
    return await CloudSecurityService.create_account(db=db, payload=payload, user=user)


@router.get("/accounts", response_model=List[CloudAccountResponse])
async def list_accounts(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List all registered cloud environments for tenant."""
    return await CloudSecurityService.list_accounts(db=db, user=user)


@router.get("/accounts/{account_id}", response_model=CloudAccountResponse)
async def get_account(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Get single cloud account details."""
    acc = await CloudSecurityService.get_account(db=db, account_id=account_id, user=user)
    open_findings = [f for f in acc.findings if f.status == "open"]
    return {
        "id": acc.id,
        "provider": acc.provider,
        "name": acc.name,
        "account_identifier": acc.account_identifier,
        "role_arn_or_ref": acc.role_arn_or_ref,
        "region": acc.region,
        "is_active": acc.is_active,
        "posture_score": acc.posture_score,
        "risk_score": acc.risk_score,
        "findings_count": len(open_findings),
        "last_scanned_at": acc.last_scanned_at,
        "created_at": acc.created_at,
        "updated_at": acc.updated_at,
    }


@router.delete("/accounts/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Delete a cloud environment and cascade delete posture findings."""
    await CloudSecurityService.delete_account(db=db, account_id=account_id, user=user)


@router.post("/accounts/{account_id}/scan", response_model=CloudAccountResponse)
async def scan_account(
    account_id: str,
    payload: Optional[CloudScanTrigger] = None,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Execute read-only CSPM compliance scan across cloud account."""
    trigger_payload = payload or CloudScanTrigger()
    acc = await CloudSecurityService.scan_account(
        db=db, account_id=account_id, payload=trigger_payload, user=user
    )
    open_findings = [f for f in acc.findings if f.status == "open"]
    return {
        "id": acc.id,
        "provider": acc.provider,
        "name": acc.name,
        "account_identifier": acc.account_identifier,
        "role_arn_or_ref": acc.role_arn_or_ref,
        "region": acc.region,
        "is_active": acc.is_active,
        "posture_score": acc.posture_score,
        "risk_score": acc.risk_score,
        "findings_count": len(open_findings),
        "last_scanned_at": acc.last_scanned_at,
        "created_at": acc.created_at,
        "updated_at": acc.updated_at,
    }


@router.get("/accounts/{account_id}/findings", response_model=List[CloudFindingResponse])
async def list_findings(
    account_id: str,
    service: Optional[str] = Query(None, description="Filter by service (storage, iam, network, database)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (open, resolved, etc.)"),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List CSPM vulnerability findings for cloud account."""
    return await CloudSecurityService.list_findings(
        db=db,
        account_id=account_id,
        service=service,
        severity=severity,
        status_filter=status_filter,
        user=user,
    )


@router.patch("/findings/{finding_id}", response_model=CloudFindingResponse)
async def update_finding_status(
    finding_id: str,
    payload: CloudFindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Triage CSPM finding with justification."""
    return await CloudSecurityService.update_finding_status(
        db=db, finding_id=finding_id, payload=payload, user=user
    )
