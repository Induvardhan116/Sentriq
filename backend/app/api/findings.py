import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.schemas.finding import (
    FindingResponse,
    FindingStatusUpdate,
    FindingStatusEventResponse,
    PaginatedFindingsResponse,
    FindingsSummaryResponse,
)
from app.services.finding_service import FindingService
from app.security.deps import (
    get_authenticated_user_or_dev_mode,
    require_csrf_if_auth_enabled,
)

logger = logging.getLogger("sentriq.api.findings")
router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=PaginatedFindingsResponse)
async def list_findings(
    project_id: Optional[str] = Query(None, description="Filter findings by parent project ID"),
    scan_id: Optional[str] = Query(None, description="Filter findings by scan ID"),
    status: Optional[str] = Query(None, description="Filter by resolution status (open, in_progress, resolved, false_positive, accepted_risk)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, informational)"),
    category: Optional[str] = Query(None, description="Filter by finding category"),
    search: Optional[str] = Query(None, description="Case-insensitive keyword search in title, description, or endpoint"),
    sort_by: str = Query("risk_score", description="Sort field: risk_score, severity, created_at, updated_at, title, status"),
    sort_order: str = Query("desc", description="Sort direction: asc or desc"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve a paginated, tenant-isolated list of findings with multi-dimensional filtering and sorting."""
    return await FindingService.list_findings(
        db=db,
        user=user,
        project_id=project_id,
        scan_id=scan_id,
        status_filter=status,
        severity_filter=severity,
        category_filter=category,
        search_query=search,
        sort_by=sort_by,
        sort_order=sort_order,
        limit=limit,
        offset=offset,
    )


# CRITICAL: /summary route MUST be registered before /{finding_id} to prevent route parameter collision
@router.get("/summary", response_model=FindingsSummaryResponse)
async def get_findings_summary(
    project_id: Optional[str] = Query(None, description="Filter metrics by project ID"),
    scan_id: Optional[str] = Query(None, description="Filter metrics by scan ID"),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve aggregate finding metrics (by severity, status, and category) across accessible projects."""
    return await FindingService.get_findings_summary(
        db=db,
        user=user,
        project_id=project_id,
        scan_id=scan_id,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve full detail for a single security finding with tenant ownership check."""
    return await FindingService.get_finding_by_id(
        db=db,
        finding_id=finding_id,
        user=user,
    )


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Update a security finding's lifecycle status with strict project ownership check, OCC, and immutable audit logging."""
    return await FindingService.update_finding_status(
        db=db,
        finding_id=finding_id,
        payload=payload,
        user=user,
    )


@router.get("/{finding_id}/history", response_model=List[FindingStatusEventResponse])
async def get_finding_history(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve immutable chronological audit history for a finding with tenant ownership enforcement."""
    return await FindingService.get_finding_history(
        db=db,
        finding_id=finding_id,
        user=user,
    )
