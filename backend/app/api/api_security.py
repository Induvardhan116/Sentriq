import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.schemas.api_security import (
    ApiSpecImport,
    ApiSpecResponse,
    ApiEndpointResponse,
    ApiFindingResponse,
    ApiFindingStatusUpdate,
)
from app.services.api_security_service import ApiSecurityService
from app.security.deps import (
    get_authenticated_user_or_dev_mode,
    require_verified_user,
    require_csrf_if_auth_enabled,
)

logger = logging.getLogger("sentriq.api.api_security")
router = APIRouter(prefix="/api-security", tags=["API Security"])


@router.post("/specs", response_model=ApiSpecResponse, status_code=status.HTTP_201_CREATED)
async def import_spec(
    payload: ApiSpecImport,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Import and analyze an OpenAPI 3.0 or Swagger 2.0 schema."""
    return await ApiSecurityService.import_spec(db=db, payload=payload, user=user)


@router.get("/specs", response_model=List[ApiSpecResponse])
async def list_specs(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List all accessible API specifications for tenant."""
    return await ApiSecurityService.list_specs(db=db, user=user)


@router.get("/specs/{spec_id}", response_model=ApiSpecResponse)
async def get_spec(
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve API specification detail by ID."""
    return await ApiSecurityService.get_spec_by_id(db=db, spec_id=spec_id, user=user)


@router.delete("/specs/{spec_id}")
async def delete_spec(
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Delete an API specification and its endpoints/findings."""
    return await ApiSecurityService.delete_spec(db=db, spec_id=spec_id, user=user)


@router.get("/specs/{spec_id}/endpoints", response_model=List[ApiEndpointResponse])
async def list_spec_endpoints(
    spec_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List all discovered endpoints for a specification."""
    return await ApiSecurityService.list_spec_endpoints(db=db, spec_id=spec_id, user=user)


@router.get("/specs/{spec_id}/findings", response_model=List[ApiFindingResponse])
async def list_spec_findings(
    spec_id: str,
    category: Optional[str] = Query(None, description="Filter by OWASP API category (e.g. API2:2023)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List findings mapped to OWASP API Security Top 10."""
    return await ApiSecurityService.list_spec_findings(
        db=db,
        spec_id=spec_id,
        user=user,
        category=category,
        severity=severity,
    )


@router.patch("/findings/{finding_id}", response_model=ApiFindingResponse)
async def update_finding_status(
    finding_id: str,
    payload: ApiFindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Update API finding status with mandatory justification rules."""
    return await ApiSecurityService.update_finding_status(
        db=db,
        finding_id=finding_id,
        payload=payload,
        user=user,
    )
