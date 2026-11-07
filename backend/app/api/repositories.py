import logging
from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, Query, Body, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.schemas.repository import (
    RepositoryCreate,
    RepositoryResponse,
    RepoScanResponse,
    RepoFindingResponse,
    RepoFindingStatusUpdate,
)
from app.services.repo_service import RepoService
from app.security.deps import (
    get_authenticated_user_or_dev_mode,
    require_verified_user,
    require_csrf_if_auth_enabled,
)

logger = logging.getLogger("sentriq.api.repositories")
router = APIRouter(prefix="/repositories", tags=["Repository Security"])


@router.post("", response_model=RepositoryResponse, status_code=status.HTTP_201_CREATED)
async def create_repository(
    payload: RepositoryCreate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Register a new repository target with SSRF clone URL validation."""
    return await RepoService.create_repository(db=db, payload=payload, user=user)


@router.get("", response_model=List[RepositoryResponse])
async def list_repositories(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List all accessible repositories for tenant."""
    return await RepoService.list_repositories(db=db, user=user)


@router.get("/{repo_id}", response_model=RepositoryResponse)
async def get_repository(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve repository detail by ID."""
    return await RepoService.get_repository_by_id(db=db, repo_id=repo_id, user=user)


@router.delete("/{repo_id}")
async def delete_repository(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Delete repository and all cascaded scans and findings."""
    return await RepoService.delete_repository(db=db, repo_id=repo_id, user=user)


@router.post("/{repo_id}/scan", response_model=RepoScanResponse)
async def run_repository_scan(
    repo_id: str,
    files: Optional[Dict[str, str]] = Body(None, description="Optional map of {file_path: file_content}"),
    branch: str = Query("main", description="Target git branch"),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Run Secret Detection, SAST, and SCA dependency audits against repository files."""
    return await RepoService.run_repository_scan(
        db=db,
        repo_id=repo_id,
        user=user,
        files_payload=files,
        branch=branch,
    )


@router.get("/{repo_id}/scans", response_model=List[RepoScanResponse])
async def list_repo_scans(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve scan history for a repository."""
    return await RepoService.list_repo_scans(db=db, repo_id=repo_id, user=user)


@router.get("/{repo_id}/findings", response_model=List[RepoFindingResponse])
async def list_repo_findings(
    repo_id: str,
    scan_type: Optional[str] = Query(None, description="Filter by scan type: secret, sast, sca"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status: open, resolved, false_positive, accepted_risk"),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve findings discovered across scans for a repository."""
    return await RepoService.list_repo_findings(
        db=db,
        repo_id=repo_id,
        user=user,
        scan_type=scan_type,
        severity=severity,
        status_filter=status,
    )


@router.patch("/findings/{finding_id}", response_model=RepoFindingResponse)
async def update_finding_status(
    finding_id: str,
    payload: RepoFindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Update repository finding status with mandatory justification rules."""
    return await RepoService.update_finding_status(
        db=db,
        finding_id=finding_id,
        payload=payload,
        user=user,
    )
