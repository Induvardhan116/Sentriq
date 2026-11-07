import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.schemas.workspace import (
    WorkspaceCreate,
    WorkspaceResponse,
    WorkspaceMemberResponse,
    WorkspaceInviteMember,
    WorkspaceUpdateRole,
    WorkspaceAuditLogResponse,
)
from app.services.workspace_service import WorkspaceService
from app.security.deps import (
    get_authenticated_user_or_dev_mode,
    require_verified_user,
    require_csrf_if_auth_enabled,
)

logger = logging.getLogger("sentriq.api.workspaces")
router = APIRouter(prefix="/workspaces", tags=["Workspaces & Enterprise Governance"])


@router.post("", response_model=WorkspaceResponse, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    payload: WorkspaceCreate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Create a new multi-tenant enterprise organization workspace."""
    return await WorkspaceService.create_workspace(db=db, payload=payload, user=user)


@router.get("", response_model=List[WorkspaceResponse])
async def list_workspaces(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List all workspaces the authenticated user belongs to."""
    return await WorkspaceService.list_workspaces(db=db, user=user)


@router.get("/{workspace_id}", response_model=WorkspaceResponse)
async def get_workspace(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Fetch details and membership role for a specific workspace."""
    return await WorkspaceService.get_workspace(db=db, workspace_id=workspace_id, user=user)


@router.get("/{workspace_id}/members", response_model=List[WorkspaceMemberResponse])
async def list_members(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """List members and assigned RBAC roles for a workspace."""
    return await WorkspaceService.list_members(db=db, workspace_id=workspace_id, user=user)


@router.post("/{workspace_id}/members", response_model=WorkspaceMemberResponse, status_code=status.HTTP_201_CREATED)
async def add_member(
    workspace_id: str,
    payload: WorkspaceInviteMember,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Invite or add a user to the workspace with specified role (Owner or Admin required)."""
    return await WorkspaceService.add_or_invite_member(
        db=db, workspace_id=workspace_id, payload=payload, user=user
    )


@router.patch("/{workspace_id}/members/{target_user_id}", response_model=WorkspaceMemberResponse)
async def update_member_role(
    workspace_id: str,
    target_user_id: str,
    payload: WorkspaceUpdateRole,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Update a workspace member's role (Owner required)."""
    return await WorkspaceService.update_member_role(
        db=db, workspace_id=workspace_id, target_user_id=target_user_id, payload=payload, user=user
    )


@router.delete("/{workspace_id}/members/{target_user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    workspace_id: str,
    target_user_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(require_verified_user),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Remove a member from the workspace (Owner, Admin, or self-leave)."""
    await WorkspaceService.remove_member(
        db=db, workspace_id=workspace_id, target_user_id=target_user_id, user=user
    )


@router.get("/{workspace_id}/audit-logs", response_model=List[WorkspaceAuditLogResponse])
async def list_audit_logs(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Fetch immutable enterprise compliance and activity audit logs."""
    return await WorkspaceService.list_audit_logs(db=db, workspace_id=workspace_id, user=user)
