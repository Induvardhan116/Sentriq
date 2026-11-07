import logging
import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.workspace import Workspace, WorkspaceMember, WorkspaceAuditLog
from app.models.user import User
from app.schemas.workspace import (
    WorkspaceCreate,
    WorkspaceResponse,
    WorkspaceMemberResponse,
    WorkspaceInviteMember,
    WorkspaceUpdateRole,
    WorkspaceAuditLogResponse,
)

logger = logging.getLogger("sentriq.services.workspaces")


def sluggify(text: str) -> str:
    """Generate URL-safe slug from workspace name."""
    s = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "-", s)


class WorkspaceService:
    @classmethod
    async def _get_caller_role(
        cls, db: AsyncSession, workspace_id: str, user: Optional[User]
    ) -> Optional[str]:
        """Determine caller's RBAC role within workspace, or 'owner' if superuser."""
        if not user:
            return None
        if getattr(user, "is_superuser", False):
            return "owner"

        stmt = select(WorkspaceMember.role).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == user.id,
        )
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @classmethod
    async def create_workspace(
        cls, db: AsyncSession, payload: WorkspaceCreate, user: Optional[User]
    ) -> WorkspaceResponse:
        """Create a new multi-tenant organization workspace with caller as owner."""
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required to create a workspace.",
            )

        base_slug = sluggify(payload.name)
        unique_slug = f"{base_slug}-{secrets.token_hex(3)}"

        workspace = Workspace(
            id=str(uuid.uuid4()),
            name=payload.name.strip(),
            slug=unique_slug,
            owner_id=user.id,
        )
        db.add(workspace)
        await db.flush()

        member = WorkspaceMember(
            id=str(uuid.uuid4()),
            workspace_id=workspace.id,
            user_id=user.id,
            role="owner",
        )
        db.add(member)

        # Audit log entry
        audit = WorkspaceAuditLog(
            id=str(uuid.uuid4()),
            workspace_id=workspace.id,
            actor_id=user.id,
            actor_email=user.email,
            action="workspace.created",
            resource_type="workspace",
            resource_id=workspace.id,
            details=f"Created workspace '{workspace.name}' (slug: {workspace.slug})",
        )
        db.add(audit)

        await db.commit()
        await db.refresh(workspace)

        return WorkspaceResponse(
            id=workspace.id,
            name=workspace.name,
            slug=workspace.slug,
            owner_id=workspace.owner_id,
            role="owner",
            members_count=1,
            created_at=workspace.created_at,
            updated_at=workspace.updated_at,
        )

    @classmethod
    async def list_workspaces(
        cls, db: AsyncSession, user: Optional[User]
    ) -> List[WorkspaceResponse]:
        """List all workspaces the authenticated user is a member of."""
        if not user:
            return []

        if getattr(user, "is_superuser", False):
            stmt = select(Workspace).order_by(Workspace.created_at.desc())
            result = await db.execute(stmt)
            workspaces = result.scalars().all()
            output = []
            for w in workspaces:
                output.append(
                    WorkspaceResponse(
                        id=w.id,
                        name=w.name,
                        slug=w.slug,
                        owner_id=w.owner_id,
                        role="owner",
                        members_count=len(w.members),
                        created_at=w.created_at,
                        updated_at=w.updated_at,
                    )
                )
            return output

        stmt = (
            select(Workspace, WorkspaceMember.role)
            .join(WorkspaceMember, Workspace.id == WorkspaceMember.workspace_id)
            .where(WorkspaceMember.user_id == user.id)
            .order_by(Workspace.created_at.desc())
        )
        result = await db.execute(stmt)
        rows = result.all()

        output = []
        for w, role in rows:
            output.append(
                WorkspaceResponse(
                    id=w.id,
                    name=w.name,
                    slug=w.slug,
                    owner_id=w.owner_id,
                    role=role,
                    members_count=len(w.members),
                    created_at=w.created_at,
                    updated_at=w.updated_at,
                )
            )
        return output

    @classmethod
    async def get_workspace(
        cls, db: AsyncSession, workspace_id: str, user: Optional[User]
    ) -> WorkspaceResponse:
        """Fetch workspace ensuring caller is a member."""
        role = await cls._get_caller_role(db, workspace_id, user)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workspace not found or access denied.",
            )

        stmt = select(Workspace).where(Workspace.id == workspace_id)
        res = await db.execute(stmt)
        w = res.scalar_one_or_none()
        if not w:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")

        return WorkspaceResponse(
            id=w.id,
            name=w.name,
            slug=w.slug,
            owner_id=w.owner_id,
            role=role,
            members_count=len(w.members),
            created_at=w.created_at,
            updated_at=w.updated_at,
        )

    @classmethod
    async def list_members(
        cls, db: AsyncSession, workspace_id: str, user: Optional[User]
    ) -> List[WorkspaceMemberResponse]:
        """List team members and roles within a workspace."""
        role = await cls._get_caller_role(db, workspace_id, user)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workspace not found or access denied.",
            )

        stmt = (
            select(WorkspaceMember, User)
            .join(User, WorkspaceMember.user_id == User.id)
            .where(WorkspaceMember.workspace_id == workspace_id)
            .order_by(WorkspaceMember.joined_at.asc())
        )
        res = await db.execute(stmt)
        rows = res.all()

        return [
            WorkspaceMemberResponse(
                id=m.id,
                user_id=u.id,
                email=u.email,
                full_name=u.full_name,
                role=m.role,
                joined_at=m.joined_at,
            )
            for m, u in rows
        ]

    @classmethod
    async def add_or_invite_member(
        cls, db: AsyncSession, workspace_id: str, payload: WorkspaceInviteMember, user: Optional[User]
    ) -> WorkspaceMemberResponse:
        """Invite/add user to workspace (requires owner or admin role)."""
        caller_role = await cls._get_caller_role(db, workspace_id, user)
        if caller_role not in ["owner", "admin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions. Only Owners and Admins can invite team members.",
            )

        # Lookup user by email
        user_stmt = select(User).where(User.email == payload.email.strip().lower())
        user_res = await db.execute(user_stmt)
        target_user = user_res.scalar_one_or_none()
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with email '{payload.email}' is not registered on Sentriq.",
            )

        # Check existing membership
        exist_stmt = select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == target_user.id,
        )
        if (await db.execute(exist_stmt)).scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already a member of this workspace.",
            )

        member = WorkspaceMember(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            user_id=target_user.id,
            role=payload.role,
        )
        db.add(member)

        # Audit log
        audit = WorkspaceAuditLog(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            actor_id=user.id if user else "system",
            actor_email=user.email if user else "system",
            action="member.invited",
            resource_type="workspace_member",
            resource_id=member.id,
            details=f"Invited {target_user.email} with role '{payload.role}'",
        )
        db.add(audit)

        await db.commit()
        await db.refresh(member)

        return WorkspaceMemberResponse(
            id=member.id,
            user_id=target_user.id,
            email=target_user.email,
            full_name=target_user.full_name,
            role=member.role,
            joined_at=member.joined_at,
        )

    @classmethod
    async def update_member_role(
        cls,
        db: AsyncSession,
        workspace_id: str,
        target_user_id: str,
        payload: WorkspaceUpdateRole,
        user: Optional[User],
    ) -> WorkspaceMemberResponse:
        """Update a member's RBAC role (requires owner role)."""
        caller_role = await cls._get_caller_role(db, workspace_id, user)
        if caller_role != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions. Only Workspace Owners can update member roles.",
            )

        stmt = (
            select(WorkspaceMember, User)
            .join(User, WorkspaceMember.user_id == User.id)
            .where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == target_user_id,
            )
        )
        res = await db.execute(stmt)
        row = res.one_or_none()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Member not found in this workspace.",
            )
        member, target_user = row

        # If demoting an owner, ensure there is at least one other owner
        if member.role == "owner" and payload.role != "owner":
            owner_count_stmt = select(func.count(WorkspaceMember.id)).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.role == "owner",
            )
            count = (await db.execute(owner_count_stmt)).scalar()
            if count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot demote the only remaining Workspace Owner.",
                )

        member.role = payload.role

        audit = WorkspaceAuditLog(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            actor_id=user.id if user else "system",
            actor_email=user.email if user else "system",
            action="role.updated",
            resource_type="workspace_member",
            resource_id=member.id,
            details=f"Updated role of {target_user.email} to '{payload.role}'",
        )
        db.add(audit)

        await db.commit()
        await db.refresh(member)

        return WorkspaceMemberResponse(
            id=member.id,
            user_id=target_user.id,
            email=target_user.email,
            full_name=target_user.full_name,
            role=member.role,
            joined_at=member.joined_at,
        )

    @classmethod
    async def remove_member(
        cls, db: AsyncSession, workspace_id: str, target_user_id: str, user: Optional[User]
    ) -> None:
        """Remove member from workspace (requires owner or admin, or self-leave)."""
        caller_role = await cls._get_caller_role(db, workspace_id, user)
        is_self = bool(user and user.id == target_user_id)

        if not is_self and caller_role not in ["owner", "admin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to remove member.",
            )

        stmt = select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == target_user_id,
        )
        res = await db.execute(stmt)
        member = res.scalar_one_or_none()
        if not member:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Member not found in workspace.",
            )

        if member.role == "owner":
            owner_count_stmt = select(func.count(WorkspaceMember.id)).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.role == "owner",
            )
            count = (await db.execute(owner_count_stmt)).scalar()
            if count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot remove the only remaining Workspace Owner.",
                )

        await db.delete(member)

        audit = WorkspaceAuditLog(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            actor_id=user.id if user else "system",
            actor_email=user.email if user else "system",
            action="member.removed",
            resource_type="workspace_member",
            resource_id=target_user_id,
            details=f"Removed user {target_user_id} from workspace",
        )
        db.add(audit)

        await db.commit()

    @classmethod
    async def list_audit_logs(
        cls, db: AsyncSession, workspace_id: str, user: Optional[User]
    ) -> List[WorkspaceAuditLogResponse]:
        """Fetch immutable organization audit log entries."""
        role = await cls._get_caller_role(db, workspace_id, user)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workspace not found or access denied.",
            )

        stmt = (
            select(WorkspaceAuditLog)
            .where(WorkspaceAuditLog.workspace_id == workspace_id)
            .order_by(WorkspaceAuditLog.created_at.desc())
            .limit(100)
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())
