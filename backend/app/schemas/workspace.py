from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field


class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, description="Organization or workspace name")


class WorkspaceResponse(BaseModel):
    id: str
    name: str
    slug: str
    owner_id: str
    role: str = "owner"
    members_count: int = 1
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class WorkspaceMemberResponse(BaseModel):
    id: str
    user_id: str
    email: str
    full_name: Optional[str] = None
    role: str
    joined_at: datetime

    model_config = {"from_attributes": True}


class WorkspaceInviteMember(BaseModel):
    email: str = Field(..., description="Target user email to add or invite")
    role: Literal["owner", "admin", "analyst", "auditor"] = Field(
        "analyst", description="RBAC Role"
    )


class WorkspaceUpdateRole(BaseModel):
    role: Literal["owner", "admin", "analyst", "auditor"] = Field(..., description="New RBAC Role")


class WorkspaceAuditLogResponse(BaseModel):
    id: str
    workspace_id: str
    actor_id: str
    actor_email: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}
