export type WorkspaceRole = 'owner' | 'admin' | 'analyst' | 'auditor';

export interface Workspace {
  id: string;
  name: string;
  slug: string;
  owner_id: string;
  role: WorkspaceRole;
  members_count: number;
  created_at: string;
  updated_at: string;
}

export interface WorkspaceMember {
  id: string;
  user_id: string;
  email: string;
  full_name?: string | null;
  role: WorkspaceRole;
  joined_at: string;
}

export interface WorkspaceAuditLog {
  id: string;
  workspace_id: string;
  actor_id: string;
  actor_email: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  details?: string | null;
  created_at: string;
}

export interface WorkspaceCreatePayload {
  name: string;
}

export interface WorkspaceInvitePayload {
  email: string;
  role: WorkspaceRole;
}
