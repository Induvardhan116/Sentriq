import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type {
  Workspace,
  WorkspaceMember,
  WorkspaceAuditLog,
  WorkspaceRole,
} from '../types/workspace.ts';

// Simulated State & RBAC Logic for WorkspacesView
class WorkspaceStateMock {
  workspaces: Workspace[] = [];
  members: Map<string, WorkspaceMember[]> = new Map();
  auditLogs: Map<string, WorkspaceAuditLog[]> = new Map();
  currentWorkspaceId: string | null = null;

  addWorkspace(ws: Workspace): void {
    this.workspaces.unshift(ws);
    this.members.set(ws.id, [
      {
        id: `mem-${Date.now()}`,
        workspace_id: ws.id,
        user_id: 'user-owner',
        email: 'owner@sentriq.io',
        full_name: 'Lead Security Officer',
        role: 'owner',
        joined_at: new Date().toISOString(),
      },
    ]);
    this.auditLogs.set(ws.id, [
      {
        id: `log-${Date.now()}`,
        workspace_id: ws.id,
        actor_id: 'user-owner',
        actor_email: 'owner@sentriq.io',
        action: 'workspace.created',
        resource_type: 'workspace',
        resource_id: ws.id,
        details: `Workspace '${ws.name}' established.`,
        created_at: new Date().toISOString(),
      },
    ]);
    this.currentWorkspaceId = ws.id;
  }

  inviteMember(wsId: string, email: string, role: WorkspaceRole, actorRole: WorkspaceRole): void {
    if (actorRole !== 'owner' && actorRole !== 'admin') {
      throw new Error('Only owners and admins have permission to invite workspace members.');
    }
    const mems = this.members.get(wsId) || [];
    const newMember: WorkspaceMember = {
      id: `mem-${Date.now()}`,
      workspace_id: wsId,
      user_id: `user-${Date.now()}`,
      email,
      full_name: email.split('@')[0],
      role,
      joined_at: new Date().toISOString(),
    };
    mems.push(newMember);
    this.members.set(wsId, mems);

    const logs = this.auditLogs.get(wsId) || [];
    logs.unshift({
      id: `log-${Date.now()}`,
      workspace_id: wsId,
      actor_id: 'current-user',
      actor_email: 'admin@sentriq.io',
      action: 'member.invited',
      resource_type: 'workspace_member',
      resource_id: newMember.id,
      details: `Invited ${email} with role '${role}'.`,
      created_at: new Date().toISOString(),
    });
    this.auditLogs.set(wsId, logs);
  }

  updateRole(wsId: string, memberId: string, newRole: WorkspaceRole, actorRole: WorkspaceRole): void {
    if (actorRole !== 'owner') {
      throw new Error('Only owners can alter membership roles.');
    }
    const mems = this.members.get(wsId) || [];
    const target = mems.find((m) => m.id === memberId);
    if (!target) throw new Error('Member not found');

    if (target.role === 'owner' && newRole !== 'owner') {
      const ownerCount = mems.filter((m) => m.role === 'owner').length;
      if (ownerCount <= 1) {
        throw new Error('Cannot demote the sole remaining workspace owner.');
      }
    }

    target.role = newRole;
  }

  removeMember(wsId: string, memberId: string, actorRole: WorkspaceRole): void {
    if (actorRole !== 'owner' && actorRole !== 'admin') {
      throw new Error('Insufficient permissions to remove workspace members.');
    }
    const mems = this.members.get(wsId) || [];
    const target = mems.find((m) => m.id === memberId);
    if (!target) throw new Error('Member not found');

    if (target.role === 'owner') {
      const ownerCount = mems.filter((m) => m.role === 'owner').length;
      if (ownerCount <= 1) {
        throw new Error('Cannot remove the sole remaining workspace owner.');
      }
    }

    this.members.set(
      wsId,
      mems.filter((m) => m.id !== memberId)
    );
  }
}

describe('Enterprise Governance & Workspaces (Phase 12) State and RBAC Logic', () => {
  it('manages workspace creation, default owner assignment, and audit log generation', () => {
    const mock = new WorkspaceStateMock();

    mock.addWorkspace({
      id: 'ws-101',
      name: 'Cyber Operations HQ',
      slug: 'cyber-operations-hq',
      role: 'owner',
      members_count: 1,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    assert.strictEqual(mock.workspaces.length, 1);
    assert.strictEqual(mock.workspaces[0].name, 'Cyber Operations HQ');

    const members = mock.members.get('ws-101');
    assert.ok(members);
    assert.strictEqual(members.length, 1);
    assert.strictEqual(members[0].role, 'owner');

    const logs = mock.auditLogs.get('ws-101');
    assert.ok(logs);
    assert.strictEqual(logs.length, 1);
    assert.strictEqual(logs[0].action, 'workspace.created');
  });

  it('enforces RBAC permissions for invitations', () => {
    const mock = new WorkspaceStateMock();
    mock.addWorkspace({
      id: 'ws-101',
      name: 'Cyber Operations HQ',
      slug: 'cyber-operations-hq',
      role: 'owner',
      members_count: 1,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    // Auditor cannot invite members
    assert.throws(
      () => mock.inviteMember('ws-101', 'guest@acme.com', 'auditor', 'auditor'),
      /Only owners and admins have permission/
    );

    // Analyst cannot invite members
    assert.throws(
      () => mock.inviteMember('ws-101', 'guest@acme.com', 'auditor', 'analyst'),
      /Only owners and admins have permission/
    );

    // Admin can invite members
    mock.inviteMember('ws-101', 'security.analyst@acme.com', 'analyst', 'admin');
    const members = mock.members.get('ws-101');
    assert.strictEqual(members?.length, 2);

    const logs = mock.auditLogs.get('ws-101');
    assert.strictEqual(logs?.length, 2);
    assert.strictEqual(logs?.[0].action, 'member.invited');
  });

  it('strictly protects the sole owner from demotion or removal', () => {
    const mock = new WorkspaceStateMock();
    mock.addWorkspace({
      id: 'ws-101',
      name: 'Cyber Operations HQ',
      slug: 'cyber-operations-hq',
      role: 'owner',
      members_count: 1,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    const members = mock.members.get('ws-101')!;
    const ownerId = members[0].id;

    // Sole owner cannot be demoted to admin
    assert.throws(
      () => mock.updateRole('ws-101', ownerId, 'admin', 'owner'),
      /Cannot demote the sole remaining workspace owner/
    );

    // Sole owner cannot be removed
    assert.throws(
      () => mock.removeMember('ws-101', ownerId, 'owner'),
      /Cannot remove the sole remaining workspace owner/
    );

    // Add a second owner
    mock.inviteMember('ws-101', 'co-founder@sentriq.io', 'owner', 'owner');
    const updatedMembers = mock.members.get('ws-101')!;
    assert.strictEqual(updatedMembers.length, 2);

    // Now first owner can be demoted because a second owner exists
    mock.updateRole('ws-101', ownerId, 'admin', 'owner');
    assert.strictEqual(updatedMembers.find((m) => m.id === ownerId)?.role, 'admin');
  });
});
