import React, { useEffect, useState, useCallback } from 'react';
import {
  Users,
  Plus,
  Trash2,
  RefreshCw,
  History,
  X,
  Building2,
  Crown,
} from 'lucide-react';
import {
  fetchWorkspaces,
  createWorkspace,
  fetchWorkspaceMembers,
  inviteWorkspaceMember,
  updateWorkspaceMemberRole,
  removeWorkspaceMember,
  fetchWorkspaceAuditLogs,
} from '../services/api';
import {
  Workspace,
  WorkspaceMember,
  WorkspaceAuditLog,
  WorkspaceRole,
} from '../types/workspace';

export const WorkspacesView: React.FC = () => {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState<string | null>(null);
  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [auditLogs, setAuditLogs] = useState<WorkspaceAuditLog[]>([]);
  const [activeTab, setActiveTab] = useState<'members' | 'audit'>('members');

  const [loadingWorkspaces, setLoadingWorkspaces] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Modals
  const [isCreateWsOpen, setIsCreateWsOpen] = useState(false);
  const [newWsName, setNewWsName] = useState('');
  const [submittingWs, setSubmittingWs] = useState(false);

  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<WorkspaceRole>('analyst');
  const [submittingInvite, setSubmittingInvite] = useState(false);

  const loadWorkspaces = useCallback(async () => {
    try {
      setLoadingWorkspaces(true);
      setError(null);
      const data = await fetchWorkspaces();
      setWorkspaces(data);
      if (data.length > 0 && !selectedWorkspaceId) {
        setSelectedWorkspaceId(data[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch workspaces');
    } finally {
      setLoadingWorkspaces(false);
    }
  }, [selectedWorkspaceId]);

  const loadWorkspaceDetails = useCallback(async (wsId: string) => {
    try {
      setLoadingDetails(true);
      const [mems, logs] = await Promise.all([
        fetchWorkspaceMembers(wsId),
        fetchWorkspaceAuditLogs(wsId),
      ]);
      setMembers(mems);
      setAuditLogs(logs);
    } catch (err) {
      console.error('Failed to load workspace details:', err);
    } finally {
      setLoadingDetails(false);
    }
  }, []);

  useEffect(() => {
    loadWorkspaces();
  }, [loadWorkspaces]);

  useEffect(() => {
    if (selectedWorkspaceId) {
      loadWorkspaceDetails(selectedWorkspaceId);
    } else {
      setMembers([]);
      setAuditLogs([]);
    }
  }, [selectedWorkspaceId, loadWorkspaceDetails]);

  const handleCreateWorkspace = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWsName.trim()) return;

    try {
      setSubmittingWs(true);
      setError(null);
      const created = await createWorkspace({ name: newWsName.trim() });
      setWorkspaces((prev) => [created, ...prev]);
      setSelectedWorkspaceId(created.id);
      setIsCreateWsOpen(false);
      setNewWsName('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create workspace');
    } finally {
      setSubmittingWs(false);
    }
  };

  const handleInviteMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedWorkspaceId || !inviteEmail.trim()) return;

    try {
      setSubmittingInvite(true);
      setError(null);
      const newMember = await inviteWorkspaceMember(selectedWorkspaceId, {
        email: inviteEmail.trim(),
        role: inviteRole,
      });
      setMembers((prev) => [...prev, newMember]);
      setIsInviteOpen(false);
      setInviteEmail('');
      await loadWorkspaceDetails(selectedWorkspaceId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to invite team member');
    } finally {
      setSubmittingInvite(false);
    }
  };

  const handleUpdateRole = async (userId: string, newRole: WorkspaceRole) => {
    if (!selectedWorkspaceId) return;
    try {
      await updateWorkspaceMemberRole(selectedWorkspaceId, userId, newRole);
      setMembers((prev) => prev.map((m) => (m.user_id === userId ? { ...m, role: newRole } : m)));
      await loadWorkspaceDetails(selectedWorkspaceId);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to update member role');
    }
  };

  const handleRemoveMember = async (userId: string) => {
    if (!selectedWorkspaceId) return;
    if (!window.confirm('Remove this member from the organization workspace?')) return;
    try {
      await removeWorkspaceMember(selectedWorkspaceId, userId);
      setMembers((prev) => prev.filter((m) => m.user_id !== userId));
      await loadWorkspaceDetails(selectedWorkspaceId);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to remove member');
    }
  };

  const selectedWs = workspaces.find((w) => w.id === selectedWorkspaceId);
  const isOwner = selectedWs?.role === 'owner';
  const isAdminOrOwner = selectedWs?.role === 'owner' || selectedWs?.role === 'admin';

  const getRoleBadgeStyle = (role: string) => {
    switch (role.toLowerCase()) {
      case 'owner':
        return { backgroundColor: 'rgba(234, 179, 8, 0.15)', color: '#eab308' };
      case 'admin':
        return { backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6' };
      case 'analyst':
        return { backgroundColor: 'rgba(6, 182, 212, 0.15)', color: 'var(--accent-cyan)' };
      default:
        return { backgroundColor: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8' };
    }
  };

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Enterprise Governance & Workspaces
            </h1>
            <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>
              Phase 12 Active
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
            Multi-tenant organization management, Role-Based Access Control (RBAC), and immutable compliance audit logs.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className="btn-secondary"
            onClick={loadWorkspaces}
            disabled={loadingWorkspaces || loadingDetails}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
          >
            <RefreshCw size={14} className={loadingWorkspaces || loadingDetails ? 'spin' : ''} /> Refresh
          </button>
          <button
            className="btn-primary"
            onClick={() => setIsCreateWsOpen(true)}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
          >
            <Plus size={14} /> Create Workspace
          </button>
        </div>
      </div>

      {error && (
        <div className="surface-card" style={{ padding: '12px 16px', borderLeft: '4px solid var(--accent-rose)', color: 'var(--accent-rose)' }}>
          {error}
        </div>
      )}

      {/* Main Grid: Workspaces Left + Workspace Inspector Right */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
        {/* Left: Workspaces List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Your Workspaces ({workspaces.length})
          </div>

          {loadingWorkspaces && workspaces.length === 0 ? (
            <div className="surface-card" style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading organizations...
            </div>
          ) : workspaces.length === 0 ? (
            <div className="surface-card" style={{ padding: '24px', textAlign: 'center' }}>
              <Building2 size={32} color="var(--text-muted)" style={{ margin: '0 auto 8px' }} />
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 500, margin: '0 0 4px' }}>
                No workspaces joined
              </p>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0 0 14px' }}>
                Create a workspace to invite security team members and establish governance.
              </p>
              <button
                className="btn-secondary"
                onClick={() => setIsCreateWsOpen(true)}
                style={{ fontSize: '0.78rem', padding: '6px 12px' }}
              >
                Create Workspace
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {workspaces.map((w) => {
                const isSelected = w.id === selectedWorkspaceId;
                return (
                  <div
                    key={w.id}
                    onClick={() => setSelectedWorkspaceId(w.id)}
                    className="surface-card"
                    style={{
                      padding: '14px',
                      cursor: 'pointer',
                      border: isSelected ? '1px solid var(--accent-cyan)' : '1px solid var(--border-color)',
                      backgroundColor: isSelected ? 'rgba(6, 182, 212, 0.05)' : undefined,
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                      <span style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
                        {w.name}
                      </span>
                      <span
                        style={{
                          fontSize: '0.7rem',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: '4px',
                          textTransform: 'uppercase',
                          ...getRoleBadgeStyle(w.role),
                        }}
                      >
                        {w.role}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                      <span>slug: {w.slug}</span>
                      <span>•</span>
                      <span>{w.members_count} members</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: Workspace Details */}
        <div>
          {selectedWs ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Workspace Hero */}
              <div className="surface-card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <h2 style={{ fontSize: '1.2rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                        {selectedWs.name}
                      </h2>
                      <span
                        style={{
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '4px',
                          textTransform: 'uppercase',
                          ...getRoleBadgeStyle(selectedWs.role),
                        }}
                      >
                        {selectedWs.role}
                      </span>
                    </div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0 }}>
                      Slug: {selectedWs.slug} • Created {new Date(selectedWs.created_at).toLocaleDateString()}
                    </p>
                  </div>

                  {isAdminOrOwner && (
                    <button
                      className="btn-primary"
                      onClick={() => setIsInviteOpen(true)}
                      style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
                    >
                      <Plus size={14} /> Invite Member
                    </button>
                  )}
                </div>
              </div>

              {/* Sub-Tabs: Members vs Audit Logs */}
              <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                <button
                  className={`btn-tab ${activeTab === 'members' ? 'active' : ''}`}
                  onClick={() => setActiveTab('members')}
                  style={{
                    background: 'none',
                    border: 'none',
                    borderBottom: activeTab === 'members' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                    color: activeTab === 'members' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    padding: '6px 14px',
                    cursor: 'pointer',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <Users size={15} />
                  <span>Team Members & RBAC ({members.length})</span>
                </button>

                <button
                  className={`btn-tab ${activeTab === 'audit' ? 'active' : ''}`}
                  onClick={() => setActiveTab('audit')}
                  style={{
                    background: 'none',
                    border: 'none',
                    borderBottom: activeTab === 'audit' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                    color: activeTab === 'audit' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    padding: '6px 14px',
                    cursor: 'pointer',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <History size={15} />
                  <span>Immutable Audit Trail ({auditLogs.length})</span>
                </button>
              </div>

              {/* Tab 1: Members Table */}
              {activeTab === 'members' && (
                <div className="surface-card" style={{ padding: 0, overflow: 'hidden' }}>
                  {loadingDetails ? (
                    <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      Loading team roster...
                    </div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                    <thead>
                      <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                        <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Member</th>
                        <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Email</th>
                        <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Role</th>
                        <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Joined</th>
                        {isAdminOrOwner && <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600, textAlign: 'right' }}>Actions</th>}
                      </tr>
                    </thead>
                    <tbody>
                      {members.map((m) => (
                        <tr key={m.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                          <td style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              {m.role === 'owner' && <Crown size={14} color="#eab308" />}
                              <span>{m.full_name || 'Team Member'}</span>
                            </div>
                          </td>
                          <td style={{ padding: '10px 14px', color: 'var(--text-secondary)' }}>
                            {m.email}
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {isOwner ? (
                              <select
                                value={m.role}
                                onChange={(e) => handleUpdateRole(m.user_id, e.target.value as WorkspaceRole)}
                                className="input-field"
                                style={{ padding: '2px 8px', fontSize: '0.76rem', textTransform: 'capitalize' }}
                              >
                                <option value="owner">Owner</option>
                                <option value="admin">Admin</option>
                                <option value="analyst">Analyst</option>
                                <option value="auditor">Auditor</option>
                              </select>
                            ) : (
                              <span
                                style={{
                                  fontSize: '0.72rem',
                                  fontWeight: 700,
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  textTransform: 'uppercase',
                                  ...getRoleBadgeStyle(m.role),
                                }}
                              >
                                {m.role}
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>
                            {new Date(m.joined_at).toLocaleDateString()}
                          </td>
                          {isAdminOrOwner && (
                            <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                              <button
                                className="btn-icon"
                                onClick={() => handleRemoveMember(m.user_id)}
                                title="Remove member"
                                style={{ color: 'var(--text-muted)' }}
                              >
                                <Trash2 size={15} />
                              </button>
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  )}
                </div>
              )}

              {/* Tab 2: Audit Logs */}
              {activeTab === 'audit' && (
                <div className="surface-card" style={{ padding: 0, overflow: 'hidden' }}>
                  <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                      Immutable Activity Trail (Latest {auditLogs.length} events)
                    </span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Tamper-evident database logs
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {auditLogs.length === 0 ? (
                      <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                        No audit events recorded for this workspace.
                      </div>
                    ) : (
                      auditLogs.map((log) => (
                        <div
                          key={log.id}
                          style={{
                            padding: '12px 16px',
                            borderBottom: '1px solid var(--border-color)',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            fontSize: '0.8rem',
                          }}
                        >
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span className="badge badge-secondary" style={{ fontSize: '0.7rem', fontFamily: 'monospace' }}>
                                {log.action}
                              </span>
                              <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                                {log.details}
                              </span>
                            </div>
                            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                              Actor: {log.actor_email} • Resource: {log.resource_type}
                            </div>
                          </div>

                          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                            {new Date(log.created_at).toLocaleString()}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="surface-card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Select a workspace from the left panel to inspect team members and compliance audit logs.
            </div>
          )}
        </div>
      </div>

      {/* Create Workspace Modal */}
      {isCreateWsOpen && (
        <div className="modal-backdrop" onClick={() => setIsCreateWsOpen(false)}>
          <div className="modal-card" style={{ maxWidth: '440px', width: '100%' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Create Organization Workspace
              </h3>
              <button className="btn-icon" onClick={() => setIsCreateWsOpen(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleCreateWorkspace} style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Workspace Name *
                </label>
                <input
                  type="text"
                  placeholder="e.g. Acme Cyber Defense Team"
                  value={newWsName}
                  onChange={(e) => setNewWsName(e.target.value)}
                  required
                  className="input-field"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
                <button type="button" className="btn-secondary" onClick={() => setIsCreateWsOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={submittingWs}>
                  {submittingWs ? 'Creating...' : 'Create Workspace'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Invite Member Modal */}
      {isInviteOpen && (
        <div className="modal-backdrop" onClick={() => setIsInviteOpen(false)}>
          <div className="modal-card" style={{ maxWidth: '440px', width: '100%' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Invite Team Member
              </h3>
              <button className="btn-icon" onClick={() => setIsInviteOpen(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleInviteMember} style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  User Email Address *
                </label>
                <input
                  type="email"
                  placeholder="analyst@company.com"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  required
                  className="input-field"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  RBAC Role *
                </label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as WorkspaceRole)}
                  className="input-field"
                  style={{ width: '100%' }}
                >
                  <option value="analyst">Analyst (Scan, Triage, Reports)</option>
                  <option value="admin">Admin (Manage Members & Assets)</option>
                  <option value="auditor">Auditor (Read-Only Findings & Reports)</option>
                  {isOwner && <option value="owner">Owner (Full Governance & Billing)</option>}
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
                <button type="button" className="btn-secondary" onClick={() => setIsInviteOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={submittingInvite}>
                  {submittingInvite ? 'Inviting...' : 'Send Invitation'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
