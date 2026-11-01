import React, { useState } from 'react';
import {
  FolderLock,
  Plus,
  Play,
  Globe,
  ShieldCheck,
  ChevronRight,
  RefreshCw,
  Edit3,
  Trash2,
  CheckCircle2,
  AlertCircle,
  X,
} from 'lucide-react';
import { Project } from '../types/project';
import { triggerScan } from '../services/api';
import { EditProjectModal } from './EditProjectModal';
import { DeleteProjectModal } from './DeleteProjectModal';

interface ProjectListProps {
  projects: Project[];
  loading: boolean;
  onOpenCreateModal: () => void;
  onSelectScan: (scanId: string) => void;
  onSelectProject?: (projectId: string) => void;
  onProjectUpdated: () => void;
}

export const ProjectList: React.FC<ProjectListProps> = ({
  projects,
  loading,
  onOpenCreateModal,
  onSelectScan,
  onSelectProject,
  onProjectUpdated,
}) => {
  const [triggeringId, setTriggeringId] = useState<string | null>(null);
  const [editingProject, setEditingProject] = useState<Project | null>(null);
  const [deletingProject, setDeletingProject] = useState<Project | null>(null);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message });
    setTimeout(() => {
      setToast((current) => (current?.message === message ? null : current));
    }, 6000);
  };

  const handleStartScan = async (projectId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setTriggeringId(projectId);
    try {
      const scan = await triggerScan(projectId);
      onProjectUpdated();
      onSelectScan(scan.id);
    } catch (err) {
      console.error('Failed to trigger scan:', err);
      showToast('error', err instanceof Error ? err.message : 'Failed to trigger scan.');
    } finally {
      setTriggeringId(null);
    }
  };

  const getScoreBadge = (score?: number | null) => {
    if (score == null) {
      return <span className="nav-link-badge">NOT SCANNED</span>;
    }
    if (score >= 90) {
      return <span className="badge badge-emerald">SCORE {score}/100</span>;
    }
    if (score >= 75) {
      return <span className="badge badge-cyan">SCORE {score}/100</span>;
    }
    if (score >= 50) {
      return <span className="badge badge-amber">SCORE {score}/100</span>;
    }
    return <span className="badge badge-rose">SCORE {score}/100</span>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px' }}>
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#fff' }}>
            Security Assessment Projects
          </h2>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            Authorized target web applications monitored for security configuration and posture.
          </p>
        </div>

        <button className="btn-primary" onClick={onOpenCreateModal}>
          <Plus size={16} />
          <span>New Project</span>
        </button>
      </div>

      {toast && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            backgroundColor:
              toast.type === 'success' ? 'var(--accent-emerald-subtle)' : 'var(--accent-rose-subtle)',
            border: `1px solid ${
              toast.type === 'success' ? 'rgba(16, 185, 129, 0.35)' : 'rgba(244, 63, 94, 0.35)'
            }`,
            color: toast.type === 'success' ? 'var(--accent-emerald)' : 'var(--accent-rose)',
            fontSize: '0.85rem',
            animation: 'fadeIn 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {toast.type === 'success' ? <CheckCircle2 size={18} /> : <AlertCircle size={18} />}
            <span>{toast.message}</span>
          </div>
          <button
            onClick={() => setToast(null)}
            style={{
              background: 'none',
              border: 'none',
              color: 'inherit',
              cursor: 'pointer',
              padding: '2px',
              display: 'flex',
              alignItems: 'center',
            }}
            title="Dismiss message"
          >
            <X size={15} />
          </button>
        </div>
      )}

      {loading && projects.length === 0 ? (
        <div className="surface-card" style={{ padding: '40px', textAlign: 'center' }}>
          <RefreshCw size={24} style={{ animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
          <div>Loading projects...</div>
        </div>
      ) : projects.length === 0 ? (
        <div className="surface-card" style={{ padding: '50px 20px', textAlign: 'center' }}>
          <FolderLock size={40} color="var(--accent-cyan)" style={{ margin: '0 auto 14px' }} />
          <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#fff', marginBottom: '6px' }}>
            No security assessment projects yet
          </h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '480px', margin: '0 auto 20px' }}>
            Add your authorized web application or target URL to launch defensive security scans and track posture.
          </p>
          <button className="btn-primary" onClick={onOpenCreateModal} style={{ margin: '0 auto' }}>
            <Plus size={16} />
            <span>Create First Project</span>
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {projects.map((project) => {
            const latestScan = project.latest_scan;
            const isTriggering = triggeringId === project.id;

            return (
              <div
                key={project.id}
                className="surface-card project-card"
                onClick={() => {
                  if (latestScan) {
                    onSelectScan(latestScan.id);
                  } else if (onSelectProject) {
                    onSelectProject(project.id);
                  }
                }}
                style={{ cursor: 'pointer', padding: '18px 22px' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px', minWidth: '240px' }}>
                    <div className="brand-logo-badge" style={{ flexShrink: 0 }}>
                      <Globe size={18} />
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.96rem', color: '#fff' }}>
                          {project.name}
                        </span>
                        <span className="badge badge-emerald" style={{ fontSize: '0.65rem' }}>
                          <ShieldCheck size={11} /> AUTHORIZED
                        </span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span>{project.target_url}</span>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                    {getScoreBadge(latestScan?.overall_score)}

                    {latestScan && (
                      <div style={{ textAlign: 'right', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                        <span style={{ display: 'block' }}>Latest Scan</span>
                        <span>{new Date(latestScan.created_at).toLocaleDateString()}</span>
                      </div>
                    )}

                    <button
                      className="btn-secondary"
                      onClick={(e) => handleStartScan(project.id, e)}
                      disabled={isTriggering}
                      style={{ padding: '6px 12px', fontSize: '0.78rem' }}
                      title="Run new safe assessment"
                      aria-label={`Run new safe scan on ${project.name}`}
                    >
                      <Play size={13} style={{ fill: 'currentColor' }} />
                      <span>{isTriggering ? 'Starting...' : 'Scan Now'}</span>
                    </button>

                    <button
                      className="btn-secondary"
                      onClick={(e) => {
                        e.stopPropagation();
                        setEditingProject(project);
                      }}
                      style={{ padding: '6px 10px', fontSize: '0.78rem' }}
                      title="Edit project name or target URL"
                      aria-label={`Edit ${project.name}`}
                    >
                      <Edit3 size={13} />
                      <span>Edit</span>
                    </button>

                    <button
                      className="btn-secondary"
                      onClick={(e) => {
                        e.stopPropagation();
                        setDeletingProject(project);
                      }}
                      style={{
                        padding: '6px 10px',
                        fontSize: '0.78rem',
                        color: 'var(--accent-rose)',
                        borderColor: 'rgba(244, 63, 94, 0.3)',
                      }}
                      title="Delete project and scan history"
                      aria-label={`Delete ${project.name}`}
                    >
                      <Trash2 size={13} />
                      <span>Delete</span>
                    </button>

                    {latestScan && <ChevronRight size={16} color="var(--text-muted)" />}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Edit Project Dialog */}
      <EditProjectModal
        project={editingProject}
        isOpen={editingProject !== null}
        onClose={() => setEditingProject(null)}
        onProjectUpdated={(updatedProject) => {
          onProjectUpdated();
          showToast('success', `Project "${updatedProject.name}" was updated successfully.`);
        }}
      />

      {/* Delete Project Confirmation Dialog */}
      <DeleteProjectModal
        project={deletingProject}
        isOpen={deletingProject !== null}
        onClose={() => setDeletingProject(null)}
        onProjectDeleted={(_deletedId, projectName) => {
          onProjectUpdated();
          showToast('success', `Project "${projectName}" and associated scan history were permanently deleted.`);
        }}
      />
    </div>
  );
};
