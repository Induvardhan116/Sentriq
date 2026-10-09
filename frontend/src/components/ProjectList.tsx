import React, { useState } from 'react';
import {
  FolderLock,
  Plus,
  Play,
  Globe,
  ShieldCheck,
  ChevronRight,
  RefreshCw,
} from 'lucide-react';
import { Project } from '../types/project';
import { triggerScan } from '../services/api';

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

  const handleStartScan = async (projectId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setTriggeringId(projectId);
    try {
      const scan = await triggerScan(projectId);
      onProjectUpdated();
      onSelectScan(scan.id);
    } catch (err) {
      console.error('Failed to trigger scan:', err);
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
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
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
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                    <div className="brand-logo-badge">
                      <Globe size={18} />
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
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

                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
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
                    >
                      <Play size={13} style={{ fill: 'currentColor' }} />
                      <span>{isTriggering ? 'Starting...' : 'Scan Now'}</span>
                    </button>

                    {latestScan && <ChevronRight size={16} color="var(--text-muted)" />}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
