import React, { useState, useEffect, useCallback } from 'react';
import {
  ArrowLeft,
  RefreshCw,
  Globe,
  ShieldCheck,
  Clock,
  Play,
  ChevronRight,
  AlertOctagon,
  ScanSearch,
} from 'lucide-react';
import { Project } from '../types/project';
import { fetchProject, triggerScan } from '../services/api';

interface ProjectDetailViewProps {
  projectId: string;
  onBack: () => void;
  onSelectScan: (scanId: string) => void;
  onProjectUpdated: () => void;
}

export const ProjectDetailView: React.FC<ProjectDetailViewProps> = ({
  projectId,
  onBack,
  onSelectScan,
  onProjectUpdated,
}) => {
  const [project, setProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isTriggering, setIsTriggering] = useState(false);

  const loadProjectData = useCallback(async () => {
    setLoadError(null);
    try {
      const data = await fetchProject(projectId);
      setProject(data);
    } catch (err) {
      console.error('Failed to load project details:', err);
      setLoadError(err instanceof Error ? err.message : 'Failed to load project.');
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    loadProjectData();
  }, [loadProjectData]);

  const handleStartScan = async () => {
    if (!project) return;
    setIsTriggering(true);
    try {
      const scan = await triggerScan(project.id);
      onProjectUpdated();
      onSelectScan(scan.id);
    } catch (err) {
      console.error('Failed to trigger scan:', err);
    } finally {
      setIsTriggering(false);
    }
  };

  if (loading && !project) {
    return (
      <div className="surface-card" style={{ padding: '40px', textAlign: 'center' }}>
        <RefreshCw size={24} style={{ animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
        <div>Loading project details...</div>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="surface-card" style={{ padding: '40px', textAlign: 'center' }}>
        <AlertOctagon size={36} color="var(--accent-rose)" style={{ margin: '0 auto 12px' }} />
        <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
          {loadError}
        </p>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '20px' }}>
          The project ID in the URL may be invalid or the project may have been deleted.
        </p>
        <button className="btn-secondary" onClick={onBack}>
          <ArrowLeft size={14} /> Back to Projects
        </button>
      </div>
    );
  }

  if (!project) {
    return (
      <div className="surface-card" style={{ padding: '40px', textAlign: 'center' }}>
        <AlertOctagon size={36} color="var(--accent-rose)" style={{ margin: '0 auto 12px' }} />
        <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
          Project not found.
        </p>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '20px' }}>
          The project ID in the URL may be invalid or the project may have been deleted.
        </p>
        <button className="btn-secondary" onClick={onBack}>
          <ArrowLeft size={14} /> Back to Projects
        </button>
      </div>
    );
  }

  const latestScan = project.latest_scan;
  const scansList = project.scans || (latestScan ? [latestScan] : []);

  const getScoreColor = (score?: number | null) => {
    if (score == null) return 'var(--text-muted)';
    if (score >= 90) return 'var(--accent-emerald)';
    if (score >= 75) return 'var(--accent-cyan)';
    if (score >= 50) return 'var(--accent-amber)';
    return 'var(--accent-rose)';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top action row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button className="btn-secondary" onClick={onBack} style={{ padding: '6px 12px' }}>
          <ArrowLeft size={14} /> Back to Projects
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            className="btn-primary"
            onClick={handleStartScan}
            disabled={isTriggering}
            style={{ padding: '6px 14px', fontSize: '0.82rem' }}
          >
            <Play size={13} style={{ fill: 'currentColor' }} />
            <span>{isTriggering ? 'Starting...' : 'Scan Now'}</span>
          </button>

          <button
            className="btn-secondary"
            onClick={loadProjectData}
            title="Refresh project details"
            style={{ padding: '6px 10px' }}
          >
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {/* Hero Card */}
      <div className="hero-card" style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '20px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <Globe size={20} color="var(--accent-cyan)" />
            <h1 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#fff' }}>
              {project.name}
            </h1>
            <span className="badge badge-emerald" style={{ fontSize: '0.68rem' }}>
              <ShieldCheck size={11} /> AUTHORIZED
            </span>
          </div>

          <p className="hero-subtitle" style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
            Target Endpoint: <code style={{ color: 'var(--accent-cyan)' }}>{project.target_url}</code>
          </p>

          <div style={{ display: 'flex', gap: '16px', marginTop: '14px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Clock size={13} /> Created: {new Date(project.created_at).toLocaleDateString()}
            </span>
            {latestScan && (
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                Latest Assessment: {new Date(latestScan.created_at).toLocaleDateString()}
              </span>
            )}
          </div>
        </div>

        {/* Posture Score Dial */}
        <div
          style={{
            minWidth: '160px',
            textAlign: 'center',
            padding: '16px 20px',
            borderRadius: '10px',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
            Latest Posture
          </span>
          <div
            style={{
              fontSize: '2.4rem',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: getScoreColor(latestScan?.overall_score),
              lineHeight: 1.1,
              margin: '6px 0',
            }}
          >
            {latestScan?.overall_score != null ? latestScan.overall_score : '—'}
            <span style={{ fontSize: '1rem', color: 'var(--text-muted)', fontWeight: 400 }}>/100</span>
          </div>
          {latestScan?.score_grade ? (
            <span
              className="badge"
              style={{
                backgroundColor: 'rgba(255,255,255,0.06)',
                color: getScoreColor(latestScan.overall_score),
                fontSize: '0.7rem',
              }}
            >
              {latestScan.score_grade}
            </span>
          ) : (
            <span className="nav-link-badge">NOT SCANNED</span>
          )}
        </div>
      </div>

      {/* Scans History Section */}
      <div className="surface-card" style={{ gap: '16px' }}>
        <div className="card-header">
          <div className="card-title-group">
            <ScanSearch size={18} color="var(--accent-cyan)" />
            <h2 className="card-title">Assessment Scan History ({scansList.length})</h2>
          </div>
        </div>

        {scansList.length === 0 ? (
          <div style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <p style={{ fontSize: '0.92rem', color: 'var(--text-primary)', fontWeight: 600, marginBottom: '6px' }}>
              No security scans have been run for this project yet.
            </p>
            <p style={{ fontSize: '0.8rem', marginBottom: '16px' }}>
              Launch your first defensive security audit to inspect HTTPS/TLS, headers, cookies, and CORS.
            </p>
            <button className="btn-primary" onClick={handleStartScan} disabled={isTriggering}>
              <Play size={13} style={{ fill: 'currentColor' }} />
              <span>Launch First Scan</span>
            </button>
          </div>
        ) : (
          <div className="diagnostic-list">
            {scansList.map((scan) => {
              const isRunning = scan.status === 'running' || scan.status === 'queued';
              return (
                <div
                  key={scan.id}
                  className="finding-row"
                  onClick={() => onSelectScan(scan.id)}
                  style={{ cursor: 'pointer' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: 0 }}>
                    <span
                      className={`badge ${
                        scan.status === 'completed'
                          ? 'badge-emerald'
                          : scan.status === 'failed'
                          ? 'badge-rose'
                          : 'badge-cyan'
                      }`}
                      style={{ minWidth: '85px', justifyContent: 'center' }}
                    >
                      {isRunning ? 'RUNNING' : scan.status.toUpperCase()}
                    </span>

                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
                        {scan.target_url}
                      </div>
                      <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', display: 'flex', gap: '12px', marginTop: '2px' }}>
                        <span>ID: {scan.id.slice(0, 8)}...</span>
                        <span>Date: {new Date(scan.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    {scan.overall_score != null ? (
                      <div style={{ textAlign: 'right' }}>
                        <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block' }}>POSTURE</span>
                        <span
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 700,
                            fontSize: '0.92rem',
                            color: getScoreColor(scan.overall_score),
                          }}
                        >
                          {scan.overall_score}/100
                        </span>
                      </div>
                    ) : (
                      <span className="nav-link-badge">IN PROGRESS</span>
                    )}

                    <ChevronRight size={16} color="var(--text-muted)" />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
