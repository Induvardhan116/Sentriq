import React, { useState, useEffect, useCallback } from 'react';
import {
  ScanSearch,
  Key,
  Code2,
  Package,
  Plus,
  RefreshCw,
  Trash2,
  Play,
  X,
  FileCode,
} from 'lucide-react';
import {
  Repository,
  RepoFinding,
  RepoScanType,
} from '../types/repository';
import {
  fetchRepositories,
  deleteRepository,
  triggerRepoScan,
  fetchRepoFindings,
  updateRepoFindingStatus,
} from '../services/api';
import { ConnectRepoModal } from './ConnectRepoModal';

export const RepoSecurityView: React.FC = () => {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Modals state
  const [isConnectOpen, setIsConnectOpen] = useState(false);
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [repoFindings, setRepoFindings] = useState<RepoFinding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [findingTypeFilter, setFindingTypeFilter] = useState<RepoScanType | 'all'>('all');
  const [scanningRepoId, setScanningRepoId] = useState<string | null>(null);

  // Triage state
  const [triageFinding, setTriageFinding] = useState<RepoFinding | null>(null);
  const [triageStatus, setTriageStatus] = useState<'resolved' | 'accepted_risk' | 'false_positive'>('resolved');
  const [triageJustification, setTriageJustification] = useState('');
  const [triageUpdating, setTriageUpdating] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);

  const loadRepos = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchRepositories();
      setRepos(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to retrieve repositories';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRepos();
  }, [loadRepos]);

  const loadFindings = useCallback(async (repoId: string) => {
    setLoadingFindings(true);
    try {
      const data = await fetchRepoFindings(repoId);
      setRepoFindings(data);
    } catch (err) {
      console.error('Failed to load repo findings:', err);
      setRepoFindings([]);
    } finally {
      setLoadingFindings(false);
    }
  }, []);

  const handleSelectRepoToInspect = (repo: Repository) => {
    setSelectedRepo(repo);
    setFindingTypeFilter('all');
    loadFindings(repo.id);
  };

  const handleRunScan = async (repo: Repository) => {
    setScanningRepoId(repo.id);
    try {
      // Run security scan with standard representative files if demo, or trigger scan
      const demoFiles: Record<string, string> = {
        'config/aws.py': '# AWS Credentials\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        'api/database.py': 'def query_user(user_id):\n    # SQL concatenation pattern\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    return db.execute(query)\n',
        'package.json': '{\n  "dependencies": {\n    "lodash": "4.17.20",\n    "axios": "1.5.0"\n  }\n}\n',
        'requirements.txt': 'requests==2.28.0\nurllib3==1.26.17\n',
      };

      await triggerRepoScan(repo.id, demoFiles, repo.default_branch);
      await loadRepos();
      if (selectedRepo?.id === repo.id) {
        await loadFindings(repo.id);
      }
    } catch (err) {
      console.error('Failed to trigger scan:', err);
    } finally {
      setScanningRepoId(null);
    }
  };

  const handleDeleteRepo = async (repoId: string) => {
    if (!window.confirm('Are you sure you want to delete this repository and all related scans?')) {
      return;
    }
    try {
      await deleteRepository(repoId);
      setRepos((prev) => prev.filter((r) => r.id !== repoId));
      if (selectedRepo?.id === repoId) {
        setSelectedRepo(null);
      }
    } catch (err) {
      console.error('Failed to delete repository:', err);
    }
  };

  const handleConfirmTriage = async () => {
    if (!triageFinding) return;
    if ((triageStatus === 'accepted_risk' || triageStatus === 'false_positive') && !triageJustification.trim()) {
      setTriageError('A justification rationale is mandatory for accepted risk and false positive status.');
      return;
    }

    setTriageUpdating(true);
    setTriageError(null);
    try {
      const updated = await updateRepoFindingStatus(triageFinding.id, {
        status: triageStatus,
        justification: triageJustification.trim() || undefined,
      });
      setRepoFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
      setTriageFinding(null);
      setTriageJustification('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to update finding status';
      setTriageError(msg);
    } finally {
      setTriageUpdating(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'var(--accent-emerald)';
    if (score >= 75) return 'var(--accent-cyan)';
    if (score >= 50) return 'var(--accent-amber)';
    return 'var(--accent-rose)';
  };

  const filteredFindings = repoFindings.filter((f) => {
    if (findingTypeFilter === 'all') return true;
    return f.scan_type === findingTypeFilter;
  });

  return (
    <div className="repo-security-view" style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* Header Banner */}
      <section className="hero-card" style={{ marginBottom: '0' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-logo-badge" style={{ width: '38px', height: '38px' }}>
              <ScanSearch size={22} color="var(--accent-cyan)" />
            </div>
            <div>
              <h1 className="hero-title" style={{ fontSize: '1.4rem' }}>
                Source Code Repository Security (SAST & SCA)
              </h1>
              <p className="hero-subtitle" style={{ fontSize: '0.84rem' }}>
                Automated Secret Detection, Static Application Security Testing, and Dependency Vulnerability Audits.
              </p>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="badge badge-cyan" style={{ fontSize: '0.78rem' }}>
            PHASE 6 ACTIVE
          </span>
          <button
            className="btn-primary"
            onClick={() => setIsConnectOpen(true)}
            style={{ fontSize: '0.8rem', padding: '7px 14px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <Plus size={14} />
            <span>Connect Repository</span>
          </button>
        </div>
      </section>

      {/* KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
        <div className="surface-card" style={{ padding: '16px' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>REPOSITORIES</div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
            {repos.length}
          </div>
        </div>
        <div className="surface-card" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent-rose)', fontWeight: 700 }}>SECRET LEAKS</span>
            <Key size={16} color="var(--accent-rose)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-rose)', marginTop: '4px' }}>
            {repos.reduce((acc, r) => acc + (r.latest_risk_score > 0 ? 1 : 0), 0)}
          </div>
        </div>
        <div className="surface-card" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent-amber)', fontWeight: 700 }}>SAST VULNERABILITIES</span>
            <Code2 size={16} color="var(--accent-amber)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-amber)', marginTop: '4px' }}>
            {repos.filter((r) => r.latest_posture_score < 75).length}
          </div>
        </div>
        <div className="surface-card" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>SCA DEPENDENCY RISKS</span>
            <Package size={16} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', marginTop: '4px' }}>
            {repos.filter((r) => r.last_scanned_at !== null).length}
          </div>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '8px',
            backgroundColor: 'rgba(244, 63, 94, 0.1)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            color: 'var(--accent-rose)',
            fontSize: '0.82rem',
          }}
        >
          {error}
        </div>
      )}

      {/* Repositories Grid */}
      {loading ? (
        <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
          <RefreshCw size={24} className="spin" style={{ margin: '0 auto 12px' }} />
          <p style={{ fontSize: '0.86rem' }}>Loading repositories...</p>
        </div>
      ) : repos.length === 0 ? (
        <div className="surface-card" style={{ padding: '60px 20px', textAlign: 'center' }}>
          <ScanSearch size={36} color="var(--text-muted)" style={{ margin: '0 auto 12px' }} />
          <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
            No repositories connected yet
          </p>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '18px' }}>
            Connect a Git repository to begin continuous SAST analysis, secret leakage detection, and dependency checks.
          </p>
          <button className="btn-primary" onClick={() => setIsConnectOpen(true)}>
            Connect Repository
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '14px' }}>
          {repos.map((repo) => {
            const isScanning = scanningRepoId === repo.id;
            return (
              <div
                key={repo.id}
                className="surface-card"
                style={{
                  padding: '20px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  border: selectedRepo?.id === repo.id ? '1px solid var(--accent-cyan)' : undefined,
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <div>
                      <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                        {repo.name}
                      </h3>
                      <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {repo.full_name} &bull; branch: <code>{repo.default_branch}</code>
                      </div>
                    </div>
                    <span
                      style={{
                        fontSize: '1.2rem',
                        fontWeight: 800,
                        fontFamily: 'var(--font-mono)',
                        color: getScoreColor(repo.latest_posture_score),
                      }}
                    >
                      {repo.latest_posture_score}
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>/100</span>
                    </span>
                  </div>

                  <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: '12px' }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Clone URL: </span>
                      <code>{repo.clone_url}</code>
                    </div>
                    {repo.languages && (
                      <div style={{ marginTop: '4px' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Languages: </span>
                        <span>{repo.languages}</span>
                      </div>
                    )}
                  </div>
                </div>

                <div
                  style={{
                    marginTop: '16px',
                    paddingTop: '12px',
                    borderTop: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {repo.last_scanned_at
                      ? `Scanned ${new Date(repo.last_scanned_at).toLocaleDateString()}`
                      : 'Never scanned'}
                  </span>

                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => handleRunScan(repo)}
                      disabled={isScanning}
                      style={{ padding: '5px 10px', fontSize: '0.74rem', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                    >
                      <Play size={12} className={isScanning ? 'spin' : ''} />
                      <span>{isScanning ? 'Scanning...' : 'Scan'}</span>
                    </button>

                    <button
                      type="button"
                      className="btn-primary"
                      onClick={() => handleSelectRepoToInspect(repo)}
                      style={{ padding: '5px 10px', fontSize: '0.74rem' }}
                    >
                      Inspect
                    </button>

                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => handleDeleteRepo(repo.id)}
                      style={{ padding: '5px 8px', color: 'var(--accent-rose)', borderColor: 'rgba(244, 63, 94, 0.3)' }}
                      title="Delete Repository"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Inspected Repository Findings Drawer / Modal */}
      {selectedRepo && (
        <div className="surface-card" style={{ padding: '20px', marginTop: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  Findings for {selectedRepo.name} ({repoFindings.length})
                </h2>
                <span className="badge badge-cyan" style={{ fontSize: '0.74rem' }}>
                  Score {selectedRepo.latest_posture_score}/100
                </span>
              </div>
              <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                Source code vulnerabilities, leaked secrets, and outdated dependencies.
              </p>
            </div>

            {/* Filter buttons */}
            <div style={{ display: 'flex', gap: '6px' }}>
              {(['all', 'secret', 'sast', 'sca'] as const).map((type) => (
                <button
                  key={type}
                  className={`btn-secondary ${findingTypeFilter === type ? 'active' : ''}`}
                  onClick={() => setFindingTypeFilter(type)}
                  style={{
                    padding: '4px 10px',
                    fontSize: '0.74rem',
                    borderColor: findingTypeFilter === type ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                    color: findingTypeFilter === type ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    textTransform: 'uppercase',
                  }}
                >
                  {type}
                </button>
              ))}
            </div>
          </div>

          {loadingFindings ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <RefreshCw size={20} className="spin" style={{ margin: '0 auto 8px' }} />
              <p style={{ fontSize: '0.8rem' }}>Loading repository findings...</p>
            </div>
          ) : filteredFindings.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
              No findings discovered matching this filter. Run a scan to inspect the codebase.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {filteredFindings.map((f) => (
                <div
                  key={f.id}
                  style={{
                    padding: '14px 16px',
                    borderRadius: '8px',
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <span className={`badge ${f.severity === 'critical' ? 'badge-rose' : f.severity === 'high' ? 'badge-rose' : 'badge-amber'}`}>
                          {f.severity.toUpperCase()}
                        </span>
                        <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                          {f.scan_type.toUpperCase()}
                        </span>
                        {f.cwe && <span className="nav-link-badge" style={{ fontSize: '0.7rem' }}>{f.cwe}</span>}
                        {f.cve && <span className="nav-link-badge" style={{ fontSize: '0.7rem' }}>{f.cve}</span>}
                        <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.88rem' }}>
                          {f.title}
                        </span>
                      </div>

                      <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <FileCode size={13} />
                        <code>{f.file_path}{f.line_number ? `:${f.line_number}` : ''}</code>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className={`badge ${f.status === 'resolved' ? 'badge-emerald' : f.status === 'open' ? 'badge-rose' : 'badge-cyan'}`}>
                        {f.status.replace('_', ' ').toUpperCase()}
                      </span>
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => {
                          setTriageFinding(f);
                          setTriageStatus('resolved');
                          setTriageJustification('');
                          setTriageError(null);
                        }}
                        style={{ padding: '3px 8px', fontSize: '0.72rem' }}
                      >
                        Triage
                      </button>
                    </div>
                  </div>

                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: '8px 0 0' }}>
                    {f.description}
                  </p>

                  {f.snippet && (
                    <pre
                      className="code-block"
                      style={{
                        margin: '8px 0 0',
                        fontSize: '0.74rem',
                        padding: '6px 10px',
                        maxHeight: '100px',
                        overflowX: 'auto',
                      }}
                    >
                      {f.snippet}
                    </pre>
                  )}

                  {f.remediation && (
                    <div style={{ fontSize: '0.74rem', color: 'var(--accent-emerald)', marginTop: '8px' }}>
                      <strong>Remediation: </strong>
                      <span>{f.remediation}</span>
                    </div>
                  )}

                  {f.justification && (
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                      <em>Rationale: {f.justification}</em>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Connect Repo Modal */}
      <ConnectRepoModal
        isOpen={isConnectOpen}
        onClose={() => setIsConnectOpen(false)}
        onRepoCreated={(newRepo) => {
          setRepos((prev) => [newRepo, ...prev]);
          handleSelectRepoToInspect(newRepo);
        }}
      />

      {/* Triage Dialog */}
      {triageFinding && (
        <div className="modal-backdrop">
          <div className="modal-container" style={{ maxWidth: '480px' }}>
            <div className="modal-header">
              <h2 className="modal-title">Triage Finding</h2>
              <button className="modal-close-btn" onClick={() => setTriageFinding(null)}>
                <X size={16} />
              </button>
            </div>
            <div className="modal-form">
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: 0 }}>
                {triageFinding.title} &bull; <code>{triageFinding.file_path}</code>
              </p>

              <div className="form-group">
                <label className="form-label">Resolution Status</label>
                <select
                  className="form-input"
                  value={triageStatus}
                  onChange={(e) => setTriageStatus(e.target.value as any)}
                >
                  <option value="resolved">Resolved</option>
                  <option value="accepted_risk">Accepted Risk</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>

              {(triageStatus === 'accepted_risk' || triageStatus === 'false_positive') && (
                <div className="form-group">
                  <label className="form-label">
                    Justification <span style={{ color: 'var(--accent-rose)' }}>* Required</span>
                  </label>
                  <textarea
                    className="form-input"
                    rows={2}
                    placeholder="Enter security review justification or compensating control..."
                    value={triageJustification}
                    onChange={(e) => setTriageJustification(e.target.value)}
                    required
                  />
                </div>
              )}

              {triageError && (
                <div style={{ color: 'var(--accent-rose)', fontSize: '0.76rem' }}>
                  {triageError}
                </div>
              )}

              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setTriageFinding(null)}>
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn-primary"
                  onClick={handleConfirmTriage}
                  disabled={triageUpdating}
                >
                  {triageUpdating ? 'Saving...' : 'Update Status'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
