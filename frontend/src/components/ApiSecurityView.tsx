import React, { useEffect, useState, useCallback } from 'react';
import {
  FileCode2,
  Plus,
  Trash2,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Unlock,
  Layers,
  Filter,
} from 'lucide-react';
import {
  fetchApiSpecs,
  fetchApiEndpoints,
  fetchApiFindings,
  deleteApiSpec,
  updateApiFindingStatus,
} from '../services/api';
import { ApiSpec, ApiEndpoint, ApiFinding } from '../types/apiSecurity';
import { ImportSpecModal } from './ImportSpecModal';

export const ApiSecurityView: React.FC = () => {
  const [specs, setSpecs] = useState<ApiSpec[]>([]);
  const [selectedSpecId, setSelectedSpecId] = useState<string | null>(null);
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [findings, setFindings] = useState<ApiFinding[]>([]);
  const [activeTab, setActiveTab] = useState<'findings' | 'endpoints'>('findings');

  const [loadingSpecs, setLoadingSpecs] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);

  // Filters for findings
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Triage state
  const [triageFindingId, setTriageFindingId] = useState<string | null>(null);
  const [triageStatus, setTriageStatus] = useState<string>('resolved');
  const [triageJustification, setTriageJustification] = useState('');
  const [isTriaging, setIsTriaging] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);

  const loadSpecs = useCallback(async () => {
    try {
      setLoadingSpecs(true);
      setError(null);
      const data = await fetchApiSpecs();
      setSpecs(data);
      if (data.length > 0 && !selectedSpecId) {
        setSelectedSpecId(data[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch API specifications');
    } finally {
      setLoadingSpecs(false);
    }
  }, [selectedSpecId]);

  const loadSpecDetails = useCallback(async (specId: string) => {
    try {
      setLoadingDetails(true);
      const [eps, fnds] = await Promise.all([
        fetchApiEndpoints(specId),
        fetchApiFindings(specId),
      ]);
      setEndpoints(eps);
      setFindings(fnds);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch specification details');
    } finally {
      setLoadingDetails(false);
    }
  }, []);

  useEffect(() => {
    loadSpecs();
  }, [loadSpecs]);

  useEffect(() => {
    if (selectedSpecId) {
      loadSpecDetails(selectedSpecId);
    } else {
      setEndpoints([]);
      setFindings([]);
    }
  }, [selectedSpecId, loadSpecDetails]);

  const handleDeleteSpec = async (specId: string) => {
    if (!window.confirm('Are you sure you want to delete this API specification?')) return;
    try {
      await deleteApiSpec(specId);
      setSpecs((prev) => prev.filter((s) => s.id !== specId));
      if (selectedSpecId === specId) {
        setSelectedSpecId(specs.find((s) => s.id !== specId)?.id || null);
      }
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete API specification');
    }
  };

  const handleApplyTriage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!triageFindingId) return;

    if (
      (triageStatus === 'accepted_risk' || triageStatus === 'false_positive') &&
      triageJustification.trim().length < 10
    ) {
      setTriageError('A detailed justification of at least 10 characters is required for risk acceptance or false positives.');
      return;
    }

    try {
      setIsTriaging(true);
      setTriageError(null);
      const updated = await updateApiFindingStatus(triageFindingId, {
        status: triageStatus as 'open' | 'resolved' | 'false_positive' | 'accepted_risk',
        justification: triageJustification.trim() || undefined,
      });

      setFindings((prev) =>
        prev.map((f) => (f.id === triageFindingId ? { ...f, status: updated.status, justification: updated.justification } : f))
      );
      setTriageFindingId(null);
      setTriageJustification('');
    } catch (err) {
      setTriageError(err instanceof Error ? err.message : 'Failed to update finding status');
    } finally {
      setIsTriaging(false);
    }
  };

  const selectedSpec = specs.find((s) => s.id === selectedSpecId);

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && f.status !== statusFilter) return false;
    return true;
  });

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      case 'low':
        return 'badge-low';
      default:
        return 'badge-info';
    }
  };

  const getMethodBadgeStyle = (method: string) => {
    const m = method.toUpperCase();
    if (m === 'GET') return { backgroundColor: 'rgba(34, 197, 94, 0.15)', color: '#22c55e' };
    if (m === 'POST') return { backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6' };
    if (m === 'PUT') return { backgroundColor: 'rgba(234, 179, 8, 0.15)', color: '#eab308' };
    if (m === 'DELETE') return { backgroundColor: 'rgba(239, 68, 68, 0.15)', color: '#ef4444' };
    return { backgroundColor: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8' };
  };

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              API Security Assessment
            </h1>
            <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>
              Phase 7 Active
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
            Autonomous OpenAPI 3.0 & Swagger schema analysis, route discovery, and OWASP API Top 10 vulnerability detection.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className="btn-secondary"
            onClick={loadSpecs}
            disabled={loadingSpecs}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
          >
            <RefreshCw size={14} className={loadingSpecs ? 'spin' : ''} /> Refresh
          </button>
          <button
            className="btn-primary"
            onClick={() => setIsImportModalOpen(true)}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
          >
            <Plus size={14} /> Import Specification
          </button>
        </div>
      </div>

      {error && (
        <div className="surface-card" style={{ padding: '12px 16px', borderLeft: '4px solid var(--accent-rose)', color: 'var(--accent-rose)' }}>
          {error}
        </div>
      )}

      {/* Main Grid: Spec List (Left) + Detailed Inspector (Right) */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
        {/* Left Column: Spec Selector */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            API Specifications ({specs.length})
          </div>

          {loadingSpecs && specs.length === 0 ? (
            <div className="surface-card" style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading specifications...
            </div>
          ) : specs.length === 0 ? (
            <div className="surface-card" style={{ padding: '24px', textAlign: 'center' }}>
              <FileCode2 size={32} color="var(--text-muted)" style={{ margin: '0 auto 8px' }} />
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 500, margin: '0 0 6px' }}>
                No API specs imported
              </p>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0 0 14px' }}>
                Import an OpenAPI or Swagger schema to audit API security posture.
              </p>
              <button
                className="btn-secondary"
                onClick={() => setIsImportModalOpen(true)}
                style={{ fontSize: '0.78rem', padding: '6px 12px' }}
              >
                Import Schema
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {specs.map((spec) => {
                const isSelected = spec.id === selectedSpecId;
                return (
                  <div
                    key={spec.id}
                    onClick={() => setSelectedSpecId(spec.id)}
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
                        {spec.title}
                      </span>
                      <span
                        className="badge"
                        style={{
                          fontSize: '0.7rem',
                          backgroundColor:
                            spec.posture_score >= 80
                              ? 'rgba(34, 197, 94, 0.15)'
                              : spec.posture_score >= 50
                              ? 'rgba(234, 179, 8, 0.15)'
                              : 'rgba(239, 68, 68, 0.15)',
                          color:
                            spec.posture_score >= 80
                              ? '#22c55e'
                              : spec.posture_score >= 50
                              ? '#eab308'
                              : '#ef4444',
                        }}
                      >
                        {spec.posture_score}/100
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                      <span>v{spec.version}</span>
                      <span>•</span>
                      <span>{spec.endpoint_count} endpoints</span>
                      <span>•</span>
                      <span style={{ textTransform: 'uppercase' }}>{spec.spec_format}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Spec Details & Findings */}
        <div>
          {selectedSpec ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Spec Hero Banner */}
              <div className="surface-card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <h2 style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                        {selectedSpec.title}
                      </h2>
                      <span className="badge badge-secondary" style={{ fontSize: '0.72rem' }}>
                        v{selectedSpec.version}
                      </span>
                      <span className="badge badge-cyan" style={{ fontSize: '0.72rem', textTransform: 'uppercase' }}>
                        {selectedSpec.spec_format}
                      </span>
                    </div>
                    {selectedSpec.base_url && (
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0, fontFamily: 'monospace' }}>
                        {selectedSpec.base_url}
                      </p>
                    )}
                  </div>

                  <button
                    className="btn-icon"
                    onClick={() => handleDeleteSpec(selectedSpec.id)}
                    title="Delete specification"
                    style={{ color: 'var(--text-muted)' }}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>

                {/* Score & Metrics Row */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '12px', marginTop: '16px' }}>
                  <div style={{ padding: '10px 14px', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Posture Score</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: selectedSpec.posture_score >= 80 ? '#22c55e' : selectedSpec.posture_score >= 50 ? '#eab308' : '#ef4444' }}>
                      {selectedSpec.posture_score}%
                    </div>
                  </div>

                  <div style={{ padding: '10px 14px', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Discovered Endpoints</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {selectedSpec.endpoint_count}
                    </div>
                  </div>

                  <div style={{ padding: '10px 14px', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Vulnerabilities</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: findings.length > 0 ? '#ef4444' : '#22c55e' }}>
                      {findings.length}
                    </div>
                  </div>

                  <div style={{ padding: '10px 14px', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Score</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: selectedSpec.risk_score > 60 ? '#ef4444' : '#eab308' }}>
                      {selectedSpec.risk_score} / 100
                    </div>
                  </div>
                </div>
              </div>

              {/* Sub-Tabs: Findings vs Endpoints */}
              <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                <button
                  className={`btn-tab ${activeTab === 'findings' ? 'active' : ''}`}
                  onClick={() => setActiveTab('findings')}
                  style={{
                    background: 'none',
                    border: 'none',
                    borderBottom: activeTab === 'findings' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                    color: activeTab === 'findings' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    padding: '6px 14px',
                    cursor: 'pointer',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <AlertTriangle size={15} />
                  <span>Vulnerabilities ({findings.length})</span>
                </button>
                <button
                  className={`btn-tab ${activeTab === 'endpoints' ? 'active' : ''}`}
                  onClick={() => setActiveTab('endpoints')}
                  style={{
                    background: 'none',
                    border: 'none',
                    borderBottom: activeTab === 'endpoints' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                    color: activeTab === 'endpoints' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    padding: '6px 14px',
                    cursor: 'pointer',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <Layers size={15} />
                  <span>Endpoint Inventory ({endpoints.length})</span>
                </button>
              </div>

              {/* Tab 1: Findings */}
              {activeTab === 'findings' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  {/* Filters */}
                  <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      <Filter size={14} /> Filter:
                    </div>
                    <select
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value)}
                      className="input-field"
                      style={{ padding: '4px 8px', fontSize: '0.78rem' }}
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>

                    <select
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value)}
                      className="input-field"
                      style={{ padding: '4px 8px', fontSize: '0.78rem' }}
                    >
                      <option value="all">All Statuses</option>
                      <option value="open">Open</option>
                      <option value="resolved">Resolved</option>
                      <option value="accepted_risk">Accepted Risk</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </div>

                  {loadingDetails ? (
                    <div className="surface-card" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      Loading vulnerabilities...
                    </div>
                  ) : filteredFindings.length === 0 ? (
                    <div className="surface-card" style={{ padding: '32px', textAlign: 'center' }}>
                      <CheckCircle2 size={32} color="#22c55e" style={{ margin: '0 auto 8px' }} />
                      <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 500, margin: '0 0 4px' }}>
                        No vulnerabilities found matching filters
                      </p>
                      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: 0 }}>
                        All endpoints adhere to configured OWASP API Top 10 security standards.
                      </p>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {filteredFindings.map((finding) => (
                        <div
                          key={finding.id}
                          className="surface-card"
                          style={{
                            padding: '16px',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '10px',
                            borderLeft: `4px solid ${
                              finding.severity === 'critical'
                                ? '#ef4444'
                                : finding.severity === 'high'
                                ? '#f97316'
                                : '#eab308'
                            }`,
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
                            <div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                                <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
                                  {finding.severity.toUpperCase()}
                                </span>
                                <span className="badge badge-secondary" style={{ fontSize: '0.72rem' }}>
                                  {finding.owasp_category}
                                </span>
                                {finding.method && (
                                  <span
                                    style={{
                                      fontSize: '0.72rem',
                                      fontWeight: 700,
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      ...getMethodBadgeStyle(finding.method),
                                    }}
                                  >
                                    {finding.method}
                                  </span>
                                )}
                                {finding.path && (
                                  <span style={{ fontSize: '0.8rem', fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                                    {finding.path}
                                  </span>
                                )}
                              </div>
                              <h4 style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                                {finding.title}
                              </h4>
                            </div>

                            <button
                              className="btn-secondary"
                              onClick={() => {
                                setTriageFindingId(finding.id);
                                setTriageStatus(finding.status === 'open' ? 'resolved' : finding.status);
                                setTriageJustification(finding.justification || '');
                                setTriageError(null);
                              }}
                              style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                            >
                              Triage ({finding.status})
                            </button>
                          </div>

                          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: 0 }}>
                            {finding.description}
                          </p>

                          {finding.remediation && (
                            <div style={{ padding: '8px 12px', backgroundColor: 'rgba(6, 182, 212, 0.05)', borderRadius: '6px', fontSize: '0.78rem', color: 'var(--accent-cyan)' }}>
                              <strong>Remediation:</strong> {finding.remediation}
                            </div>
                          )}

                          {finding.justification && (
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                              Justification: {finding.justification}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: Endpoints Inventory */}
              {activeTab === 'endpoints' && (
                <div className="surface-card" style={{ padding: 0, overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border-color)', backgroundColor: 'rgba(255, 255, 255, 0.02)' }}>
                        <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Method</th>
                        <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Endpoint Path</th>
                        <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Authentication</th>
                        <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Summary</th>
                      </tr>
                    </thead>
                    <tbody>
                      {endpoints.map((ep) => (
                        <tr key={ep.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                          <td style={{ padding: '10px 14px' }}>
                            <span
                              style={{
                                fontSize: '0.72rem',
                                fontWeight: 700,
                                padding: '2px 6px',
                                borderRadius: '4px',
                                ...getMethodBadgeStyle(ep.method),
                              }}
                            >
                              {ep.method}
                            </span>
                          </td>
                          <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                            {ep.path}
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {ep.auth_required ? (
                              <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#22c55e', fontSize: '0.78rem' }}>
                                <Lock size={12} /> {ep.auth_type}
                              </span>
                            ) : (
                              <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#ef4444', fontSize: '0.78rem' }}>
                                <Unlock size={12} /> None
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '10px 14px', color: 'var(--text-secondary)' }}>
                            {ep.summary || '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ) : (
            <div className="surface-card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Select an API specification from the left panel to inspect discovered routes and vulnerability findings.
            </div>
          )}
        </div>
      </div>

      {/* Triage Modal */}
      {triageFindingId && (
        <div className="modal-backdrop" onClick={() => setTriageFindingId(null)}>
          <div className="modal-card" style={{ maxWidth: '480px', width: '100%' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Triage API Vulnerability
              </h3>
            </div>
            <form onSubmit={handleApplyTriage} style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {triageError && (
                <div style={{ padding: '8px 12px', borderRadius: '4px', backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', fontSize: '0.8rem' }}>
                  {triageError}
                </div>
              )}

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Status
                </label>
                <select
                  value={triageStatus}
                  onChange={(e) => setTriageStatus(e.target.value)}
                  className="input-field"
                  style={{ width: '100%' }}
                >
                  <option value="open">Open</option>
                  <option value="resolved">Resolved</option>
                  <option value="accepted_risk">Accepted Risk</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Justification / Remediation Notes {(triageStatus === 'accepted_risk' || triageStatus === 'false_positive') && '*'}
                </label>
                <textarea
                  value={triageJustification}
                  onChange={(e) => setTriageJustification(e.target.value)}
                  rows={4}
                  placeholder="Explain why this risk is accepted or marked as false positive..."
                  className="input-field"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                <button type="button" className="btn-secondary" onClick={() => setTriageFindingId(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={isTriaging}>
                  {isTriaging ? 'Saving...' : 'Update Status'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Import Modal */}
      <ImportSpecModal
        isOpen={isImportModalOpen}
        onClose={() => setIsImportModalOpen(false)}
        onSpecImported={(newSpec) => {
          setSpecs((prev) => [newSpec, ...prev]);
          setSelectedSpecId(newSpec.id);
        }}
      />
    </div>
  );
};
