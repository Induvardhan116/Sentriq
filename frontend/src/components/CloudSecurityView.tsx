import React, { useEffect, useState, useCallback } from 'react';
import {
  Cloud,
  Plus,
  Play,
  Trash2,
  RefreshCw,
  CheckCircle2,
  Server,
  KeyRound,
  Database,
  Network,
  Filter,
} from 'lucide-react';
import {
  fetchCloudAccounts,
  fetchCloudFindings,
  scanCloudAccount,
  deleteCloudAccount,
  updateCloudFindingStatus,
} from '../services/api';
import { CloudAccount, CloudFinding } from '../types/cloudSecurity';
import { ConnectCloudModal } from './ConnectCloudModal';

export const CloudSecurityView: React.FC = () => {
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<string | null>(null);
  const [findings, setFindings] = useState<CloudFinding[]>([]);

  const [loadingAccounts, setLoadingAccounts] = useState(false);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false);

  // Filters
  const [serviceFilter, setServiceFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Triage state
  const [triageFindingId, setTriageFindingId] = useState<string | null>(null);
  const [triageStatus, setTriageStatus] = useState<string>('resolved');
  const [triageJustification, setTriageJustification] = useState('');
  const [isTriaging, setIsTriaging] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);

  const loadAccounts = useCallback(async () => {
    try {
      setLoadingAccounts(true);
      setError(null);
      const data = await fetchCloudAccounts();
      setAccounts(data);
      if (data.length > 0 && !selectedAccountId) {
        setSelectedAccountId(data[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch cloud accounts');
    } finally {
      setLoadingAccounts(false);
    }
  }, [selectedAccountId]);

  const loadFindings = useCallback(async (accId: string) => {
    try {
      setLoadingFindings(true);
      const data = await fetchCloudFindings(accId);
      setFindings(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch cloud findings');
    } finally {
      setLoadingFindings(false);
    }
  }, []);

  useEffect(() => {
    loadAccounts();
  }, [loadAccounts]);

  useEffect(() => {
    if (selectedAccountId) {
      loadFindings(selectedAccountId);
    } else {
      setFindings([]);
    }
  }, [selectedAccountId, loadFindings]);

  const handleRunScan = async (accId: string) => {
    try {
      setScanning(true);
      setError(null);
      const updated = await scanCloudAccount(accId);
      setAccounts((prev) => prev.map((a) => (a.id === accId ? updated : a)));
      await loadFindings(accId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'CSPM scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleDeleteAccount = async (accId: string) => {
    if (!window.confirm('Are you sure you want to delete this cloud account integration?')) return;
    try {
      await deleteCloudAccount(accId);
      setAccounts((prev) => prev.filter((a) => a.id !== accId));
      if (selectedAccountId === accId) {
        setSelectedAccountId(accounts.find((a) => a.id !== accId)?.id || null);
      }
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete cloud account');
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
      const updated = await updateCloudFindingStatus(triageFindingId, {
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

  const selectedAccount = accounts.find((a) => a.id === selectedAccountId);

  const filteredFindings = findings.filter((f) => {
    if (serviceFilter !== 'all' && f.service !== serviceFilter) return false;
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && f.status !== statusFilter) return false;
    return true;
  });

  const getServiceIcon = (service: string) => {
    switch (service.toLowerCase()) {
      case 'storage':
        return <Server size={14} color="var(--accent-cyan)" />;
      case 'iam':
        return <KeyRound size={14} color="#eab308" />;
      case 'network':
        return <Network size={14} color="#3b82f6" />;
      case 'database':
        return <Database size={14} color="#22c55e" />;
      default:
        return <Cloud size={14} color="var(--text-muted)" />;
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      default:
        return 'badge-low';
    }
  };

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Cloud Security Posture (CSPM)
            </h1>
            <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>
              Phase 8 Active
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
            Read-only configuration compliance auditing for AWS, GCP, and Supabase mapped to CIS benchmarks.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className="btn-secondary"
            onClick={loadAccounts}
            disabled={loadingAccounts}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
          >
            <RefreshCw size={14} className={loadingAccounts ? 'spin' : ''} /> Refresh
          </button>
          <button
            className="btn-primary"
            onClick={() => setIsConnectModalOpen(true)}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
          >
            <Plus size={14} /> Connect Environment
          </button>
        </div>
      </div>

      {error && (
        <div className="surface-card" style={{ padding: '12px 16px', borderLeft: '4px solid var(--accent-rose)', color: 'var(--accent-rose)' }}>
          {error}
        </div>
      )}

      {/* Main Grid: Accounts List (Left) + Detailed Audit Inspector (Right) */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
        {/* Left Column: Account Selector */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Cloud Accounts ({accounts.length})
          </div>

          {loadingAccounts && accounts.length === 0 ? (
            <div className="surface-card" style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading environments...
            </div>
          ) : accounts.length === 0 ? (
            <div className="surface-card" style={{ padding: '24px', textAlign: 'center' }}>
              <Cloud size={32} color="var(--text-muted)" style={{ margin: '0 auto 8px' }} />
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 500, margin: '0 0 6px' }}>
                No cloud accounts connected
              </p>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0 0 14px' }}>
                Connect AWS or Supabase using read-only audit roles to evaluate compliance.
              </p>
              <button
                className="btn-secondary"
                onClick={() => setIsConnectModalOpen(true)}
                style={{ fontSize: '0.78rem', padding: '6px 12px' }}
              >
                Connect Cloud
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {accounts.map((acc) => {
                const isSelected = acc.id === selectedAccountId;
                return (
                  <div
                    key={acc.id}
                    onClick={() => setSelectedAccountId(acc.id)}
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
                        {acc.name}
                      </span>
                      <span
                        className="badge"
                        style={{
                          fontSize: '0.7rem',
                          backgroundColor:
                            acc.posture_score >= 80
                              ? 'rgba(34, 197, 94, 0.15)'
                              : acc.posture_score >= 50
                              ? 'rgba(234, 179, 8, 0.15)'
                              : 'rgba(239, 68, 68, 0.15)',
                          color:
                            acc.posture_score >= 80
                              ? '#22c55e'
                              : acc.posture_score >= 50
                              ? '#eab308'
                              : '#ef4444',
                        }}
                      >
                        {acc.posture_score}/100
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                      <span style={{ textTransform: 'uppercase', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                        {acc.provider}
                      </span>
                      <span>•</span>
                      <span>{acc.region}</span>
                      <span>•</span>
                      <span>{acc.findings_count} findings</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Account Inspector & Findings */}
        <div>
          {selectedAccount ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Account Hero Banner */}
              <div className="surface-card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <h2 style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                        {selectedAccount.name}
                      </h2>
                      <span className="badge badge-cyan" style={{ fontSize: '0.72rem', textTransform: 'uppercase' }}>
                        {selectedAccount.provider}
                      </span>
                      <span className="badge badge-secondary" style={{ fontSize: '0.72rem' }}>
                        {selectedAccount.region}
                      </span>
                      <span className="badge badge-secondary" style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)' }}>
                        {selectedAccount.connection_status || 'Awaiting Live Cloud Credentials'}
                      </span>
                    </div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0, fontFamily: 'monospace' }}>
                      Ref: {selectedAccount.account_identifier} | Role: {selectedAccount.role_arn_or_ref}
                    </p>
                    <div style={{ marginTop: '8px', padding: '6px 10px', borderRadius: '4px', backgroundColor: 'rgba(6, 182, 212, 0.06)', border: '1px solid rgba(6, 182, 212, 0.15)', fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                      <strong>Integration Notice:</strong> {selectedAccount.connection_status || 'Awaiting Live Cloud Credentials'}. Audits reflect CIS Benchmark rules evaluated on cloud resource configurations.
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      className="btn-primary"
                      onClick={() => handleRunScan(selectedAccount.id)}
                      disabled={scanning}
                      style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 14px' }}
                    >
                      <Play size={14} className={scanning ? 'spin' : ''} />
                      {scanning ? 'Auditing CIS Rules...' : 'Run CSPM Scan'}
                    </button>
                    <button
                      className="btn-icon"
                      onClick={() => handleDeleteAccount(selectedAccount.id)}
                      title="Delete account integration"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>

                {/* KPI Metrics Row */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '12px', marginTop: '16px' }}>
                  <div style={{ padding: '10px 14px', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>CIS Posture Score</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: selectedAccount.posture_score >= 80 ? '#22c55e' : selectedAccount.posture_score >= 50 ? '#eab308' : '#ef4444' }}>
                      {selectedAccount.posture_score}%
                    </div>
                  </div>

                  <div style={{ padding: '10px 14px', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Open Compliance Violations</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: findings.length > 0 ? '#ef4444' : '#22c55e' }}>
                      {findings.length}
                    </div>
                  </div>

                  <div style={{ padding: '10px 14px', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Calculated Risk Score</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: selectedAccount.risk_score > 50 ? '#ef4444' : '#eab308' }}>
                      {selectedAccount.risk_score} / 100
                    </div>
                  </div>

                  <div style={{ padding: '10px 14px', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Last Audited</div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '4px' }}>
                      {selectedAccount.last_scanned_at ? new Date(selectedAccount.last_scanned_at).toLocaleDateString() : 'Never'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Filters */}
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  <Filter size={14} /> Filter:
                </div>

                <select
                  value={serviceFilter}
                  onChange={(e) => setServiceFilter(e.target.value)}
                  className="input-field"
                  style={{ padding: '4px 8px', fontSize: '0.78rem' }}
                >
                  <option value="all">All Services</option>
                  <option value="storage">Storage / S3</option>
                  <option value="iam">IAM & Identity</option>
                  <option value="network">Network & Firewalls</option>
                  <option value="database">Database / RLS</option>
                </select>

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

              {/* Findings List */}
              {loadingFindings ? (
                <div className="surface-card" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Loading compliance findings...
                </div>
              ) : filteredFindings.length === 0 ? (
                <div className="surface-card" style={{ padding: '32px', textAlign: 'center' }}>
                  <CheckCircle2 size={32} color="#22c55e" style={{ margin: '0 auto 8px' }} />
                  <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 500, margin: '0 0 4px' }}>
                    No compliance violations detected
                  </p>
                  <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: 0 }}>
                    {selectedAccount.last_scanned_at
                      ? 'All cloud resources satisfy configured CIS benchmarks.'
                      : 'Click "Run CSPM Scan" above to execute the first compliance audit.'}
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
                              {finding.benchmark_ref}
                            </span>
                            <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                              {getServiceIcon(finding.service)}
                              <span style={{ textTransform: 'capitalize' }}>{finding.service}</span>
                            </span>
                            <span style={{ fontSize: '0.78rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                              ({finding.resource_id})
                            </span>
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
          ) : (
            <div className="surface-card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Select a cloud environment from the left panel to inspect CIS compliance findings.
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
                Triage Cloud Compliance Finding
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

      {/* Connect Modal */}
      <ConnectCloudModal
        isOpen={isConnectModalOpen}
        onClose={() => setIsConnectModalOpen(false)}
        onAccountConnected={(newAcc) => {
          setAccounts((prev) => [newAcc, ...prev]);
          setSelectedAccountId(newAcc.id);
        }}
      />
    </div>
  );
};
