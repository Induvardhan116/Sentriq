import React, { useState, useEffect, useCallback } from 'react';
import {
  X,
  ShieldAlert,
  Terminal,
  Wrench,
  History,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  GitBranch,
  Fingerprint as FingerprintIcon,
} from 'lucide-react';
import { Finding, FindingStatus, FindingStatusEvent } from '../types/finding';
import { updateFindingStatus, fetchFindingHistory, fetchFinding } from '../services/api';

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  onStatusChanged: (updated: Finding) => void;
}

const ALL_STATUSES: { key: FindingStatus; label: string; requiresJustification: boolean }[] = [
  { key: 'open', label: 'Open', requiresJustification: false },
  { key: 'in_progress', label: 'In Progress', requiresJustification: false },
  { key: 'resolved', label: 'Resolved', requiresJustification: false },
  { key: 'accepted_risk', label: 'Accepted Risk', requiresJustification: true },
  { key: 'false_positive', label: 'False Positive', requiresJustification: true },
];

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onStatusChanged,
}) => {
  const [currentFinding, setCurrentFinding] = useState<Finding | null>(finding);
  const [history, setHistory] = useState<FindingStatusEvent[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Status transition state
  const [selectedStatus, setSelectedStatus] = useState<FindingStatus | null>(null);
  const [justification, setJustification] = useState('');
  const [updating, setUpdating] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [concurrencyConflict, setConcurrencyConflict] = useState<boolean>(false);
  const [showHistory, setShowHistory] = useState(true);

  // Synchronize when prop changes
  useEffect(() => {
    setCurrentFinding(finding);
    setSelectedStatus(null);
    setJustification('');
    setErrorMessage(null);
    setConcurrencyConflict(false);
  }, [finding]);

  const loadHistory = useCallback(async (findingId: string) => {
    setLoadingHistory(true);
    try {
      const data = await fetchFindingHistory(findingId);
      setHistory(data);
    } catch {
      // History fetch may fail silently if auth is enabled and session expired
      setHistory([]);
    } finally {
      setLoadingHistory(false);
    }
  }, []);

  useEffect(() => {
    if (finding?.id) {
      loadHistory(finding.id);
    }
  }, [finding?.id, loadHistory]);

  if (!currentFinding) return null;

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'badge-rose';
      case 'medium':
        return 'badge-amber';
      case 'low':
      case 'informational':
      default:
        return 'badge-cyan';
    }
  };

  const getStatusBadgeClass = (status: FindingStatus) => {
    switch (status) {
      case 'resolved':
        return 'badge-emerald';
      case 'in_progress':
        return 'badge-amber';
      case 'open':
        return 'badge-rose';
      case 'accepted_risk':
      case 'false_positive':
      default:
        return 'badge-cyan';
    }
  };

  const handleSelectStatusToChange = (newStatus: FindingStatus) => {
    if (newStatus === currentFinding.status) {
      setSelectedStatus(null);
      setJustification('');
      setErrorMessage(null);
      return;
    }
    setSelectedStatus(newStatus);
    setJustification('');
    setErrorMessage(null);
    setConcurrencyConflict(false);
  };

  const handleConfirmStatusChange = async () => {
    if (!selectedStatus) return;

    const requiresJustification =
      selectedStatus === 'accepted_risk' || selectedStatus === 'false_positive';

    if (requiresJustification && !justification.trim()) {
      setErrorMessage(
        `A non-empty justification is mandatory when transitioning finding to '${selectedStatus.replace(
          '_',
          ' '
        )}'.`
      );
      return;
    }

    setUpdating(true);
    setErrorMessage(null);
    setConcurrencyConflict(false);

    try {
      const updated = await updateFindingStatus(
        currentFinding.id,
        selectedStatus,
        justification.trim() || undefined,
        currentFinding.version
      );
      setCurrentFinding(updated);
      setSelectedStatus(null);
      setJustification('');
      onStatusChanged(updated);
      // Reload history to reflect the new immutable event
      loadHistory(updated.id);
    } catch (err: unknown) {
      const errorStr = err instanceof Error ? err.message : String(err);
      if (errorStr.toLowerCase().includes('concurrency') || errorStr.includes('409')) {
        setConcurrencyConflict(true);
        setErrorMessage(
          'Concurrency Conflict: Finding was modified in another session. Refetching latest state...'
        );
        // Refetch latest finding to synchronize version
        try {
          const fresh = await fetchFinding(currentFinding.id);
          setCurrentFinding(fresh);
          onStatusChanged(fresh);
          loadHistory(fresh.id);
        } catch {
          // ignore refetch failure
        }
      } else {
        setErrorMessage(errorStr || 'Failed to update finding status');
      }
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div
        className="modal-container"
        style={{ maxWidth: '780px', maxHeight: '90vh', overflowY: 'auto' }}
      >
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-logo-badge" style={{ width: '34px', height: '34px' }}>
              <ShieldAlert size={18} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span className={`badge ${getSeverityBadgeClass(currentFinding.severity)}`}>
                  {currentFinding.severity.toUpperCase()}
                </span>
                <span className="badge badge-cyan">RISK {currentFinding.risk_score}/100</span>
                <span className={`badge ${getStatusBadgeClass(currentFinding.status)}`}>
                  {currentFinding.status.replace('_', ' ').toUpperCase()}
                </span>
                <span
                  className="nav-link-badge"
                  title="Optimistic Concurrency Control Version"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                >
                  <GitBranch size={11} />
                  v{currentFinding.version || 1}
                </span>
                {currentFinding.cwe && <span className="nav-link-badge">{currentFinding.cwe}</span>}
              </div>
              <h2 className="modal-title" style={{ marginTop: '6px', fontSize: '1.15rem' }}>
                {currentFinding.title}
              </h2>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            <X size={18} />
          </button>
        </div>

        <div className="modal-form" style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Metadata Grid */}
          <div
            className="diagnostic-list"
            style={{ gridTemplateColumns: 'repeat(4, 1fr)', display: 'grid', gap: '8px' }}
          >
            <div className="diagnostic-item" style={{ flexDirection: 'column', alignItems: 'flex-start', padding: '8px 12px' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>CATEGORY</span>
              <span style={{ fontWeight: 600, fontSize: '0.82rem' }}>{currentFinding.category}</span>
            </div>
            <div className="diagnostic-item" style={{ flexDirection: 'column', alignItems: 'flex-start', padding: '8px 12px' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>CONFIDENCE</span>
              <span style={{ fontWeight: 600, fontSize: '0.82rem' }}>{Math.round(currentFinding.confidence * 100)}%</span>
            </div>
            <div className="diagnostic-item" style={{ flexDirection: 'column', alignItems: 'flex-start', padding: '8px 12px' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SOURCE</span>
              <span style={{ fontWeight: 600, fontSize: '0.82rem' }}>{currentFinding.source.toUpperCase()}</span>
            </div>
            <div className="diagnostic-item" style={{ flexDirection: 'column', alignItems: 'flex-start', padding: '8px 12px' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>LAST UPDATED</span>
              <span style={{ fontWeight: 600, fontSize: '0.78rem' }}>
                {new Date(currentFinding.updated_at).toLocaleDateString()}
              </span>
            </div>
          </div>

          {/* Project or Asset Context */}
          {(currentFinding.project_name || currentFinding.target_url) && (
            <div style={{ display: 'flex', gap: '16px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              {currentFinding.project_name && (
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Project: </span>
                  <strong style={{ color: 'var(--text-primary)' }}>{currentFinding.project_name}</strong>
                </div>
              )}
              {currentFinding.target_url && (
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Target: </span>
                  <span className="code-block" style={{ padding: '2px 6px', fontSize: '0.75rem' }}>
                    {currentFinding.target_url}
                  </span>
                </div>
              )}
            </div>
          )}

          {/* Affected Endpoint */}
          {currentFinding.endpoint && (
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                Affected Target Endpoint
              </div>
              <div className="code-block" style={{ fontSize: '0.8rem' }}>{currentFinding.endpoint}</div>
            </div>
          )}

          {/* Fingerprint */}
          {currentFinding.fingerprint && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              <FingerprintIcon size={13} />
              <span>Deduplication Fingerprint: </span>
              <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                {currentFinding.fingerprint}
              </code>
            </div>
          )}

          {/* Description & Impact */}
          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
              Description & Security Impact
            </div>
            <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {currentFinding.description}
            </p>
          </div>

          {/* Scanner Evidence */}
          {currentFinding.evidence && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                <Terminal size={14} />
                <span>Scanner Evidence (Sanitized)</span>
              </div>
              <pre className="code-block" style={{ fontSize: '0.78rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: '160px', overflowY: 'auto' }}>
                {currentFinding.evidence}
              </pre>
            </div>
          )}

          {/* Recommended Remediation */}
          {currentFinding.remediation && (
            <div style={{ padding: '14px', borderRadius: '8px', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.74rem', color: 'var(--accent-emerald)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
                <Wrench size={14} />
                <span>Recommended Remediation</span>
              </div>
              <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {currentFinding.remediation}
              </p>
            </div>
          )}

          {/* Triage & Status Transition Section */}
          <div
            style={{
              padding: '16px',
              borderRadius: '8px',
              backgroundColor: 'rgba(6, 182, 212, 0.03)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
              <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Triage & Resolution Lifecycle
              </span>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                OCC Version {currentFinding.version || 1}
              </span>
            </div>

            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {ALL_STATUSES.map((st) => {
                const isCurrent = currentFinding.status === st.key;
                const isSelected = selectedStatus === st.key;
                return (
                  <button
                    key={st.key}
                    type="button"
                    disabled={updating}
                    className={`btn-secondary ${isCurrent ? 'active' : ''}`}
                    style={{
                      padding: '6px 12px',
                      fontSize: '0.76rem',
                      borderColor: isSelected
                        ? 'var(--accent-cyan)'
                        : isCurrent
                        ? 'var(--text-secondary)'
                        : 'var(--border-subtle)',
                      backgroundColor: isSelected ? 'rgba(6, 182, 212, 0.15)' : undefined,
                      color: isSelected
                        ? 'var(--accent-cyan)'
                        : isCurrent
                        ? '#fff'
                        : 'var(--text-secondary)',
                    }}
                    onClick={() => handleSelectStatusToChange(st.key)}
                  >
                    {isCurrent && <CheckCircle2 size={12} style={{ marginRight: '4px' }} />}
                    {st.label}
                  </button>
                );
              })}
            </div>

            {/* Transition Justification Form */}
            {selectedStatus && (
              <div
                style={{
                  marginTop: '14px',
                  padding: '12px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <span style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Transitioning: {currentFinding.status.toUpperCase()} &rarr; {selectedStatus.toUpperCase()}
                  </span>
                  {(selectedStatus === 'accepted_risk' || selectedStatus === 'false_positive') && (
                    <span style={{ fontSize: '0.7rem', color: 'var(--accent-rose)', fontWeight: 600 }}>
                      * Justification is mandatory
                    </span>
                  )}
                </div>

                <textarea
                  className="form-input"
                  rows={2}
                  placeholder={
                    selectedStatus === 'accepted_risk'
                      ? 'Specify why this risk is accepted (e.g., compensating controls, scheduled deprecation)...'
                      : selectedStatus === 'false_positive'
                      ? 'Specify verification rationale for false positive status...'
                      : 'Optional triage notes or resolution details...'
                  }
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  style={{ width: '100%', fontSize: '0.8rem', resize: 'vertical' }}
                />

                {errorMessage && (
                  <div
                    style={{
                      marginTop: '8px',
                      padding: '8px 12px',
                      borderRadius: '6px',
                      backgroundColor: concurrencyConflict ? 'rgba(245, 158, 11, 0.1)' : 'rgba(244, 63, 94, 0.1)',
                      border: `1px solid ${concurrencyConflict ? 'rgba(245, 158, 11, 0.3)' : 'rgba(244, 63, 94, 0.3)'}`,
                      color: concurrencyConflict ? 'var(--accent-amber)' : 'var(--accent-rose)',
                      fontSize: '0.76rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    <AlertTriangle size={14} />
                    <span>{errorMessage}</span>
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '10px' }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    style={{ padding: '5px 10px', fontSize: '0.76rem' }}
                    onClick={() => {
                      setSelectedStatus(null);
                      setJustification('');
                      setErrorMessage(null);
                    }}
                    disabled={updating}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    style={{ padding: '5px 12px', fontSize: '0.76rem' }}
                    onClick={handleConfirmStatusChange}
                    disabled={
                      updating ||
                      ((selectedStatus === 'accepted_risk' || selectedStatus === 'false_positive') &&
                        !justification.trim())
                    }
                  >
                    {updating ? 'Updating...' : 'Confirm Status Change'}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Chronological Audit Trail History */}
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '14px' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
                marginBottom: '10px',
              }}
              onClick={() => setShowHistory((prev) => !prev)}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <History size={15} color="var(--accent-cyan)" />
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Lifecycle Audit History ({history.length})
                </span>
                {loadingHistory && <RefreshCw size={12} className="spin" />}
              </div>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                {showHistory ? 'Collapse' : 'Expand'}
              </span>
            </div>

            {showHistory && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {history.length === 0 ? (
                  <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    {loadingHistory ? 'Loading history...' : 'No status transitions recorded yet. Finding in initial state.'}
                  </p>
                ) : (
                  history.map((evt) => (
                    <div
                      key={evt.id}
                      style={{
                        padding: '10px 12px',
                        borderRadius: '6px',
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border-subtle)',
                        fontSize: '0.76rem',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '4px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span className="badge badge-cyan" style={{ fontSize: '0.68rem', padding: '1px 6px' }}>
                            {evt.previous_status.toUpperCase()}
                          </span>
                          <span style={{ color: 'var(--text-muted)' }}>&rarr;</span>
                          <span className="badge badge-emerald" style={{ fontSize: '0.68rem', padding: '1px 6px' }}>
                            {evt.new_status.toUpperCase()}
                          </span>
                        </div>
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                          {new Date(evt.created_at).toLocaleString()}
                        </span>
                      </div>
                      {evt.justification && (
                        <div style={{ color: 'var(--text-secondary)', marginTop: '2px' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Rationale: </span>
                          <span>{evt.justification}</span>
                        </div>
                      )}
                      {evt.user_email && (
                        <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                          Actor: {evt.user_email}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
