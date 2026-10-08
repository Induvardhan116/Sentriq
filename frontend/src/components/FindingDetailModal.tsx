import React, { useState } from 'react';
import { X, ShieldAlert, Terminal, Wrench } from 'lucide-react';
import { Finding, FindingStatus } from '../types/finding';
import { updateFindingStatus } from '../services/api';

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  onStatusChanged: (updated: Finding) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onStatusChanged,
}) => {
  const [updating, setUpdating] = useState(false);

  if (!finding) return null;

  const handleStatusChange = async (newStatus: FindingStatus) => {
    setUpdating(true);
    try {
      const updated = await updateFindingStatus(finding.id, newStatus);
      onStatusChanged(updated);
    } catch (err) {
      console.error('Failed to update status:', err);
    } finally {
      setUpdating(false);
    }
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'badge-rose';
      case 'high':
        return 'badge-rose';
      case 'medium':
        return 'badge-amber';
      case 'low':
        return 'badge-cyan';
      default:
        return 'badge-cyan';
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container" style={{ maxWidth: '680px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-logo-badge" style={{ width: '32px', height: '32px' }}>
              <ShieldAlert size={18} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
                  {finding.severity.toUpperCase()}
                </span>
                <span className="badge badge-cyan">RISK {finding.risk_score}/100</span>
                {finding.cwe && <span className="nav-link-badge">{finding.cwe}</span>}
              </div>
              <h2 className="modal-title" style={{ marginTop: '6px' }}>{finding.title}</h2>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="modal-form" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Metadata Bar */}
          <div className="diagnostic-list" style={{ gridTemplateColumns: 'repeat(3, 1fr)', display: 'grid', gap: '8px' }}>
            <div className="diagnostic-item" style={{ flexDirection: 'column', alignItems: 'flex-start', padding: '8px 12px' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>CATEGORY</span>
              <span style={{ fontWeight: 600, fontSize: '0.82rem' }}>{finding.category}</span>
            </div>
            <div className="diagnostic-item" style={{ flexDirection: 'column', alignItems: 'flex-start', padding: '8px 12px' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>CONFIDENCE</span>
              <span style={{ fontWeight: 600, fontSize: '0.82rem' }}>{Math.round(finding.confidence * 100)}%</span>
            </div>
            <div className="diagnostic-item" style={{ flexDirection: 'column', alignItems: 'flex-start', padding: '8px 12px' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>SOURCE</span>
              <span style={{ fontWeight: 600, fontSize: '0.82rem' }}>{finding.source.toUpperCase()}</span>
            </div>
          </div>

          {/* Endpoint */}
          {finding.endpoint && (
            <div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                Affected Target Endpoint
              </div>
              <div className="code-block" style={{ fontSize: '0.8rem' }}>{finding.endpoint}</div>
            </div>
          )}

          {/* Description */}
          <div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
              Description & Security Impact
            </div>
            <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {finding.description}
            </p>
          </div>

          {/* Evidence */}
          {finding.evidence && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.74rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                <Terminal size={14} />
                <span>Scanner Evidence (Sanitized)</span>
              </div>
              <pre className="code-block" style={{ fontSize: '0.78rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                {finding.evidence}
              </pre>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div style={{ padding: '14px', borderRadius: '8px', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.76rem', color: 'var(--accent-emerald)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
                <Wrench size={14} />
                <span>Recommended Remediation</span>
              </div>
              <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {finding.remediation}
              </p>
            </div>
          )}

          {/* Lifecycle Status Management */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
            <div>
              <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)', display: 'block' }}>RESOLUTION STATUS</span>
              <strong style={{ fontSize: '0.88rem', color: 'var(--text-primary)' }}>{finding.status.toUpperCase()}</strong>
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              {(['open', 'in_progress', 'resolved', 'false_positive'] as FindingStatus[]).map((st) => (
                <button
                  key={st}
                  disabled={updating}
                  className={`btn-secondary ${finding.status === st ? 'active' : ''}`}
                  style={{
                    padding: '6px 10px',
                    fontSize: '0.76rem',
                    borderColor: finding.status === st ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                    color: finding.status === st ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  }}
                  onClick={() => handleStatusChange(st)}
                >
                  {st.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
