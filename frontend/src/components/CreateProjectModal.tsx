import React, { useState } from 'react';
import { X, ShieldCheck, AlertCircle, Globe, Lock } from 'lucide-react';
import { createProject } from '../services/api';
import { Project } from '../types/project';
import { useAuth } from '../context/AuthContext';

interface CreateProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onProjectCreated: (project: Project) => void;
}

export const CreateProjectModal: React.FC<CreateProjectModalProps> = ({
  isOpen,
  onClose,
  onProjectCreated,
}) => {
  const { user } = useAuth();
  const isUnverified = Boolean(user && user.is_verified === false);
  const [name, setName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authorizationConfirmed) {
      setError('You must explicitly confirm target authorization to proceed.');
      return;
    }
    setError(null);
    setLoading(true);

    try {
      const newProj = await createProject({
        name: name.trim(),
        target_url: targetUrl.trim(),
        authorization_confirmed: true,
      });
      setName('');
      setTargetUrl('');
      setAuthorizationConfirmed(false);
      onProjectCreated(newProj);
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create security project');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container">
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-logo-badge" style={{ width: '32px', height: '32px' }}>
              <ShieldCheck size={18} />
            </div>
            <div>
              <h2 className="modal-title">New Security Assessment Project</h2>
              <p className="modal-subtitle">Define an authorized website target for defensive assessment.</p>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {isUnverified && (
          <div
            style={{
              backgroundColor: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.35)',
              borderRadius: '8px',
              padding: '12px 14px',
              margin: '16px 24px 0 24px',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              fontSize: '0.82rem',
              color: '#fbbf24',
            }}
          >
            <AlertCircle size={18} style={{ flexShrink: 0, marginTop: '2px', color: '#f59e0b' }} />
            <div>
              <strong style={{ display: 'block', color: '#fef3c7', marginBottom: '2px' }}>
                Account Email Not Verified
              </strong>
              Creating new assessment projects and triggering scans requires a verified email address. Please check your inbox for the verification link or use the resend button at the top of the dashboard.
            </div>
          </div>
        )}

        {error && (
          <div className="alert-box-error">
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="modal-form">
          <div className="form-group">
            <label className="form-label">Project Name</label>
            <input
              type="text"
              required
              className="form-input"
              placeholder="e.g. Production Web App, Demo E-Commerce"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Target Website URL</label>
            <div style={{ position: 'relative' }}>
              <Globe
                size={16}
                color="var(--text-muted)"
                style={{ position: 'absolute', left: '12px', top: '12px' }}
              />
              <input
                type="text"
                required
                className="form-input"
                style={{ paddingLeft: '38px' }}
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
              />
            </div>
            <span className="form-hint">
              Only HTTP/HTTPS protocols are permitted. Private, loopback, and metadata targets are strictly blocked.
            </span>
          </div>

          <div className="authorization-card">
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
              <input
                type="checkbox"
                id="auth-checkbox"
                required
                checked={authorizationConfirmed}
                onChange={(e) => setAuthorizationConfirmed(e.target.checked)}
                style={{ marginTop: '3px', cursor: 'pointer' }}
              />
              <label htmlFor="auth-checkbox" style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <strong style={{ color: 'var(--text-primary)', display: 'block', marginBottom: '2px' }}>
                  Target Authorization Confirmation (Mandatory)
                </strong>
                I confirm that I own this application or have explicit authorization from the owner to conduct defensive, safe security testing.
              </label>
            </div>
          </div>

          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary"
              disabled={loading || !name || !targetUrl || !authorizationConfirmed || isUnverified}
            >
              <Lock size={14} />
              <span>{loading ? 'Creating Target...' : isUnverified ? 'Verification Required' : 'Create Project'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
