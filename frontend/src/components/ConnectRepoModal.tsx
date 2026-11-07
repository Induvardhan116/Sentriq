import React, { useState } from 'react';
import { X, GitBranch, AlertTriangle } from 'lucide-react';
import { RepositoryCreate, Repository } from '../types/repository';
import { createRepository } from '../services/api';

interface ConnectRepoModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRepoCreated: (repo: Repository) => void;
}

export const ConnectRepoModal: React.FC<ConnectRepoModalProps> = ({
  isOpen,
  onClose,
  onRepoCreated,
}) => {
  const [name, setName] = useState('');
  const [fullName, setFullName] = useState('');
  const [cloneUrl, setCloneUrl] = useState('');
  const [defaultBranch, setDefaultBranch] = useState('main');
  const [languages, setLanguages] = useState('TypeScript, Python');
  const [isPrivate, setIsPrivate] = useState(false);
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !fullName.trim() || !cloneUrl.trim()) {
      setError('Please provide a repository name, full name, and HTTPS clone URL.');
      return;
    }

    if (!cloneUrl.startsWith('https://')) {
      setError('Clone URL must use the HTTPS protocol for secure transmission.');
      return;
    }

    if (!authConfirmed) {
      setError('You must explicitly confirm repository ownership or authorization.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const payload: RepositoryCreate = {
        name: name.trim(),
        full_name: fullName.trim(),
        clone_url: cloneUrl.trim(),
        default_branch: defaultBranch.trim() || 'main',
        languages: languages.trim() || undefined,
        is_private: isPrivate,
        authorization_confirmed: true,
      };

      const newRepo = await createRepository(payload);
      onRepoCreated(newRepo);
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to register repository';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container" style={{ maxWidth: '580px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-logo-badge" style={{ width: '34px', height: '34px' }}>
              <GitBranch size={18} color="var(--accent-cyan)" />
            </div>
            <div>
              <h2 className="modal-title">Connect Source Code Repository</h2>
              <p className="modal-subtitle">
                Configure a Git repository target for Secret Detection, SAST, and SCA auditing.
              </p>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-form">
          {error && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '8px',
                backgroundColor: 'rgba(244, 63, 94, 0.1)',
                border: '1px solid rgba(244, 63, 94, 0.3)',
                color: 'var(--accent-rose)',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <AlertTriangle size={15} />
              <span>{error}</span>
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Repository Display Name</label>
            <input
              type="text"
              className="form-input"
              placeholder="e.g., Sentriq Core Platform"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">Full Identifier (org/repo)</label>
            <input
              type="text"
              className="form-input"
              placeholder="e.g., sentriq-org/sentriq"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">HTTPS Clone URL</label>
            <input
              type="url"
              className="form-input"
              placeholder="https://github.com/sentriq-org/sentriq.git"
              value={cloneUrl}
              onChange={(e) => setCloneUrl(e.target.value)}
              required
            />
            <span className="form-hint">SSRF-protected: Private subnets and cloud metadata are strictly blocked.</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div className="form-group">
              <label className="form-label">Default Branch</label>
              <input
                type="text"
                className="form-input"
                placeholder="main"
                value={defaultBranch}
                onChange={(e) => setDefaultBranch(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Languages</label>
              <input
                type="text"
                className="form-input"
                placeholder="TypeScript, Python"
                value={languages}
                onChange={(e) => setLanguages(e.target.value)}
              />
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <input
                type="checkbox"
                checked={isPrivate}
                onChange={(e) => setIsPrivate(e.target.checked)}
              />
              <span>Private Repository (Requires authenticated credentials in CI/CD)</span>
            </label>
          </div>

          <div className="authorization-card" style={{ marginTop: '8px' }}>
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              <input
                type="checkbox"
                checked={authConfirmed}
                onChange={(e) => setAuthConfirmed(e.target.checked)}
                style={{ marginTop: '3px' }}
                required
              />
              <span>
                <strong style={{ color: 'var(--text-primary)' }}>Authorization Confirmation: </strong>
                I confirm that I am authorized to assess this repository. Sentriq will perform non-destructive Secret Detection, SAST analysis, and dependency audits.
              </span>
            </label>
          </div>

          <div className="modal-actions" style={{ marginTop: '12px' }}>
            <button type="button" className="btn-secondary" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={loading || !authConfirmed}>
              {loading ? 'Connecting...' : 'Connect Repository'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
