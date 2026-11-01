import React, { useState, useEffect } from 'react';
import { X, Globe, Save, AlertCircle, Edit3 } from 'lucide-react';
import { updateProject } from '../services/api';
import { Project } from '../types/project';

interface EditProjectModalProps {
  project: Project | null;
  isOpen: boolean;
  onClose: () => void;
  onProjectUpdated: (updatedProject: Project) => void;
}

export const EditProjectModal: React.FC<EditProjectModalProps> = ({
  project,
  isOpen,
  onClose,
  onProjectUpdated,
}) => {
  const [name, setName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (project) {
      setName(project.name);
      setTargetUrl(project.target_url);
      setError(null);
    }
  }, [project, isOpen]);

  if (!isOpen || !project) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedName = name.trim();
    const trimmedUrl = targetUrl.trim();

    if (trimmedName.length < 2) {
      setError('Project name must be at least 2 characters long.');
      return;
    }
    if (!trimmedUrl) {
      setError('Target website URL is required.');
      return;
    }

    // If no changes were made, simply close
    if (trimmedName === project.name && trimmedUrl === project.target_url) {
      onClose();
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const updated = await updateProject(project.id, {
        name: trimmedName,
        target_url: trimmedUrl,
      });
      onProjectUpdated(updated);
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update security project.');
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
              <Edit3 size={17} />
            </div>
            <div>
              <h2 className="modal-title">Edit Security Target Project</h2>
              <p className="modal-subtitle">Update project name or assessment target URL.</p>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose} disabled={loading} title="Close modal">
            <X size={18} />
          </button>
        </div>

        {error && (
          <div className="alert-box-error">
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="modal-form">
          <div className="form-group">
            <label className="form-label" htmlFor="edit-project-name">
              Project Name
            </label>
            <input
              id="edit-project-name"
              type="text"
              required
              className="form-input"
              placeholder="e.g. Production Web App"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="edit-project-url">
              Target Website URL
            </label>
            <div style={{ position: 'relative' }}>
              <Globe
                size={16}
                color="var(--text-muted)"
                style={{ position: 'absolute', left: '12px', top: '12px' }}
              />
              <input
                id="edit-project-url"
                type="text"
                required
                className="form-input"
                style={{ paddingLeft: '38px' }}
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={loading}
              />
            </div>
            <span className="form-hint">
              Target URL will be strictly validated against SSRF. Private networks, loopback (127.0.0.1, localhost), and cloud metadata are blocked.
            </span>
          </div>

          <div className="modal-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={onClose}
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary"
              disabled={loading || !name.trim() || !targetUrl.trim()}
            >
              <Save size={14} />
              <span>{loading ? 'Saving Changes...' : 'Save Changes'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
