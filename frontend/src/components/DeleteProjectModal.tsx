import React, { useState, useEffect } from 'react';
import { X, Trash2, AlertTriangle, Globe, AlertCircle } from 'lucide-react';
import { deleteProject } from '../services/api';
import { Project } from '../types/project';

interface DeleteProjectModalProps {
  project: Project | null;
  isOpen: boolean;
  onClose: () => void;
  onProjectDeleted: (deletedProjectId: string, projectName: string) => void;
}

export const DeleteProjectModal: React.FC<DeleteProjectModalProps> = ({
  project,
  isOpen,
  onClose,
  onProjectDeleted,
}) => {
  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setConfirmed(false);
      setError(null);
    }
  }, [isOpen, project]);

  if (!isOpen || !project) return null;

  const handleDelete = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!confirmed) {
      setError('Please check the confirmation box to confirm deletion.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      await deleteProject(project.id);
      onProjectDeleted(project.id, project.name);
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete project.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container" style={{ maxWidth: '480px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                backgroundColor: 'var(--accent-rose-subtle)',
                border: '1px solid rgba(244, 63, 94, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-rose)',
              }}
            >
              <Trash2 size={16} />
            </div>
            <div>
              <h2 className="modal-title">Delete Security Project</h2>
              <p className="modal-subtitle">Permanent removal of assessment target and history.</p>
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

        <form onSubmit={handleDelete} className="modal-form">
          {/* Target details card */}
          <div
            style={{
              padding: '14px 16px',
              borderRadius: '8px',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Project to be Deleted
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {project.name}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
              <Globe size={14} color="var(--accent-cyan)" />
              <span>{project.target_url}</span>
            </div>
          </div>

          {/* Warning notice */}
          <div
            style={{
              padding: '12px 14px',
              borderRadius: '8px',
              backgroundColor: 'rgba(244, 63, 94, 0.08)',
              border: '1px solid rgba(244, 63, 94, 0.25)',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
            }}
          >
            <AlertTriangle size={18} color="var(--accent-rose)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              <strong style={{ color: 'var(--accent-rose)', display: 'block', marginBottom: '2px' }}>
                Warning: Permanent Action
              </strong>
              Deleting this project will permanently delete all associated scan records, posture history, and security findings. This action cannot be undone.
            </div>
          </div>

          {/* Accidental deletion prevention barrier */}
          <div
            style={{
              padding: '12px 14px',
              borderRadius: '8px',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-muted)',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
            }}
          >
            <input
              type="checkbox"
              id="confirm-delete-checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              disabled={loading}
              style={{ marginTop: '3px', cursor: 'pointer' }}
            />
            <label
              htmlFor="confirm-delete-checkbox"
              style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', cursor: 'pointer', userSelect: 'none' }}
            >
              I understand that deleting <strong style={{ color: '#fff' }}>{project.name}</strong> will permanently remove all associated scan history and findings.
            </label>
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
              className="btn-danger"
              disabled={loading || !confirmed}
            >
              <Trash2 size={14} />
              <span>{loading ? 'Deleting...' : 'Delete Project'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
