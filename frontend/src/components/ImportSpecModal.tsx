import React, { useState } from 'react';
import { X, UploadCloud, AlertCircle, FileCode } from 'lucide-react';
import { importApiSpec } from '../services/api';
import { ApiSpec } from '../types/apiSecurity';

interface ImportSpecModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSpecImported: (spec: ApiSpec) => void;
}

const SAMPLE_SPEC_JSON = JSON.stringify(
  {
    openapi: "3.0.0",
    info: {
      title: "Core Banking Gateway API",
      version: "2.1.0",
      description: "Internal banking transactions and user accounts service"
    },
    servers: [
      { url: "https://api.banking.example.com/v1" }
    ],
    paths: {
      "/api/accounts": {
        get: {
          summary: "List user accounts",
          responses: {
            "200": {
              description: "Account listings",
              content: {
                "application/json": {
                  schema: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        account_number: { type: "string" },
                        balance: { type: "number" },
                        ssn: { type: "string" },
                        api_key: { type: "string" }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/transfers": {
        post: {
          summary: "Execute funds transfer without authentication",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    source: { type: "string" },
                    destination: { type: "string" },
                    amount: { type: "number" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Transfer initiated" }
          }
        }
      },
      "/api/admin/debug-dump": {
        get: {
          summary: "Debug environment variables",
          responses: {
            "200": { description: "Debug dump" }
          }
        }
      }
    }
  },
  null,
  2
);

export const ImportSpecModal: React.FC<ImportSpecModalProps> = ({
  isOpen,
  onClose,
  onSpecImported,
}) => {
  const [title, setTitle] = useState('');
  const [version, setVersion] = useState('1.0.0');
  const [baseUrl, setBaseUrl] = useState('');
  const [rawSpec, setRawSpec] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleLoadSample = () => {
    setTitle('Core Banking Gateway API');
    setVersion('2.1.0');
    setBaseUrl('https://api.banking.example.com/v1');
    setRawSpec(SAMPLE_SPEC_JSON);
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      setError('Specification title is required');
      return;
    }
    if (!rawSpec.trim() || rawSpec.trim().length < 10) {
      setError('Please provide a valid OpenAPI or Swagger schema (JSON/YAML)');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      const spec = await importApiSpec({
        title: title.trim(),
        version: version.trim() || '1.0.0',
        raw_spec: rawSpec.trim(),
        base_url: baseUrl.trim() || undefined,
      });
      onSpecImported(spec);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to import and analyze specification');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-card"
        style={{ maxWidth: '640px', width: '100%' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <UploadCloud size={18} color="var(--accent-cyan)" />
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Import API Specification
            </h3>
          </div>
          <button
            className="btn-icon"
            onClick={onClose}
            aria-label="Close modal"
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
          >
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {error && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 12px',
                borderRadius: '6px',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#ef4444',
                fontSize: '0.85rem',
              }}
            >
              <AlertCircle size={16} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          <div style={{ display: 'flex', gap: '12px' }}>
            <div style={{ flex: 2 }}>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                API Title *
              </label>
              <input
                type="text"
                placeholder="e.g. Core Banking Gateway API"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                required
                className="input-field"
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Version
              </label>
              <input
                type="text"
                placeholder="1.0.0"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                className="input-field"
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Base Target URL (Optional)
            </label>
            <input
              type="url"
              placeholder="https://api.banking.example.com/v1"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              className="input-field"
              style={{ width: '100%', boxSizing: 'border-box' }}
            />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label style={{ fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)' }}>
                OpenAPI 3.0 / Swagger 2.0 Schema (JSON or YAML) *
              </label>
              <button
                type="button"
                onClick={handleLoadSample}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--accent-cyan)',
                  fontSize: '0.78rem',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  padding: 0,
                }}
              >
                <FileCode size={13} /> Load Sample Schema
              </button>
            </div>
            <textarea
              placeholder="Paste raw OpenAPI 3.0 or Swagger JSON/YAML schema here..."
              value={rawSpec}
              onChange={(e) => setRawSpec(e.target.value)}
              rows={9}
              required
              className="input-field"
              style={{
                width: '100%',
                boxSizing: 'border-box',
                fontFamily: 'monospace',
                fontSize: '0.78rem',
                lineHeight: 1.4,
                resize: 'vertical',
              }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '8px' }}>
            <button
              type="button"
              className="btn-secondary"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary"
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Analyzing Schema...' : 'Import & Audit Spec'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
