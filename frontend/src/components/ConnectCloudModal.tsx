import React, { useState } from 'react';
import { X, Cloud, AlertCircle, Sparkles } from 'lucide-react';
import { createCloudAccount } from '../services/api';
import { CloudAccount, CloudProvider } from '../types/cloudSecurity';

interface ConnectCloudModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAccountConnected: (account: CloudAccount) => void;
}

export const ConnectCloudModal: React.FC<ConnectCloudModalProps> = ({
  isOpen,
  onClose,
  onAccountConnected,
}) => {
  const [provider, setProvider] = useState<CloudProvider>('aws');
  const [name, setName] = useState('');
  const [accountIdentifier, setAccountIdentifier] = useState('');
  const [roleArnOrRef, setRoleArnOrRef] = useState('');
  const [region, setRegion] = useState('us-east-1');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleApplyPreset = (presetType: 'aws' | 'supabase') => {
    if (presetType === 'aws') {
      setProvider('aws');
      setName('Production AWS Cloud Infrastructure');
      setAccountIdentifier('123456789012');
      setRoleArnOrRef('arn:aws:iam::123456789012:role/SentriqReadOnlyAuditRole');
      setRegion('us-east-1');
    } else {
      setProvider('supabase');
      setName('Production Supabase PostgreSQL PaaS');
      setAccountIdentifier('sb-proj-prod-core');
      setRoleArnOrRef('sb_read_only_audit_token_9918');
      setRegion('us-east-1');
    }
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError('Account name is required.');
      return;
    }
    if (!accountIdentifier.trim()) {
      setError('Account identifier (e.g. AWS Account ID or Supabase project ref) is required.');
      return;
    }
    if (!roleArnOrRef.trim()) {
      setError('Read-only audit Role ARN or credentials reference is required.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      const newAcc = await createCloudAccount({
        provider,
        name: name.trim(),
        account_identifier: accountIdentifier.trim(),
        role_arn_or_ref: roleArnOrRef.trim(),
        region: region.trim() || 'us-east-1',
      });
      onAccountConnected(newAcc);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to connect cloud account.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-card"
        style={{ maxWidth: '580px', width: '100%' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Cloud size={18} color="var(--accent-cyan)" />
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Connect Cloud Environment (CSPM)
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

          {/* Quick presets */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            <Sparkles size={14} color="var(--accent-cyan)" /> Quick Presets:
            <button
              type="button"
              className="btn-secondary"
              onClick={() => handleApplyPreset('aws')}
              style={{ padding: '2px 8px', fontSize: '0.74rem' }}
            >
              Sample AWS
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => handleApplyPreset('supabase')}
              style={{ padding: '2px 8px', fontSize: '0.74rem' }}
            >
              Sample Supabase
            </button>
          </div>

          <div style={{ display: 'flex', gap: '12px' }}>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Cloud Provider *
              </label>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value as CloudProvider)}
                className="input-field"
                style={{ width: '100%' }}
              >
                <option value="aws">Amazon Web Services (AWS)</option>
                <option value="supabase">Supabase PaaS</option>
                <option value="gcp">Google Cloud Platform (GCP)</option>
                <option value="azure">Microsoft Azure</option>
              </select>
            </div>

            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Primary Region
              </label>
              <input
                type="text"
                placeholder="us-east-1"
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                className="input-field"
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Environment Display Name *
            </label>
            <input
              type="text"
              placeholder="e.g. Production AWS Cloud Infrastructure"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="input-field"
              style={{ width: '100%', boxSizing: 'border-box' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Account Identifier (Account ID or Project Ref) *
            </label>
            <input
              type="text"
              placeholder="e.g. 123456789012 or sb-proj-core"
              value={accountIdentifier}
              onChange={(e) => setAccountIdentifier(e.target.value)}
              required
              className="input-field"
              style={{ width: '100%', boxSizing: 'border-box' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Read-Only Audit IAM Role ARN or Token Ref *
            </label>
            <input
              type="text"
              placeholder="e.g. arn:aws:iam::123456789012:role/SentriqReadOnlyAuditRole"
              value={roleArnOrRef}
              onChange={(e) => setRoleArnOrRef(e.target.value)}
              required
              className="input-field"
              style={{ width: '100%', boxSizing: 'border-box' }}
            />
            <p style={{ fontSize: '0.74rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
              Security Guarantee: Sentriq enforces strictly read-only audit roles and masks all credentials in storage and logs.
            </p>
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
              {isSubmitting ? 'Connecting...' : 'Connect Environment'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
