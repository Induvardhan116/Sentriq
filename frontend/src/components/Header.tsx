import React from 'react';
import { Shield, Activity, RefreshCw } from 'lucide-react';
import { SystemHealth } from '../types/system';

interface HeaderProps {
  health: SystemHealth | null;
  loading: boolean;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({ health, loading, onRefresh }) => {
  const isHealthy = health?.status === 'healthy';
  const isConnected = !!health;

  return (
    <header className="top-header">
      <div className="brand-section">
        <div className="brand-logo-badge">
          <Shield size={20} />
        </div>
        <div>
          <div className="brand-name">SENTRIQ</div>
          <div className="brand-tagline">Application Security Intelligence</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        {health && (
          <span className="badge badge-cyan" title="Environment">
            {health.environment.toUpperCase()}
          </span>
        )}

        <div
          className={`badge ${
            !isConnected
              ? 'badge-rose'
              : isHealthy
              ? 'badge-emerald'
              : 'badge-amber'
          }`}
        >
          <Activity size={13} />
          <span>
            {!isConnected
              ? 'OFFLINE'
              : isHealthy
              ? 'SYSTEM ONLINE'
              : 'DEGRADED'}
          </span>
        </div>

        <button
          className="btn-secondary"
          onClick={onRefresh}
          disabled={loading}
          title="Refresh system diagnostics"
          style={{ padding: '6px 10px', fontSize: '0.78rem' }}
        >
          <RefreshCw
            size={13}
            style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }}
          />
          <span>Check</span>
        </button>
      </div>
    </header>
  );
};
