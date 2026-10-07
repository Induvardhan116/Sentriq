import React from 'react';
import { Database, Server, Clock, Cpu, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react';
import { SystemHealth } from '../types/system';

interface SystemStatusCardProps {
  health: SystemHealth | null;
  error: string | null;
  latencyMs: number;
}

export const SystemStatusCard: React.FC<SystemStatusCardProps> = ({
  health,
  error,
  latencyMs,
}) => {
  const isConnected = !!health;
  const isHealthy = health?.status === 'healthy';
  const isDbConnected = health?.database === 'connected';

  return (
    <div className="surface-card">
      <div className="card-header">
        <div className="card-title-group">
          <Server size={18} color="var(--accent-cyan)" />
          <h2 className="card-title">Backend & Database Infrastructure</h2>
        </div>
        <span
          className={`badge ${
            !isConnected ? 'badge-rose' : isHealthy ? 'badge-emerald' : 'badge-amber'
          }`}
        >
          {isConnected ? (isHealthy ? 'Operating Normal' : 'Degraded') : 'Service Unavailable'}
        </span>
      </div>

      <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
        Real-time telemetry verified via canonical health probe (
        <code style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
          GET /api/system/health
        </code>
        ).
      </p>

      {error && (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: '8px',
            backgroundColor: 'var(--accent-rose-subtle)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            color: 'var(--accent-rose)',
            fontSize: '0.82rem',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <AlertTriangle size={16} />
          <span>Connection Probe Failed: {error}</span>
        </div>
      )}

      <div className="diagnostic-list">
        <div className="diagnostic-item">
          <div className="diagnostic-label">
            <Server size={15} />
            <span>FastAPI Core Server</span>
          </div>
          <div className="diagnostic-value">
            {isConnected ? (
              <span style={{ color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <CheckCircle2 size={14} /> ACTIVE
              </span>
            ) : (
              <span style={{ color: 'var(--accent-rose)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <XCircle size={14} /> UNREACHABLE
              </span>
            )}
          </div>
        </div>

        <div className="diagnostic-item">
          <div className="diagnostic-label">
            <Database size={15} />
            <span>Database Connectivity (Probe: SELECT 1)</span>
          </div>
          <div className="diagnostic-value">
            {isDbConnected ? (
              <span style={{ color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <CheckCircle2 size={14} /> CONNECTED
              </span>
            ) : (
              <span style={{ color: 'var(--accent-rose)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <XCircle size={14} /> DISCONNECTED
              </span>
            )}
          </div>
        </div>

        <div className="diagnostic-item">
          <div className="diagnostic-label">
            <Clock size={15} />
            <span>API Latency</span>
          </div>
          <div className="diagnostic-value">
            {isConnected ? `${latencyMs} ms` : '—'}
          </div>
        </div>

        <div className="diagnostic-item">
          <div className="diagnostic-label">
            <Cpu size={15} />
            <span>App Version & Environment</span>
          </div>
          <div className="diagnostic-value">
            {health ? `v${health.version} (${health.environment})` : '—'}
          </div>
        </div>

        <div className="diagnostic-item">
          <div className="diagnostic-label">
            <Clock size={15} />
            <span>Server Verification Timestamp</span>
          </div>
          <div className="diagnostic-value" style={{ fontSize: '0.75rem' }}>
            {health ? new Date(health.timestamp).toLocaleTimeString() : '—'}
          </div>
        </div>
      </div>
    </div>
  );
};
