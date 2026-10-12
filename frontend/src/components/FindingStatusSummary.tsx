import React from 'react';
import { Activity, ShieldAlert, Clock, CheckCircle2, ShieldOff, Layers } from 'lucide-react';
import type { FindingStatusSummary as FindingStatusSummaryType } from '../utils/findingStatus';

export interface FindingStatusSummaryProps {
  summary: FindingStatusSummaryType;
}

export const FindingStatusSummary: React.FC<FindingStatusSummaryProps> = ({ summary }) => {
  return (
    <div
      className="surface-card"
      data-testid="finding-status-summary"
      style={{
        padding: '16px 20px',
        gap: '12px',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '8px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={16} color="var(--accent-cyan)" />
          <span
            style={{
              fontSize: '0.78rem',
              fontWeight: 700,
              color: 'var(--text-secondary)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
            }}
          >
            Finding Status Summary
          </span>
        </div>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          Resolution lifecycle for current scan
        </span>
      </div>

      <div className="status-summary-grid">
        {/* Total Findings */}
        <div
          data-testid="status-card-total"
          style={{
            padding: '12px 14px',
            borderRadius: '8px',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            textAlign: 'center',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
            <Layers size={13} color="var(--text-secondary)" />
            <span
              style={{
                fontSize: '0.7rem',
                color: 'var(--text-secondary)',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              Total Findings
            </span>
          </div>
          <div
            data-testid="status-count-total"
            style={{
              fontSize: '1.4rem',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: '#fff',
              marginTop: '4px',
            }}
          >
            {summary.total}
          </div>
        </div>

        {/* Open */}
        <div
          data-testid="status-card-open"
          style={{
            padding: '12px 14px',
            borderRadius: '8px',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            textAlign: 'center',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
            <ShieldAlert size={13} color="var(--accent-rose)" />
            <span
              style={{
                fontSize: '0.7rem',
                color: 'var(--accent-rose)',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              Open
            </span>
          </div>
          <div
            data-testid="status-count-open"
            style={{
              fontSize: '1.4rem',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: 'var(--accent-rose)',
              marginTop: '4px',
            }}
          >
            {summary.open}
          </div>
        </div>

        {/* In Progress */}
        <div
          data-testid="status-card-in-progress"
          style={{
            padding: '12px 14px',
            borderRadius: '8px',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            textAlign: 'center',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
            <Clock size={13} color="var(--accent-amber)" />
            <span
              style={{
                fontSize: '0.7rem',
                color: 'var(--accent-amber)',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              In Progress
            </span>
          </div>
          <div
            data-testid="status-count-in-progress"
            style={{
              fontSize: '1.4rem',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: 'var(--accent-amber)',
              marginTop: '4px',
            }}
          >
            {summary.inProgress}
          </div>
        </div>

        {/* Resolved */}
        <div
          data-testid="status-card-resolved"
          style={{
            padding: '12px 14px',
            borderRadius: '8px',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            textAlign: 'center',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
            <CheckCircle2 size={13} color="var(--accent-emerald)" />
            <span
              style={{
                fontSize: '0.7rem',
                color: 'var(--accent-emerald)',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              Resolved
            </span>
          </div>
          <div
            data-testid="status-count-resolved"
            style={{
              fontSize: '1.4rem',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: 'var(--accent-emerald)',
              marginTop: '4px',
            }}
          >
            {summary.resolved}
          </div>
        </div>

        {/* False Positive */}
        <div
          data-testid="status-card-false-positive"
          style={{
            padding: '12px 14px',
            borderRadius: '8px',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            textAlign: 'center',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
            <ShieldOff size={13} color="var(--text-muted)" />
            <span
              style={{
                fontSize: '0.7rem',
                color: 'var(--text-muted)',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              False Positive
            </span>
          </div>
          <div
            data-testid="status-count-false-positive"
            style={{
              fontSize: '1.4rem',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-secondary)',
              marginTop: '4px',
            }}
          >
            {summary.falsePositive}
          </div>
        </div>
      </div>
    </div>
  );
};
