import React from 'react';
import { Layers, CheckCircle2, ArrowRight } from 'lucide-react';

export const PhaseRoadmapCard: React.FC = () => {
  return (
    <div className="surface-card">
      <div className="card-header">
        <div className="card-title-group">
          <Layers size={18} color="var(--accent-cyan)" />
          <h2 className="card-title">Engineering Roadmap & Phase Execution</h2>
        </div>
        <span className="badge badge-cyan">Phase 1 of 12</span>
      </div>

      <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
        Sentriq follows an incremental, production-grade engineering roadmap without simulated metrics or placeholder data.
      </p>

      <div className="roadmap-list">
        <div className="roadmap-item current">
          <div className="roadmap-bullet done">
            <CheckCircle2 size={13} />
          </div>
          <div className="roadmap-details">
            <div className="roadmap-title">
              <span>Phase 1: Project Foundation</span>
              <span className="badge badge-emerald" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>VERIFIED</span>
            </div>
            <div className="roadmap-desc">
              FastAPI backend, React/Vite/TS shell, SQLAlchemy 2.0 async engine, canonical health endpoint, and environment isolation.
            </div>
          </div>
        </div>

        <div className="roadmap-item">
          <div className="roadmap-bullet pending">2</div>
          <div className="roadmap-details">
            <div className="roadmap-title">
              <span>Phase 2: Authentication & Authorized Projects</span>
              <span className="badge badge-cyan" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>NEXT</span>
            </div>
            <div className="roadmap-desc">
              User identity, GitHub OAuth integration, project registration with mandatory ownership & authorization confirmation.
            </div>
          </div>
        </div>

        <div className="roadmap-item">
          <div className="roadmap-bullet pending">3</div>
          <div className="roadmap-details">
            <div className="roadmap-title">
              <span>Phase 3: Defensive Website Security Scanner</span>
            </div>
            <div className="roadmap-desc">
              Non-destructive HTTPS/TLS, security headers, cookie flags, CORS rules, and safe information exposure checks.
            </div>
          </div>
        </div>

        <div className="roadmap-item">
          <div className="roadmap-bullet pending">4</div>
          <div className="roadmap-details">
            <div className="roadmap-title">
              <span>Phase 4 & 5: Finding Normalization & Risk Engine</span>
            </div>
            <div className="roadmap-desc">
              Common security finding schema, explainable risk algorithm (0-100), and holistic security posture scoring.
            </div>
          </div>
        </div>
      </div>

      <div
        style={{
          marginTop: '4px',
          padding: '12px 14px',
          borderRadius: '8px',
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          fontSize: '0.8rem',
          color: 'var(--text-secondary)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
        }}
      >
        <ArrowRight size={14} color="var(--accent-cyan)" />
        <span>Strict policy: No mock vulnerabilities, simulated scores, or fake scanners.</span>
      </div>
    </div>
  );
};
