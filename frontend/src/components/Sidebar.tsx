import React from 'react';
import {
  LayoutDashboard,
  FolderLock,
  ScanSearch,
  AlertOctagon,
  Gauge,
  FileText,
  SlidersHorizontal,
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  return (
    <aside className="sidebar">
      <nav className="nav-group">
        <div className="nav-heading">Platform</div>
        <div className="nav-link active">
          <LayoutDashboard size={16} />
          <span>Overview</span>
          <span className="nav-link-badge">P1</span>
        </div>

        <div className="nav-heading" style={{ marginTop: '16px' }}>
          Security Modules
        </div>

        <div className="nav-link disabled" title="Available in Phase 2: Project Management & Target Ownership">
          <FolderLock size={16} />
          <span>Projects</span>
          <span className="nav-link-badge">Phase 2</span>
        </div>

        <div className="nav-link disabled" title="Available in Phase 3 & 6: Website DAST & Repo SAST/Secrets/OSV">
          <ScanSearch size={16} />
          <span>Security Scans</span>
          <span className="nav-link-badge">Phase 3</span>
        </div>

        <div className="nav-link disabled" title="Available in Phase 4: Normalized Security Findings">
          <AlertOctagon size={16} />
          <span>Findings</span>
          <span className="nav-link-badge">Phase 4</span>
        </div>

        <div className="nav-link disabled" title="Available in Phase 5: Explainable Risk Engine & Posture Scoring">
          <Gauge size={16} />
          <span>Risk Engine</span>
          <span className="nav-link-badge">Phase 5</span>
        </div>

        <div className="nav-link disabled" title="Available in Phase 9: Automated Executive PDF Security Reports">
          <FileText size={16} />
          <span>Reports</span>
          <span className="nav-link-badge">Phase 9</span>
        </div>

        <div className="nav-heading" style={{ marginTop: '16px' }}>
          Configuration
        </div>

        <div className="nav-link disabled" title="Deployment & Environment Settings">
          <SlidersHorizontal size={16} />
          <span>Settings</span>
          <span className="nav-link-badge">Phase 10</span>
        </div>
      </nav>

      <div
        style={{
          padding: '16px 20px',
          borderTop: '1px solid var(--border-subtle)',
          fontSize: '0.72rem',
          color: 'var(--text-muted)',
          display: 'flex',
          flexDirection: 'column',
          gap: '4px',
        }}
      >
        <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Sentriq Foundation</span>
        <span>Phase 1 Verified Architecture</span>
      </div>
    </aside>
  );
};
