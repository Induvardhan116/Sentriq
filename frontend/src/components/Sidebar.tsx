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

interface SidebarProps {
  currentTab: 'overview' | 'projects';
  onSelectTab: (tab: 'overview' | 'projects') => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  return (
    <aside className="sidebar">
      <nav className="nav-group">
        <div className="nav-heading">Platform</div>
        <button
          className={`nav-link ${currentTab === 'overview' ? 'active' : ''}`}
          onClick={() => onSelectTab('overview')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <LayoutDashboard size={16} />
          <span>Overview</span>
          <span className="nav-link-badge">P1</span>
        </button>

        <button
          className={`nav-link ${currentTab === 'projects' ? 'active' : ''}`}
          onClick={() => onSelectTab('projects')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <FolderLock size={16} />
          <span>Projects & Scans</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P2 Active</span>
        </button>

        <div className="nav-heading" style={{ marginTop: '16px' }}>
          Security Modules
        </div>

        <div className="nav-link disabled" title="Available in Phase 4: Normalized Security Findings Hub">
          <AlertOctagon size={16} />
          <span>Findings Hub</span>
          <span className="nav-link-badge">Phase 4</span>
        </div>

        <div className="nav-link disabled" title="Available in Phase 5: Deep Risk Engine Analytics">
          <Gauge size={16} />
          <span>Risk Analytics</span>
          <span className="nav-link-badge">Phase 5</span>
        </div>

        <div className="nav-link disabled" title="Available in Phase 6: Code Repository SAST & Secret Detection">
          <ScanSearch size={16} />
          <span>Repo Security</span>
          <span className="nav-link-badge">Phase 6</span>
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
        <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Sentriq Platform</span>
        <span>Phase 2: Website Security Scanner</span>
      </div>
    </aside>
  );
};
