import React from 'react';
import {
  LayoutDashboard,
  FolderLock,
  ScanSearch,
  AlertOctagon,
  Gauge,
  FileText,
  SlidersHorizontal,
  Code2,
  Cloud,
  Webhook,
  Users,
} from 'lucide-react';

export type SidebarTab =
  | 'overview'
  | 'projects'
  | 'findings'
  | 'analytics'
  | 'repositories'
  | 'api-security'
  | 'cloud-security'
  | 'reports'
  | 'settings'
  | 'integrations'
  | 'workspaces';

interface SidebarProps {
  currentTab: SidebarTab;
  onSelectTab: (tab: SidebarTab) => void;
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

        <button
          className={`nav-link ${currentTab === 'findings' ? 'active' : ''}`}
          onClick={() => onSelectTab('findings')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <AlertOctagon size={16} />
          <span>Findings Hub</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P4 Active</span>
        </button>

        <button
          className={`nav-link ${currentTab === 'analytics' ? 'active' : ''}`}
          onClick={() => onSelectTab('analytics')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <Gauge size={16} />
          <span>Risk Analytics</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P5 Active</span>
        </button>

        <button
          className={`nav-link ${currentTab === 'repositories' ? 'active' : ''}`}
          onClick={() => onSelectTab('repositories')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <ScanSearch size={16} />
          <span>Repo Security</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P6 Active</span>
        </button>

        <button
          className={`nav-link ${currentTab === 'api-security' ? 'active' : ''}`}
          onClick={() => onSelectTab('api-security')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <Code2 size={16} />
          <span>API Security</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P7 Active</span>
        </button>

        <button
          className={`nav-link ${currentTab === 'cloud-security' ? 'active' : ''}`}
          onClick={() => onSelectTab('cloud-security')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <Cloud size={16} />
          <span>Cloud Security</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P8 Active</span>
        </button>

        <button
          className={`nav-link ${currentTab === 'reports' ? 'active' : ''}`}
          onClick={() => onSelectTab('reports')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <FileText size={16} />
          <span>Reports & Export</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P9 Active</span>
        </button>

        <div className="nav-heading" style={{ marginTop: '16px' }}>
          Configuration
        </div>

        <button
          className={`nav-link ${currentTab === 'settings' ? 'active' : ''}`}
          onClick={() => onSelectTab('settings')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <SlidersHorizontal size={16} />
          <span>Settings</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P10 Active</span>
        </button>

        <button
          className={`nav-link ${currentTab === 'integrations' ? 'active' : ''}`}
          onClick={() => onSelectTab('integrations')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <Webhook size={16} />
          <span>Integrations & SIEM</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P11 Active</span>
        </button>

        <button
          className={`nav-link ${currentTab === 'workspaces' ? 'active' : ''}`}
          onClick={() => onSelectTab('workspaces')}
          style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none' }}
        >
          <Users size={16} />
          <span>Workspaces & RBAC</span>
          <span className="nav-link-badge" style={{ color: 'var(--accent-cyan)', borderColor: 'rgba(6, 182, 212, 0.4)' }}>P12 Active</span>
        </button>
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
