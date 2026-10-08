import React, { useEffect, useState, useCallback } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { SystemStatusCard } from './components/SystemStatusCard';
import { PhaseRoadmapCard } from './components/PhaseRoadmapCard';
import { ProjectList } from './components/ProjectList';
import { CreateProjectModal } from './components/CreateProjectModal';
import { ScanDetailView } from './components/ScanDetailView';
import { fetchSystemHealth, fetchProjects } from './services/api';
import { SystemHealth } from './types/system';
import { Project } from './types/project';

export const App: React.FC = () => {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [latencyMs, setLatencyMs] = useState<number>(0);
  const [loadingHealth, setLoadingHealth] = useState<boolean>(true);

  // Tab & Navigation State
  const [currentTab, setCurrentTab] = useState<'overview' | 'projects'>('overview');
  const [activeScanId, setActiveScanId] = useState<string | null>(null);

  // Projects State
  const [projects, setProjects] = useState<Project[]>([]);
  const [loadingProjects, setLoadingProjects] = useState<boolean>(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState<boolean>(false);

  const loadHealth = useCallback(async () => {
    setLoadingHealth(true);
    const result = await fetchSystemHealth();
    setHealth(result.data);
    setError(result.error);
    setLatencyMs(result.latencyMs);
    setLoadingHealth(false);
  }, []);

  const loadProjects = useCallback(async () => {
    setLoadingProjects(true);
    try {
      const data = await fetchProjects();
      setProjects(data);
    } catch (err) {
      console.error('Failed to load projects:', err);
    } finally {
      setLoadingProjects(false);
    }
  }, []);

  useEffect(() => {
    loadHealth();
    loadProjects();
  }, [loadHealth, loadProjects]);

  const handleSelectTab = (tab: 'overview' | 'projects') => {
    setCurrentTab(tab);
    setActiveScanId(null);
  };

  const handleSelectScan = (scanId: string) => {
    setActiveScanId(scanId);
    setCurrentTab('projects');
  };

  return (
    <div className="app-container">
      <Sidebar currentTab={currentTab} onSelectTab={handleSelectTab} />
      <div className="main-content">
        <Header health={health} loading={loadingHealth} onRefresh={loadHealth} />

        <main className="page-body">
          {activeScanId ? (
            <ScanDetailView
              scanId={activeScanId}
              onBack={() => setActiveScanId(null)}
            />
          ) : currentTab === 'overview' ? (
            <>
              {/* Platform Overview Hero */}
              <section className="hero-card">
                <div>
                  <h1 className="hero-title">Sentriq Security Intelligence</h1>
                  <p className="hero-subtitle">
                    Automated, defensive application security posture management. Engineered with free and open-source tools
                    for reliable cloud and local deployment.
                  </p>
                </div>
                <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'flex-end' }}>
                  <span className="badge badge-cyan" style={{ fontSize: '0.78rem' }}>
                    PHASE 2 ACTIVE
                  </span>
                  <button
                    className="btn-primary"
                    onClick={() => {
                      setCurrentTab('projects');
                      setIsCreateModalOpen(true);
                    }}
                    style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                  >
                    Assess Website
                  </button>
                </div>
              </section>

              {/* Real-time System Diagnostics and Roadmap Grid */}
              <div className="grid-two-column">
                <SystemStatusCard health={health} error={error} latencyMs={latencyMs} />
                <PhaseRoadmapCard />
              </div>
            </>
          ) : (
            <ProjectList
              projects={projects}
              loading={loadingProjects}
              onOpenCreateModal={() => setIsCreateModalOpen(true)}
              onSelectScan={handleSelectScan}
              onProjectUpdated={loadProjects}
            />
          )}
        </main>
      </div>

      <CreateProjectModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onProjectCreated={(newProject) => {
          setProjects((prev) => [newProject, ...prev]);
          loadProjects();
        }}
      />
    </div>
  );
};

export default App;
