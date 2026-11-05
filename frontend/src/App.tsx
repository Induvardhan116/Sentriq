import React, { useEffect, useState, useCallback } from 'react';
import { AlertOctagon, ArrowLeft, Shield } from 'lucide-react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { SystemStatusCard } from './components/SystemStatusCard';
import { PhaseRoadmapCard } from './components/PhaseRoadmapCard';
import { ProjectList } from './components/ProjectList';
import { CreateProjectModal } from './components/CreateProjectModal';
import { ScanDetailView } from './components/ScanDetailView';
import { ProjectDetailView } from './components/ProjectDetailView';
import { LoginPage } from './components/LoginPage';
import { RegisterPage } from './components/RegisterPage';
import { ForgotPasswordPage } from './components/ForgotPasswordPage';
import { ResetPasswordPage } from './components/ResetPasswordPage';
import { VerifyEmailPage } from './components/VerifyEmailPage';
import { UnverifiedEmailBanner } from './components/UnverifiedEmailBanner';
import { AuthProvider, useAuth } from './context/AuthContext';
import { fetchSystemHealth, fetchProjects } from './services/api';
import { SystemHealth } from './types/system';
import { Project } from './types/project';
import { AppRoute, parseRoute, navigate } from './utils/routing';

const AppContent: React.FC = () => {
  const { user, isAuthenticated, isLoading } = useAuth();
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [latencyMs, setLatencyMs] = useState<number>(0);
  const [loadingHealth, setLoadingHealth] = useState<boolean>(true);

  // Derive route state from current browser URL
  const [route, setRoute] = useState<AppRoute>(() =>
    parseRoute(window.location.hash, window.location.pathname)
  );

  // Projects State
  const [projects, setProjects] = useState<Project[]>([]);
  const [loadingProjects, setLoadingProjects] = useState<boolean>(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState<boolean>(false);

  // Sync route on hashchange (browser forward, back, or direct URL edits)
  useEffect(() => {
    const onHashChange = () => {
      setRoute(parseRoute(window.location.hash, window.location.pathname));
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

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

  // Loading state while restoring session
  if (isLoading) {
    return (
      <div
        style={{
          display: 'flex',
          minHeight: '100vh',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'var(--bg-canvas, #090d16)',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <div
            className="brand-logo-badge"
            style={{
              width: '48px',
              height: '48px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '12px',
              backgroundColor: 'var(--accent-cyan-subtle, rgba(6, 182, 212, 0.15))',
              color: 'var(--accent-cyan, #06b6d4)',
            }}
          >
            <Shield size={28} />
          </div>
          <div style={{ fontSize: '0.88rem', color: 'var(--text-muted, #94a3b8)' }}>
            Authenticating session...
          </div>
        </div>
      </div>
    );
  }

  // Handle dedicated full-screen auth routes
  if (route.view === 'login') {
    if (isAuthenticated) {
      navigate({ view: 'overview' });
      return null;
    }
    return <LoginPage />;
  }

  if (route.view === 'register') {
    if (isAuthenticated) {
      navigate({ view: 'overview' });
      return null;
    }
    return <RegisterPage />;
  }

  if (route.view === 'forgot-password') {
    if (isAuthenticated) {
      navigate({ view: 'overview' });
      return null;
    }
    return <ForgotPasswordPage />;
  }

  if (route.view === 'reset-password') {
    return <ResetPasswordPage token={route.token} />;
  }

  if (route.view === 'verify-email') {
    return <VerifyEmailPage token={route.token} />;
  }

  // Determine active sidebar tab
  const currentTab: 'overview' | 'projects' =
    route.view === 'overview' ? 'overview' : 'projects';

  const handleSelectTab = (tab: 'overview' | 'projects') => {
    navigate({ view: tab });
  };

  const handleSelectScan = (scanId: string) => {
    navigate({ view: 'scan', scanId });
  };

  const handleSelectProject = (projectId: string) => {
    navigate({ view: 'project', projectId });
  };

  return (
    <div className="app-container">
      <Sidebar currentTab={currentTab} onSelectTab={handleSelectTab} />
      <div className="main-content">
        <Header health={health} loading={loadingHealth} onRefresh={loadHealth} />

        {isAuthenticated && user && user.is_verified === false && (
          <UnverifiedEmailBanner email={user.email} />
        )}

        <main className="page-body">
          {route.view === 'error' ? (
            <div className="surface-card" style={{ padding: '40px', textAlign: 'center' }}>
              <AlertOctagon size={36} color="var(--accent-rose)" style={{ margin: '0 auto 12px' }} />
              <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
                {route.message}
              </p>
              {route.submessage && (
                <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '20px' }}>
                  {route.submessage}
                </p>
              )}
              <button className="btn-secondary" onClick={() => navigate({ view: 'projects' })}>
                <ArrowLeft size={14} /> Back to Projects
              </button>
            </div>
          ) : route.view === 'scan' ? (
            <ScanDetailView
              scanId={route.scanId}
              initialFindingId={route.findingId}
              onBack={() => navigate({ view: 'projects' })}
              onSelectFinding={(fId) =>
                navigate({ view: 'scan', scanId: route.scanId, findingId: fId ?? undefined })
              }
            />
          ) : route.view === 'project' ? (
            <ProjectDetailView
              projectId={route.projectId}
              onBack={() => navigate({ view: 'projects' })}
              onSelectScan={handleSelectScan}
              onProjectUpdated={loadProjects}
            />
          ) : route.view === 'overview' ? (
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
                    PHASE 3.3 ACTIVE
                  </span>
                  <button
                    className="btn-primary"
                    onClick={() => {
                      navigate({ view: 'projects' });
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
              onSelectProject={handleSelectProject}
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
          navigate({ view: 'projects' });
        }}
      />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;
