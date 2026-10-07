import React, { useEffect, useState, useCallback } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { SystemStatusCard } from './components/SystemStatusCard';
import { PhaseRoadmapCard } from './components/PhaseRoadmapCard';
import { fetchSystemHealth } from './services/api';
import { SystemHealth } from './types/system';

export const App: React.FC = () => {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [latencyMs, setLatencyMs] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);

  const loadHealth = useCallback(async () => {
    setLoading(true);
    const result = await fetchSystemHealth();
    setHealth(result.data);
    setError(result.error);
    setLatencyMs(result.latencyMs);
    setLoading(false);
  }, []);

  useEffect(() => {
    loadHealth();
  }, [loadHealth]);

  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <Header health={health} loading={loading} onRefresh={loadHealth} />

        <main className="page-body">
          {/* Welcome & Platform Overview */}
          <section className="hero-card">
            <div>
              <h1 className="hero-title">Sentriq Security Intelligence</h1>
              <p className="hero-subtitle">
                Automated, defensive application security posture management. Engineered with free and open-source tools
                for reliable cloud and local deployment.
              </p>
            </div>
            <div style={{ textAlign: 'right' }}>
              <span className="badge badge-cyan" style={{ fontSize: '0.78rem' }}>
                FOUNDATION VERIFIED
              </span>
            </div>
          </section>

          {/* Real-time System Diagnostics and Roadmap Grid */}
          <div className="grid-two-column">
            <SystemStatusCard health={health} error={error} latencyMs={latencyMs} />
            <PhaseRoadmapCard />
          </div>
        </main>
      </div>
    </div>
  );
};

export default App;
