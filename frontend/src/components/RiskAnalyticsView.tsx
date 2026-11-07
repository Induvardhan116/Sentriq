import React, { useState, useEffect, useCallback } from 'react';
import {
  Gauge,
  TrendingUp,
  TrendingDown,
  Minus,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FolderLock,
  RefreshCw,
  Clock,
  Layers,
  ArrowRight,
  Info,
} from 'lucide-react';
import {
  RiskSummaryResponse,
  PostureTrendsResponse,
  ProjectRankingsResponse,
} from '../types/analytics';
import { Project } from '../types/project';
import {
  fetchRiskSummary,
  fetchPostureTrends,
  fetchProjectRankings,
  fetchProjects,
} from '../services/api';

interface RiskAnalyticsViewProps {
  onNavigateProject?: (projectId: string) => void;
  onNavigateFindings?: () => void;
}

export const RiskAnalyticsView: React.FC<RiskAnalyticsViewProps> = ({
  onNavigateProject,
  onNavigateFindings,
}) => {
  const [summary, setSummary] = useState<RiskSummaryResponse | null>(null);
  const [trends, setTrends] = useState<PostureTrendsResponse | null>(null);
  const [rankings, setRankings] = useState<ProjectRankingsResponse | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);

  const [selectedProjectId, setSelectedProjectId] = useState<string>('all');
  const [trendDays, setTrendDays] = useState<number>(30);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Load project dropdown items
  useEffect(() => {
    fetchProjects()
      .then(setProjects)
      .catch((err) => console.error('Failed to load projects list:', err));
  }, []);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const projFilter = selectedProjectId !== 'all' ? selectedProjectId : undefined;
      const [summaryRes, trendsRes, rankingsRes] = await Promise.all([
        fetchRiskSummary(projFilter),
        fetchPostureTrends({ project_id: projFilter, days: trendDays }),
        fetchProjectRankings(50),
      ]);
      setSummary(summaryRes);
      setTrends(trendsRes);
      setRankings(rankingsRes);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to retrieve risk analytics';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId, trendDays]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'var(--accent-emerald)';
    if (score >= 75) return 'var(--accent-cyan)';
    if (score >= 50) return 'var(--accent-amber)';
    return 'var(--accent-rose)';
  };

  const getGradeBadgeClass = (grade: string) => {
    switch (grade.toLowerCase()) {
      case 'excellent':
        return 'badge-emerald';
      case 'good':
        return 'badge-cyan';
      case 'needs improvement':
        return 'badge-amber';
      case 'poor':
      case 'critical':
      default:
        return 'badge-rose';
    }
  };

  const getHealthBadgeClass = (health: string) => {
    switch (health) {
      case 'healthy':
        return 'badge-emerald';
      case 'warning':
        return 'badge-amber';
      case 'critical':
      default:
        return 'badge-rose';
    }
  };

  return (
    <div className="risk-analytics-view" style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* Header Banner */}
      <section className="hero-card" style={{ marginBottom: '0' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-logo-badge" style={{ width: '38px', height: '38px' }}>
              <Gauge size={22} color="var(--accent-cyan)" />
            </div>
            <div>
              <h1 className="hero-title" style={{ fontSize: '1.4rem' }}>
                Deep Security Risk Analytics
              </h1>
              <p className="hero-subtitle" style={{ fontSize: '0.84rem' }}>
                Deterministic posture scoring, domain exposure breakdown, and remediation telemetry.
              </p>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {/* Target Filter Dropdown */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FolderLock size={15} color="var(--text-muted)" />
            <select
              className="form-input"
              value={selectedProjectId}
              onChange={(e) => setSelectedProjectId(e.target.value)}
              style={{ fontSize: '0.82rem', padding: '6px 10px' }}
            >
              <option value="all">All Monitored Projects</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          <button
            className="btn-secondary"
            onClick={loadData}
            style={{ fontSize: '0.8rem', padding: '6px 12px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </section>

      {/* Error Banner */}
      {error && (
        <div
          style={{
            padding: '14px 18px',
            borderRadius: '8px',
            backgroundColor: 'rgba(244, 63, 94, 0.1)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            color: 'var(--accent-rose)',
            fontSize: '0.84rem',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
          }}
        >
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Posture Score Hero & KPIs Grid */}
      {summary && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr', gap: '16px' }}>
          {/* Executive Posture Score Card */}
          <div
            className="surface-card"
            style={{
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              padding: '24px',
              border: `1px solid ${getScoreColor(summary.overall_posture_score)}33`,
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Overall Posture Score
                </span>
                <span className={`badge ${getGradeBadgeClass(summary.grade)}`}>
                  {summary.grade.toUpperCase()}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '16px' }}>
                <span
                  style={{
                    fontSize: '3.6rem',
                    fontWeight: 900,
                    fontFamily: 'var(--font-mono)',
                    color: getScoreColor(summary.overall_posture_score),
                    lineHeight: 1,
                  }}
                >
                  {summary.overall_posture_score}
                </span>
                <span style={{ fontSize: '1.2rem', color: 'var(--text-muted)' }}>/100</span>
              </div>

              {/* Ceiling Caps Alert */}
              {summary.active_caps_applied.length > 0 && (
                <div
                  style={{
                    marginTop: '16px',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    backgroundColor: 'rgba(244, 63, 94, 0.1)',
                    border: '1px solid rgba(244, 63, 94, 0.25)',
                    fontSize: '0.76rem',
                    color: 'var(--accent-rose)',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '6px',
                  }}
                >
                  <AlertTriangle size={14} style={{ marginTop: '2px', flexShrink: 0 }} />
                  <div>
                    {summary.active_caps_applied.map((cap, i) => (
                      <div key={i}>{cap}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div style={{ marginTop: '20px', paddingTop: '12px', borderTop: '1px solid var(--border-subtle)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '4px' }}>
                <Info size={12} />
                <span>Deterministic Scoring Model</span>
              </div>
              <p style={{ margin: 0, lineHeight: 1.4 }}>{summary.score_formula_explanation}</p>
            </div>
          </div>

          {/* Telemetry & Remediation KPIs */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px' }}>
            {/* Remediation Velocity */}
            <div className="surface-card" style={{ padding: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>REMEDIATION VELOCITY</span>
                <ShieldCheck size={16} color="var(--accent-emerald)" />
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-emerald)', marginTop: '6px' }}>
                {summary.remediation_metrics.remediation_rate_percent}%
              </div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                {summary.remediation_metrics.resolved_findings_count} of {summary.remediation_metrics.total_findings_discovered} findings resolved
              </div>
            </div>

            {/* Mean Time To Remediate (MTTR) */}
            <div className="surface-card" style={{ padding: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>MEAN TIME TO REMEDIATE</span>
                <Clock size={16} color="var(--accent-cyan)" />
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', marginTop: '6px' }}>
                {summary.remediation_metrics.mean_time_to_remediate_days !== null && summary.remediation_metrics.mean_time_to_remediate_days !== undefined
                  ? `${summary.remediation_metrics.mean_time_to_remediate_days}d`
                  : 'N/A'}
              </div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                Average lifecycle duration to closure
              </div>
            </div>

            {/* Oldest Open Finding Exposure */}
            <div className="surface-card" style={{ padding: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>MAX EXPOSURE AGE</span>
                <ShieldAlert size={16} color="var(--accent-amber)" />
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-amber)', marginTop: '6px' }}>
                {summary.remediation_metrics.oldest_open_finding_days !== null && summary.remediation_metrics.oldest_open_finding_days !== undefined
                  ? `${summary.remediation_metrics.oldest_open_finding_days}d`
                  : '0d'}
              </div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                Oldest active unmitigated risk
              </div>
            </div>

            {/* Active Vulnerability Burden */}
            <div className="surface-card" style={{ padding: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>ACTIVE VULNERABILITIES</span>
                <Layers size={16} color="var(--accent-rose)" />
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-rose)', marginTop: '6px' }}>
                {summary.active_findings}
              </div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: '4px', display: 'flex', gap: '8px' }}>
                <span>{summary.severity_distribution.critical} Crit</span>
                <span>{summary.severity_distribution.high} High</span>
                <span>{summary.severity_distribution.medium} Med</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Security Domain Breakdown */}
      {summary && summary.domain_breakdown.length > 0 && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Security Domain Posture Breakdown
            </h2>
            {onNavigateFindings && (
              <button
                className="btn-secondary"
                onClick={onNavigateFindings}
                style={{ fontSize: '0.76rem', padding: '4px 10px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
              >
                <span>View Findings Hub</span>
                <ArrowRight size={13} />
              </button>
            )}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
            {summary.domain_breakdown.map((dom) => (
              <div
                key={dom.domain}
                className="surface-card"
                style={{ padding: '16px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
                      {dom.domain}
                    </span>
                    <span className={`badge ${getHealthBadgeClass(dom.health_status)}`}>
                      {dom.health_status.toUpperCase()}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '6px', lineHeight: 1.4 }}>
                    {dom.description}
                  </p>
                </div>

                <div
                  style={{
                    marginTop: '12px',
                    paddingTop: '10px',
                    borderTop: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: '0.78rem',
                  }}
                >
                  <span style={{ color: 'var(--text-secondary)' }}>Active Findings:</span>
                  <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {dom.finding_count > 0 ? (
                      <span style={{ color: dom.critical_count > 0 ? 'var(--accent-rose)' : 'var(--accent-amber)' }}>
                        {dom.finding_count} ({dom.critical_count} crit, {dom.high_count} high)
                      </span>
                    ) : (
                      <span style={{ color: 'var(--accent-emerald)' }}>0 (Clean)</span>
                    )}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Historical Posture Trends Timeline */}
      {trends && (
        <div className="surface-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  Historical Posture Score Timeline
                </h2>
                {trends.trend_direction === 'improving' ? (
                  <span className="badge badge-emerald" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                    <TrendingUp size={12} /> Improving (+{trends.score_delta} pts)
                  </span>
                ) : trends.trend_direction === 'degrading' ? (
                  <span className="badge badge-rose" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                    <TrendingDown size={12} /> Degrading ({trends.score_delta} pts)
                  </span>
                ) : (
                  <span className="badge badge-cyan" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                    <Minus size={12} /> Stable
                  </span>
                )}
              </div>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                Chronological assessment trajectory across {trends.total_points} recorded scans in the last {trends.timeframe_days} days.
              </p>
            </div>

            {/* Timeframe buttons */}
            <div style={{ display: 'flex', gap: '6px' }}>
              {[7, 30, 90].map((d) => (
                <button
                  key={d}
                  className={`btn-secondary ${trendDays === d ? 'active' : ''}`}
                  onClick={() => setTrendDays(d)}
                  style={{
                    padding: '4px 10px',
                    fontSize: '0.74rem',
                    borderColor: trendDays === d ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                    color: trendDays === d ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  }}
                >
                  {d}D
                </button>
              ))}
            </div>
          </div>

          {trends.data_points.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
              No scan history points found within this timeframe. Run scans to generate trend data.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {/* Point Timeline Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
                {trends.data_points.map((pt, idx) => (
                  <div
                    key={pt.scan_id || idx}
                    style={{
                      padding: '12px 14px',
                      borderRadius: '8px',
                      backgroundColor: 'var(--bg-card)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{pt.date_label}</span>
                      <span className={`badge ${getGradeBadgeClass(pt.grade)}`} style={{ fontSize: '0.66rem', padding: '1px 5px' }}>
                        {pt.grade}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', marginTop: '6px' }}>
                      <span
                        style={{
                          fontSize: '1.4rem',
                          fontWeight: 800,
                          fontFamily: 'var(--font-mono)',
                          color: getScoreColor(pt.posture_score),
                        }}
                      >
                        {pt.posture_score}
                      </span>
                      <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>/100</span>
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {pt.project_name}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Project Risk Leaderboard Table */}
      {rankings && (
        <div className="surface-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Project Security Risk Rankings
            </h2>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
              Prioritized by risk index (100 - Posture Score) and critical vulnerability density.
            </p>
          </div>

          {rankings.rankings.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.84rem' }}>
              No projects registered yet.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                <thead>
                  <tr
                    style={{
                      backgroundColor: 'var(--bg-card)',
                      borderBottom: '1px solid var(--border-subtle)',
                      fontSize: '0.72rem',
                      color: 'var(--text-muted)',
                      textTransform: 'uppercase',
                    }}
                  >
                    <th style={{ padding: '12px 16px', width: '60px' }}>Rank</th>
                    <th style={{ padding: '12px 16px' }}>Project & Asset</th>
                    <th style={{ padding: '12px 16px', width: '120px' }}>Posture Score</th>
                    <th style={{ padding: '12px 16px', width: '110px' }}>Risk Index</th>
                    <th style={{ padding: '12px 16px', width: '110px' }}>Trend</th>
                    <th style={{ padding: '12px 16px', width: '130px' }}>Active Vulns</th>
                    <th style={{ padding: '12px 16px', width: '110px' }}>Exposure</th>
                    <th style={{ padding: '12px 16px', width: '90px', textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {rankings.rankings.map((rk) => (
                    <tr
                      key={rk.project_id}
                      style={{ borderBottom: '1px solid var(--border-subtle)' }}
                    >
                      <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        #{rk.rank}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{rk.project_name}</div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{rk.target_url}</div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: getScoreColor(rk.posture_score) }}>
                            {rk.posture_score}
                          </span>
                          <span className={`badge ${getGradeBadgeClass(rk.grade)}`} style={{ fontSize: '0.64rem', padding: '1px 5px' }}>
                            {rk.grade}
                          </span>
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span
                          style={{
                            fontWeight: 700,
                            fontFamily: 'var(--font-mono)',
                            color: rk.risk_index >= 50 ? 'var(--accent-rose)' : rk.risk_index >= 25 ? 'var(--accent-amber)' : 'var(--accent-emerald)',
                          }}
                        >
                          {rk.risk_index}/100
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {rk.trend === 'improving' ? (
                          <span className="badge badge-emerald" style={{ fontSize: '0.68rem' }}>Improving</span>
                        ) : rk.trend === 'degrading' ? (
                          <span className="badge badge-rose" style={{ fontSize: '0.68rem' }}>Degrading</span>
                        ) : rk.trend === 'new' ? (
                          <span className="badge badge-cyan" style={{ fontSize: '0.68rem' }}>New</span>
                        ) : (
                          <span className="badge badge-cyan" style={{ fontSize: '0.68rem' }}>Stable</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', gap: '6px', fontSize: '0.74rem' }}>
                          {rk.critical_findings > 0 && (
                            <span style={{ color: 'var(--accent-rose)', fontWeight: 700 }}>{rk.critical_findings} crit</span>
                          )}
                          {rk.high_findings > 0 && (
                            <span style={{ color: 'var(--accent-rose)' }}>{rk.high_findings} high</span>
                          )}
                          {rk.total_active_findings === 0 && (
                            <span style={{ color: 'var(--accent-emerald)' }}>0 active</span>
                          )}
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px', color: 'var(--text-muted)', fontSize: '0.74rem' }}>
                        {rk.exposure_days !== null && rk.exposure_days !== undefined ? `${rk.exposure_days}d` : 'Clean'}
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        {onNavigateProject && (
                          <button
                            type="button"
                            className="btn-secondary"
                            onClick={() => onNavigateProject(rk.project_id)}
                            style={{ padding: '4px 8px', fontSize: '0.72rem' }}
                          >
                            Inspect
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
