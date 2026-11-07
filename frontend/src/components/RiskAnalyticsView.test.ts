import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type {
  RiskSummaryResponse,
  PostureTrendsResponse,
  ProjectRankingsResponse,
  ProjectRiskRankingItem,
} from '../types/analytics.ts';

// Simulated State Mock for RiskAnalyticsView
class RiskAnalyticsStateMock {
  summary: RiskSummaryResponse | null = null;
  trends: PostureTrendsResponse | null = null;
  rankings: ProjectRankingsResponse | null = null;
  selectedProjectId = 'all';
  trendDays = 30;
  loading = false;
  error: string | null = null;

  async loadData(
    fetchSummaryFn: (projId?: string) => Promise<RiskSummaryResponse>,
    fetchTrendsFn: (params: { project_id?: string; days: number }) => Promise<PostureTrendsResponse>,
    fetchRankingsFn: (limit: number) => Promise<ProjectRankingsResponse>
  ): Promise<void> {
    this.loading = true;
    this.error = null;
    try {
      const pId = this.selectedProjectId !== 'all' ? this.selectedProjectId : undefined;
      const [sumData, trendData, rankData] = await Promise.all([
        fetchSummaryFn(pId),
        fetchTrendsFn({ project_id: pId, days: this.trendDays }),
        fetchRankingsFn(50),
      ]);
      this.summary = sumData;
      this.trends = trendData;
      this.rankings = rankData;
    } catch (err: unknown) {
      this.error = err instanceof Error ? err.message : 'Failed to load analytics';
    } finally {
      this.loading = false;
    }
  }

  getScoreTier(score: number): string {
    if (score >= 90) return 'Excellent';
    if (score >= 75) return 'Good';
    if (score >= 50) return 'Needs Improvement';
    if (score >= 25) return 'Poor';
    return 'Critical';
  }

  getRiskIndex(postureScore: number): number {
    return Math.max(0, Math.min(100, 100 - postureScore));
  }
}

describe('Risk Analytics: Posture Scoring and Risk Index Calculation', () => {
  it('correctly maps posture scores to standard cyber grade tiers', () => {
    const mock = new RiskAnalyticsStateMock();
    assert.equal(mock.getScoreTier(100), 'Excellent');
    assert.equal(mock.getScoreTier(90), 'Excellent');
    assert.equal(mock.getScoreTier(89), 'Good');
    assert.equal(mock.getScoreTier(75), 'Good');
    assert.equal(mock.getScoreTier(74), 'Needs Improvement');
    assert.equal(mock.getScoreTier(50), 'Needs Improvement');
    assert.equal(mock.getScoreTier(49), 'Poor');
    assert.equal(mock.getScoreTier(25), 'Poor');
    assert.equal(mock.getScoreTier(24), 'Critical');
    assert.equal(mock.getScoreTier(0), 'Critical');
  });

  it('computes inverted risk index from posture score', () => {
    const mock = new RiskAnalyticsStateMock();
    assert.equal(mock.getRiskIndex(100), 0); // Pristine
    assert.equal(mock.getRiskIndex(85), 15);
    assert.equal(mock.getRiskIndex(40), 60); // High risk
    assert.equal(mock.getRiskIndex(0), 100);  // Maximum risk
  });

  it('determines trend direction and score delta correctly', () => {
    const calcTrend = (first: number, last: number): { delta: number; dir: string } => {
      const delta = last - first;
      if (delta > 3) return { delta, dir: 'improving' };
      if (delta < -3) return { delta, dir: 'degrading' };
      return { delta, dir: 'stable' };
    };

    assert.deepEqual(calcTrend(60, 85), { delta: 25, dir: 'improving' });
    assert.deepEqual(calcTrend(80, 65), { delta: -15, dir: 'degrading' });
    assert.deepEqual(calcTrend(75, 76), { delta: 1, dir: 'stable' });
  });

  it('ranks projects in descending order of risk index and critical density', () => {
    const items: ProjectRiskRankingItem[] = [
      {
        rank: 1,
        project_id: 'p-1',
        project_name: 'App Alpha',
        target_url: 'https://alpha.example.com',
        posture_score: 95,
        risk_index: 5,
        grade: 'Excellent',
        trend: 'stable',
        critical_findings: 0,
        high_findings: 0,
        total_active_findings: 0,
      },
      {
        rank: 2,
        project_id: 'p-2',
        project_name: 'App Beta',
        target_url: 'https://beta.example.com',
        posture_score: 35,
        risk_index: 65,
        grade: 'Poor',
        trend: 'degrading',
        critical_findings: 2,
        high_findings: 3,
        total_active_findings: 5,
      },
      {
        rank: 3,
        project_id: 'p-3',
        project_name: 'App Gamma',
        target_url: 'https://gamma.example.com',
        posture_score: 70,
        risk_index: 30,
        grade: 'Needs Improvement',
        trend: 'improving',
        critical_findings: 0,
        high_findings: 2,
        total_active_findings: 2,
      },
    ];

    // Sort descending by risk_index
    const sorted = [...items].sort((a, b) => b.risk_index - a.risk_index);
    assert.equal(sorted[0].project_name, 'App Beta');  // 65 risk
    assert.equal(sorted[1].project_name, 'App Gamma'); // 30 risk
    assert.equal(sorted[2].project_name, 'App Alpha'); // 5 risk
  });

  it('loads risk summary, trends, and rankings into state asynchronously', async () => {
    const mock = new RiskAnalyticsStateMock();

    await mock.loadData(
      async () => ({
        overall_posture_score: 82,
        grade: 'Good',
        evaluated_at: '2026-11-06T12:00:00Z',
        total_projects: 3,
        total_scans: 12,
        total_findings: 18,
        active_findings: 4,
        severity_distribution: { critical: 0, high: 1, medium: 2, low: 1, informational: 0 },
        status_distribution: { open: 3, in_progress: 1, resolved: 14, accepted_risk: 0, false_positive: 0 },
        domain_breakdown: [
          { domain: 'TLS & Cryptography', finding_count: 0, critical_count: 0, high_count: 0, health_status: 'healthy', description: 'SSL/TLS check' },
          { domain: 'Security Headers', finding_count: 2, critical_count: 0, high_count: 1, health_status: 'warning', description: 'Headers check' },
        ],
        remediation_metrics: {
          remediation_rate_percent: 77.8,
          total_findings_discovered: 18,
          active_findings_count: 4,
          resolved_findings_count: 14,
          mean_time_to_remediate_days: 3.2,
          oldest_open_finding_days: 12.0,
        },
        score_formula_explanation: 'Base 100 with deductions',
        active_caps_applied: [],
      }),
      async () => ({
        total_points: 2,
        timeframe_days: 30,
        trend_direction: 'improving',
        score_delta: 12,
        data_points: [],
      }),
      async () => ({
        total_projects: 1,
        highest_risk_project: 'App Beta',
        rankings: [],
      })
    );

    assert.equal(mock.summary?.overall_posture_score, 82);
    assert.equal(mock.summary?.remediation_metrics.remediation_rate_percent, 77.8);
    assert.equal(mock.trends?.trend_direction, 'improving');
    assert.equal(mock.rankings?.highest_risk_project, 'App Beta');
    assert.equal(mock.loading, false);
    assert.equal(mock.error, null);
  });
});
