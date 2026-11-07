export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface StatusDistribution {
  open: number;
  in_progress: number;
  resolved: number;
  accepted_risk: number;
  false_positive: number;
}

export interface DomainScore {
  domain: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  health_status: 'healthy' | 'warning' | 'critical';
  description: string;
}

export interface RemediationMetrics {
  remediation_rate_percent: number;
  total_findings_discovered: number;
  active_findings_count: number;
  resolved_findings_count: number;
  mean_time_to_remediate_days?: number | null;
  oldest_open_finding_days?: number | null;
  avg_finding_age_days?: number | null;
}

export interface RiskSummaryResponse {
  overall_posture_score: number;
  grade: string;
  evaluated_at: string;
  total_projects: number;
  total_scans: number;
  total_findings: number;
  active_findings: number;
  severity_distribution: SeverityDistribution;
  status_distribution: StatusDistribution;
  domain_breakdown: DomainScore[];
  remediation_metrics: RemediationMetrics;
  score_formula_explanation: string;
  active_caps_applied: string[];
}

export interface PostureTrendPoint {
  scan_id: string;
  project_id: string;
  project_name: string;
  scan_date: string;
  date_label: string;
  posture_score: number;
  grade: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  active_findings_count: number;
}

export interface PostureTrendsResponse {
  total_points: number;
  timeframe_days: number;
  trend_direction: 'improving' | 'degrading' | 'stable' | 'insufficient_data';
  score_delta: number;
  data_points: PostureTrendPoint[];
}

export interface ProjectRiskRankingItem {
  rank: number;
  project_id: string;
  project_name: string;
  target_url: string;
  posture_score: number;
  risk_index: number;
  grade: string;
  trend: 'improving' | 'degrading' | 'stable' | 'new';
  critical_findings: number;
  high_findings: number;
  total_active_findings: number;
  last_scanned_at?: string | null;
  exposure_days?: number | null;
}

export interface ProjectRankingsResponse {
  total_projects: number;
  highest_risk_project?: string | null;
  rankings: ProjectRiskRankingItem[];
}
