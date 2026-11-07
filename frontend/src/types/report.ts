export interface ReportAssetCounts {
  projects_count: number;
  repos_count: number;
  api_specs_count: number;
  cloud_accounts_count: number;
  total_monitored: number;
}

export interface ReportPosture {
  score: number;
  risk_score: number;
  grade: string;
}

export interface ReportFindingsSummary {
  total: number;
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  resolved: number;
}

export interface ReportFindingItem {
  id: string;
  source: string;
  asset_name: string;
  title: string;
  severity: string;
  category: string;
  risk_score: number;
  status: string;
  remediation?: string;
  created_at: string;
}

export interface ReportSummaryResponse {
  generated_at: string;
  tenant_email: string;
  assets: ReportAssetCounts;
  posture: ReportPosture;
  findings_summary: ReportFindingsSummary;
  findings: ReportFindingItem[];
}
