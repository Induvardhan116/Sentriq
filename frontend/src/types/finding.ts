export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'false_positive' | 'accepted_risk';

export interface Finding {
  id: string;
  scan_id: string;
  source: string;
  category: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: number;
  risk_score: number;
  cwe?: string | null;
  endpoint?: string | null;
  evidence?: string | null;
  remediation?: string | null;
  status: FindingStatus;
  version?: number;
  justification?: string | null;
  project_id?: string | null;
  project_name?: string | null;
  target_url?: string | null;
  created_at: string;
  updated_at: string;
}

export interface FindingStatusEvent {
  id: string;
  finding_id: string;
  user_id?: string | null;
  user_email?: string | null;
  previous_status: FindingStatus;
  new_status: FindingStatus;
  justification?: string | null;
  created_at: string;
}

export interface PaginatedFindingsResponse {
  items: Finding[];
  total: number;
  limit: number;
  offset: number;
}

export interface FindingsSummaryResponse {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_category: Record<string, number>;
}

export interface FindingFilterParams {
  project_id?: string;
  scan_id?: string;
  status?: FindingStatus;
  severity?: FindingSeverity;
  category?: string;
  search?: string;
  sort_by?: 'risk_score' | 'severity' | 'created_at' | 'updated_at' | 'title' | 'status';
  sort_order?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
}

