export type CloudProvider = 'aws' | 'gcp' | 'supabase' | 'azure';

export interface CloudAccount {
  id: string;
  provider: CloudProvider;
  name: string;
  account_identifier: string;
  role_arn_or_ref: string;
  region: string;
  is_active: boolean;
  posture_score: number;
  risk_score: number;
  findings_count: number;
  connection_status?: string;
  audit_mode?: string;
  last_scanned_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CloudFinding {
  id: string;
  account_id: string;
  service: string;
  resource_id: string;
  resource_type: string;
  benchmark_ref: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  risk_score: number;
  remediation?: string | null;
  status: 'open' | 'resolved' | 'false_positive' | 'accepted_risk';
  justification?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CloudAccountCreate {
  provider: CloudProvider;
  name: string;
  account_identifier: string;
  role_arn_or_ref: string;
  region?: string;
}

export interface CloudFindingStatusUpdate {
  status: 'open' | 'resolved' | 'false_positive' | 'accepted_risk';
  justification?: string;
}
