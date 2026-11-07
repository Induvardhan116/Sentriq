export type RepoScanType = 'secret' | 'sast' | 'sca';
export type RepoSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type RepoFindingStatus = 'open' | 'resolved' | 'false_positive' | 'accepted_risk';

export interface Repository {
  id: string;
  name: string;
  full_name: string;
  clone_url: string;
  default_branch: string;
  languages?: string | null;
  is_private: boolean;
  authorization_confirmed: boolean;
  owner_id?: string | null;
  last_scanned_at?: string | null;
  latest_posture_score: number;
  latest_risk_score: number;
  created_at: string;
  updated_at: string;
}

export interface RepoScan {
  id: string;
  repository_id: string;
  branch: string;
  commit_hash?: string | null;
  status: 'queued' | 'running' | 'completed' | 'failed';
  started_at?: string | null;
  completed_at?: string | null;
  posture_score: number;
  findings_count: number;
  secret_count: number;
  sast_count: number;
  sca_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  error_message?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RepoFinding {
  id: string;
  scan_id: string;
  scan_type: RepoScanType;
  title: string;
  description: string;
  severity: RepoSeverity;
  confidence: number;
  risk_score: number;
  file_path: string;
  line_number?: number | null;
  rule_id: string;
  cwe?: string | null;
  cve?: string | null;
  snippet?: string | null;
  remediation?: string | null;
  status: RepoFindingStatus;
  justification?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RepositoryCreate {
  name: string;
  full_name: string;
  clone_url: string;
  default_branch?: string;
  languages?: string;
  is_private?: boolean;
  authorization_confirmed?: boolean;
}

export interface RepoFindingStatusUpdate {
  status: RepoFindingStatus;
  justification?: string;
}
