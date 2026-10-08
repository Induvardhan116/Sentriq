export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'false_positive';

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
  created_at: string;
  updated_at: string;
}
