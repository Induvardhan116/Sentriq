import { Finding } from './finding';

export interface Scan {
  id: string;
  project_id: string;
  target_url: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  started_at?: string | null;
  completed_at?: string | null;
  overall_score?: number | null;
  score_grade?: string | null;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message?: string | null;
  findings?: Finding[];
  created_at: string;
  updated_at: string;
}

export interface ScanSummary {
  id: string;
  project_id: string;
  target_url: string;
  status: string;
  overall_score?: number | null;
  score_grade?: string | null;
  severity_breakdown: Record<string, number>;
  category_breakdown: Record<string, number>;
  top_risks: Finding[];
  completed_at?: string | null;
}
