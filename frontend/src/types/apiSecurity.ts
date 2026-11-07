export type ApiSpecFormat = 'openapi_3' | 'swagger_2' | 'unknown';

export interface ApiSpec {
  id: string;
  title: string;
  version: string;
  description?: string | null;
  base_url?: string | null;
  spec_format: string;
  endpoint_count: number;
  posture_score: number;
  risk_score: number;
  last_scanned_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApiEndpoint {
  id: string;
  spec_id: string;
  path: string;
  method: string;
  summary?: string | null;
  auth_required: boolean;
  auth_type: string;
  parameters_count: number;
  has_request_body: boolean;
  tags?: string | null;
}

export interface ApiFinding {
  id: string;
  spec_id: string;
  endpoint_id?: string | null;
  path?: string | null;
  method?: string | null;
  owasp_category: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  risk_score: number;
  remediation?: string | null;
  status: 'open' | 'resolved' | 'false_positive' | 'accepted_risk';
  justification?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApiSpecImportPayload {
  title: string;
  version?: string;
  raw_spec: string;
  base_url?: string;
}

export interface ApiFindingStatusUpdate {
  status: 'open' | 'resolved' | 'false_positive' | 'accepted_risk';
  justification?: string;
}
