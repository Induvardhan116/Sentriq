export interface WebhookEndpoint {
  id: string;
  name: string;
  target_url: string;
  secret_token: string;
  event_types: string;
  is_active: boolean;
  last_dispatched_at?: string | null;
  last_status_code?: number | null;
  created_at: string;
  updated_at: string;
}

export interface WebhookCreatePayload {
  name: string;
  target_url: string;
  event_types?: string;
  secret_token?: string;
}

export interface WebhookTestResult {
  success: boolean;
  status_code?: number | null;
  message: string;
  delivered_payload: Record<string, unknown>;
}

export interface ScanSchedule {
  id: string;
  target_type: 'project' | 'repository' | 'cloud_account';
  target_id: string;
  target_name: string;
  frequency: 'daily' | 'weekly' | 'monthly';
  is_active: boolean;
  last_run_at?: string | null;
  next_run_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanScheduleCreatePayload {
  target_type: 'project' | 'repository' | 'cloud_account';
  target_id: string;
  target_name: string;
  frequency: 'daily' | 'weekly' | 'monthly';
}

export interface SiemLogItem {
  timestamp: string;
  event_id: string;
  severity: string;
  source: string;
  asset: string;
  message: string;
  cef_string: string;
}
