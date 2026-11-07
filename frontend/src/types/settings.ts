export interface UserProfileResponse {
  id: string;
  email: string;
  full_name?: string | null;
  is_active: boolean;
  is_verified: boolean;
  is_superuser: boolean;
  created_at: string;
  updated_at: string;
}

export interface UserSessionItem {
  id: string;
  ip_address?: string | null;
  user_agent?: string | null;
  created_at: string;
  expires_at: string;
  is_current: boolean;
}

export interface PasswordChangePayload {
  current_password: string;
  new_password: string;
}

export interface UserSettingsResponse {
  id: string;
  user_id: string;
  scanner_timeout_seconds: number;
  scanner_max_redirects: number;
  scanner_verify_ssl: boolean;
  scanner_strict_headers: boolean;
  notify_email_scan_completed: boolean;
  notify_email_critical_finding: boolean;
  notify_webhook_enabled: boolean;
  default_scan_cadence: string;
  theme: string;
  session_timeout_minutes: number;
  created_at: string;
  updated_at: string;
}

export interface UserSettingsUpdatePayload {
  scanner_timeout_seconds?: number;
  scanner_max_redirects?: number;
  scanner_verify_ssl?: boolean;
  scanner_strict_headers?: boolean;
  notify_email_scan_completed?: boolean;
  notify_email_critical_finding?: boolean;
  notify_webhook_enabled?: boolean;
  default_scan_cadence?: string;
  theme?: string;
  session_timeout_minutes?: number;
}
