import type { SystemHealth } from '../types/system';
import type { Project, ProjectCreate, ProjectUpdate } from '../types/project';
import type { Scan, ScanSummary } from '../types/scan';
import type {
  Finding,
  FindingStatus,
  FindingStatusEvent,
  PaginatedFindingsResponse,
  FindingsSummaryResponse,
  FindingFilterParams,
} from '../types/finding';
import type { User, LoginPayload, RegisterPayload, ProfileUpdatePayload, AuthResponse } from '../types/auth';
import type {
  RiskSummaryResponse,
  PostureTrendsResponse,
  ProjectRankingsResponse,
} from '../types/analytics';
import type {
  Repository,
  RepoScan,
  RepoFinding,
  RepositoryCreate,
  RepoFindingStatusUpdate,
} from '../types/repository';
import type {
  ApiSpec,
  ApiEndpoint,
  ApiFinding,
  ApiSpecImportPayload,
  ApiFindingStatusUpdate,
} from '../types/apiSecurity';
import type {
  CloudAccount,
  CloudFinding,
  CloudAccountCreate,
  CloudFindingStatusUpdate,
} from '../types/cloudSecurity';
import type { ReportSummaryResponse } from '../types/report';
import type {
  UserProfileResponse,
  UserSessionItem,
  PasswordChangePayload,
  UserSettingsResponse,
  UserSettingsUpdatePayload,
} from '../types/settings';
import type {
  WebhookEndpoint,
  WebhookCreatePayload,
  WebhookTestResult,
  ScanSchedule,
  ScanScheduleCreatePayload,
  SiemLogItem,
} from '../types/integration';
import type {
  Workspace,
  WorkspaceMember,
  WorkspaceAuditLog,
  WorkspaceCreatePayload,
  WorkspaceInvitePayload,
  WorkspaceRole,
} from '../types/workspace';

/**
 * Same-Origin API Architecture:
 * Both local development (Vite proxy) and production deployment (Vercel reverse proxy)
 * route browser requests to `/api` on the same origin as the frontend.
 *
 * - In local development: Vite proxy routes `/api/...` to `http://127.0.0.1:8000/api/...`
 * - In production (Vercel): Vercel rewrites `/api/:path*` to `https://sentriq.onrender.com/api/:path*`
 *
 * When VITE_API_BASE_URL is omitted or empty, `API_BASE` is `""`, and all requests
 * use relative paths (e.g. `/api/auth/me`), ensuring HttpOnly cookies are treated as first-party
 * and never dropped by browser cross-site / PSL restrictions.
 * If VITE_API_BASE_URL is explicitly defined (e.g. for standalone API testing), it is respected.
 */
const RAW_BASE =
  (typeof import.meta !== 'undefined' && (import.meta as { env?: { VITE_API_BASE_URL?: string } }).env?.VITE_API_BASE_URL) ||
  (typeof globalThis !== 'undefined' && (globalThis as { process?: { env?: Record<string, string> } }).process?.env?.VITE_API_BASE_URL) ||
  '';
const API_BASE = RAW_BASE.replace(/\/$/, '');

/**
 * Pure helper to construct normalized API URLs across various deployment base URL formats.
 * Handles bases ending in '/api', '/api/', with no '/api', and empty string (local dev).
 */
export function buildApiUrl(base: string, path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  if (!base) return normalizedPath;
  const baseOrigin = base.replace(/\/api\/?$/, '').replace(/\/$/, '');
  return `${baseOrigin}${normalizedPath}`;
}

/**
 * Build a full URL for a given API path segment using application config.
 */
export function apiUrl(path: string): string {
  return buildApiUrl(API_BASE, path);
}

/**
 * In-Memory Anti-CSRF Token Management.
 * Security Invariant: CSRF token is held strictly in JavaScript memory (React AuthContext)
 * and NEVER written to localStorage, sessionStorage, or browser-readable cookies.
 */
let inMemoryCsrfToken: string | null = null;

export function setMemoryCsrfToken(token: string | null): void {
  inMemoryCsrfToken = token;
}

export function getMemoryCsrfToken(): string | null {
  return inMemoryCsrfToken;
}

/**
 * Robust wrapper around fetch providing:
 * 1. Strict credentials inclusion (`credentials: 'include'`) for HttpOnly cookie transport.
 * 2. Automatic injection of `X-CSRF-Token` header for state-changing HTTP requests.
 */
async function secureFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const method = (init.method || 'GET').toUpperCase();
  const headers = new Headers(init.headers || {});

  // Add credentials mode if not explicitly set
  const requestInit: RequestInit = {
    ...init,
    credentials: init.credentials || 'include',
  };

  // State-changing requests require the session-bound anti-CSRF token
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    if (inMemoryCsrfToken && !headers.has('X-CSRF-Token')) {
      headers.set('X-CSRF-Token', inMemoryCsrfToken);
    }
  }

  requestInit.headers = headers;
  return fetch(input, requestInit);
}

// =====================================================================
// Authentication API Endpoints
// =====================================================================

export async function authRegister(payload: RegisterPayload): Promise<AuthResponse> {
  const res = await secureFetch(apiUrl('/api/auth/register'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    if (res.status === 503) {
      throw new Error('Authentication is temporarily unavailable. Please try again later.');
    }
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Registration failed (${res.statusText})`);
  }
  const data: AuthResponse = await res.json();
  if (data.csrf_token) {
    setMemoryCsrfToken(data.csrf_token);
  }
  return data;
}

export async function authLogin(payload: LoginPayload): Promise<AuthResponse> {
  const res = await secureFetch(apiUrl('/api/auth/login'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    if (res.status === 503) {
      throw new Error('Authentication is temporarily unavailable. Please try again later.');
    }
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Login failed (${res.statusText})`);
  }
  const data: AuthResponse = await res.json();
  if (data.csrf_token) {
    setMemoryCsrfToken(data.csrf_token);
  }
  return data;
}

export async function authLogout(): Promise<{ message: string }> {
  try {
    const res = await secureFetch(apiUrl('/api/auth/logout'), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Logout failed');
    }
    return res.json();
  } finally {
    // Clear in-memory token on logout regardless of backend response
    setMemoryCsrfToken(null);
  }
}

export async function authGetMe(): Promise<User> {
  const res = await secureFetch(apiUrl('/api/auth/me'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Authentication check failed: ${res.statusText}`);
  }
  const data: User = await res.json();
  if (data.csrf_token) {
    setMemoryCsrfToken(data.csrf_token);
  }
  return data;
}

export async function authUpdateProfile(payload: ProfileUpdatePayload): Promise<User> {
  const res = await secureFetch(apiUrl('/api/auth/profile'), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update profile: ${res.statusText}`);
  }
  const data: User = await res.json();
  if (data.csrf_token) {
    setMemoryCsrfToken(data.csrf_token);
  }
  return data;
}

export async function authRequestPasswordReset(email: string): Promise<{ message: string }> {
  const res = await secureFetch(apiUrl('/api/auth/password-reset/request'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to request password reset: ${res.statusText}`);
  }
  return res.json();
}

export async function authConfirmPasswordReset(token: string, newPassword: string): Promise<{ message: string }> {
  const res = await secureFetch(apiUrl('/api/auth/password-reset/confirm'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, new_password: newPassword }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to reset password: ${res.statusText}`);
  }
  return res.json();
}

export async function authRequestEmailVerification(email?: string): Promise<{ message: string }> {
  const res = await secureFetch(apiUrl('/api/auth/verify-email/request'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(email ? { email } : {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to request verification email: ${res.statusText}`);
  }
  return res.json();
}

export async function authConfirmEmailVerification(token: string): Promise<{ message: string }> {
  const res = await secureFetch(apiUrl('/api/auth/verify-email/confirm'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to verify email: ${res.statusText}`);
  }
  return res.json();
}

// =====================================================================
// System Health
// =====================================================================

export async function fetchSystemHealth(): Promise<{
  data: SystemHealth | null;
  error: string | null;
  latencyMs: number;
}> {
  const start = performance.now();
  try {
    const response = await secureFetch(apiUrl('/api/system/health'), {
      headers: { Accept: 'application/json' },
    });
    const latencyMs = Math.round(performance.now() - start);

    if (!response.ok) {
      return {
        data: null,
        error: `Server responded with HTTP ${response.status} (${response.statusText})`,
        latencyMs,
      };
    }
    const data: SystemHealth = await response.json();
    return { data, error: null, latencyMs };
  } catch (err: unknown) {
    const latencyMs = Math.round(performance.now() - start);
    const message = err instanceof Error ? err.message : 'Failed to reach API server';
    return { data: null, error: message, latencyMs };
  }
}

// =====================================================================
// Projects & Scans
// =====================================================================

export async function fetchProjects(): Promise<Project[]> {
  const res = await secureFetch(apiUrl('/api/projects'));
  if (!res.ok) throw new Error(`Failed to fetch projects: ${res.statusText}`);
  return res.json();
}

export async function createProject(payload: ProjectCreate): Promise<Project> {
  const res = await secureFetch(apiUrl('/api/projects'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create project: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchProject(id: string): Promise<Project> {
  const res = await secureFetch(apiUrl(`/api/projects/${id}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch project: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerScan(projectId: string): Promise<Scan> {
  const res = await secureFetch(apiUrl(`/api/projects/${projectId}/scans`), {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to trigger scan: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScan(scanId: string): Promise<Scan> {
  const res = await secureFetch(apiUrl(`/api/scans/${scanId}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch scan: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScanFindings(scanId: string): Promise<Finding[]> {
  const res = await secureFetch(apiUrl(`/api/scans/${scanId}/findings`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch findings: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScanSummary(scanId: string): Promise<ScanSummary> {
  const res = await secureFetch(apiUrl(`/api/scans/${scanId}/summary`));
  if (!res.ok) throw new Error(`Failed to fetch scan summary: ${res.statusText}`);
  return res.json();
}

export async function updateFindingStatus(
  findingId: string,
  status: FindingStatus,
  justification?: string | null,
  expectedVersion?: number | null
): Promise<Finding> {
  const payload: { status: FindingStatus; justification?: string | null; expected_version?: number | null } = { status };
  if (justification !== undefined) payload.justification = justification;
  if (expectedVersion !== undefined) payload.expected_version = expectedVersion;

  const res = await secureFetch(apiUrl(`/api/findings/${findingId}`), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to update finding status: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchFindingHistory(findingId: string): Promise<FindingStatusEvent[]> {
  const res = await secureFetch(apiUrl(`/api/findings/${findingId}/history`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch finding history: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchFindings(params?: FindingFilterParams): Promise<PaginatedFindingsResponse> {
  const query = new URLSearchParams();
  if (params) {
    if (params.project_id) query.set('project_id', params.project_id);
    if (params.scan_id) query.set('scan_id', params.scan_id);
    if (params.status) query.set('status', params.status);
    if (params.severity) query.set('severity', params.severity);
    if (params.category) query.set('category', params.category);
    if (params.search) query.set('search', params.search);
    if (params.sort_by) query.set('sort_by', params.sort_by);
    if (params.sort_order) query.set('sort_order', params.sort_order);
    if (params.limit !== undefined) query.set('limit', String(params.limit));
    if (params.offset !== undefined) query.set('offset', String(params.offset));
  }
  const qs = query.toString();
  const url = qs ? `/api/findings?${qs}` : '/api/findings';
  const res = await secureFetch(apiUrl(url));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch findings: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchFindingsSummary(params?: { project_id?: string; scan_id?: string }): Promise<FindingsSummaryResponse> {
  const query = new URLSearchParams();
  if (params?.project_id) query.set('project_id', params.project_id);
  if (params?.scan_id) query.set('scan_id', params.scan_id);
  const qs = query.toString();
  const url = qs ? `/api/findings/summary?${qs}` : '/api/findings/summary';
  const res = await secureFetch(apiUrl(url));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch findings summary: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchFinding(findingId: string): Promise<Finding> {
  const res = await secureFetch(apiUrl(`/api/findings/${findingId}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch finding: ${res.statusText}`);
  }
  return res.json();
}

export async function updateProject(
  projectId: string,
  payload: ProjectUpdate
): Promise<Project> {
  const res = await secureFetch(apiUrl(`/api/projects/${projectId}`), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update project: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteProject(
  projectId: string
): Promise<{ success: boolean; message: string; deleted_id?: string }> {
  const res = await secureFetch(apiUrl(`/api/projects/${projectId}`), {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete project: ${res.statusText}`);
  }
  return res.json();
}

export async function claimProject(projectId: string): Promise<Project> {
  const res = await secureFetch(apiUrl(`/api/projects/${projectId}/claim`), {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to claim project: ${res.statusText}`);
  }
  return res.json();
}

// =====================================================================
// Phase 5: Deep Risk Analytics API Endpoints
// =====================================================================

export async function fetchRiskSummary(projectId?: string): Promise<RiskSummaryResponse> {
  const url = projectId ? `/api/analytics/risk-summary?project_id=${encodeURIComponent(projectId)}` : '/api/analytics/risk-summary';
  const res = await secureFetch(apiUrl(url));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch risk summary: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchPostureTrends(params?: { project_id?: string; days?: number }): Promise<PostureTrendsResponse> {
  const query = new URLSearchParams();
  if (params?.project_id) query.set('project_id', params.project_id);
  if (params?.days !== undefined) query.set('days', String(params.days));
  const qs = query.toString();
  const url = qs ? `/api/analytics/posture-trends?${qs}` : '/api/analytics/posture-trends';
  const res = await secureFetch(apiUrl(url));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch posture trends: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchProjectRankings(limit = 50): Promise<ProjectRankingsResponse> {
  const res = await secureFetch(apiUrl(`/api/analytics/project-rankings?limit=${limit}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch project rankings: ${res.statusText}`);
  }
  return res.json();
}

// =====================================================================
// Phase 6: Code Repository Security API Endpoints
// =====================================================================

export async function fetchRepositories(): Promise<Repository[]> {
  const res = await secureFetch(apiUrl('/api/repositories'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch repositories: ${res.statusText}`);
  }
  return res.json();
}

export async function createRepository(payload: RepositoryCreate): Promise<Repository> {
  const res = await secureFetch(apiUrl('/api/repositories'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to register repository: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchRepository(repoId: string): Promise<Repository> {
  const res = await secureFetch(apiUrl(`/api/repositories/${repoId}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch repository: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteRepository(repoId: string): Promise<{ success: boolean; message: string }> {
  const res = await secureFetch(apiUrl(`/api/repositories/${repoId}`), {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete repository: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerRepoScan(
  repoId: string,
  files?: Record<string, string>,
  branch = 'main'
): Promise<RepoScan> {
  const res = await secureFetch(apiUrl(`/api/repositories/${repoId}/scan?branch=${encodeURIComponent(branch)}`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(files || {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to execute repository scan: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchRepoScans(repoId: string): Promise<RepoScan[]> {
  const res = await secureFetch(apiUrl(`/api/repositories/${repoId}/scans`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch repository scans: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchRepoFindings(
  repoId: string,
  params?: { scan_type?: string; severity?: string; status?: string }
): Promise<RepoFinding[]> {
  const query = new URLSearchParams();
  if (params?.scan_type) query.set('scan_type', params.scan_type);
  if (params?.severity) query.set('severity', params.severity);
  if (params?.status) query.set('status', params.status);
  const qs = query.toString();
  const url = qs ? `/api/repositories/${repoId}/findings?${qs}` : `/api/repositories/${repoId}/findings`;
  const res = await secureFetch(apiUrl(url));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch repository findings: ${res.statusText}`);
  }
  return res.json();
}

export async function updateRepoFindingStatus(
  findingId: string,
  payload: RepoFindingStatusUpdate
): Promise<RepoFinding> {
  const res = await secureFetch(apiUrl(`/api/repositories/findings/${findingId}`), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update finding status: ${res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------
// Phase 7: API Security Assessment
// ---------------------------------------------------------

export async function importApiSpec(payload: ApiSpecImportPayload): Promise<ApiSpec> {
  const res = await secureFetch(apiUrl('/api/api-security/specs'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to import API specification: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchApiSpecs(): Promise<ApiSpec[]> {
  const res = await secureFetch(apiUrl('/api/api-security/specs'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch API specs: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchApiSpec(specId: string): Promise<ApiSpec> {
  const res = await secureFetch(apiUrl(`/api/api-security/specs/${specId}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch API spec: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteApiSpec(specId: string): Promise<void> {
  const res = await secureFetch(apiUrl(`/api/api-security/specs/${specId}`), {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete API spec: ${res.statusText}`);
  }
}

export async function fetchApiEndpoints(specId: string): Promise<ApiEndpoint[]> {
  const res = await secureFetch(apiUrl(`/api/api-security/specs/${specId}/endpoints`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch API endpoints: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchApiFindings(
  specId: string,
  params?: { severity?: string; status?: string }
): Promise<ApiFinding[]> {
  const query = new URLSearchParams();
  if (params?.severity) query.set('severity', params.severity);
  if (params?.status) query.set('status', params.status);
  const qs = query.toString();
  const url = qs ? `/api/api-security/specs/${specId}/findings?${qs}` : `/api/api-security/specs/${specId}/findings`;
  const res = await secureFetch(apiUrl(url));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch API findings: ${res.statusText}`);
  }
  return res.json();
}

export async function updateApiFindingStatus(
  findingId: string,
  payload: ApiFindingStatusUpdate
): Promise<ApiFinding> {
  const res = await secureFetch(apiUrl(`/api/api-security/findings/${findingId}`), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update API finding status: ${res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------
// Phase 8: Cloud Security Posture (CSPM)
// ---------------------------------------------------------

export async function createCloudAccount(payload: CloudAccountCreate): Promise<CloudAccount> {
  const res = await secureFetch(apiUrl('/api/cloud-security/accounts'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to connect cloud account: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCloudAccounts(): Promise<CloudAccount[]> {
  const res = await secureFetch(apiUrl('/api/cloud-security/accounts'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch cloud accounts: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCloudAccount(accountId: string): Promise<CloudAccount> {
  const res = await secureFetch(apiUrl(`/api/cloud-security/accounts/${accountId}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch cloud account: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteCloudAccount(accountId: string): Promise<void> {
  const res = await secureFetch(apiUrl(`/api/cloud-security/accounts/${accountId}`), {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete cloud account: ${res.statusText}`);
  }
}

export async function scanCloudAccount(accountId: string, configData?: Record<string, unknown>): Promise<CloudAccount> {
  const res = await secureFetch(apiUrl(`/api/cloud-security/accounts/${accountId}/scan`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ config_data: configData || null }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to scan cloud account: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCloudFindings(
  accountId: string,
  params?: { service?: string; severity?: string; status?: string }
): Promise<CloudFinding[]> {
  const query = new URLSearchParams();
  if (params?.service) query.set('service', params.service);
  if (params?.severity) query.set('severity', params.severity);
  if (params?.status) query.set('status', params.status);
  const qs = query.toString();
  const url = qs ? `/api/cloud-security/accounts/${accountId}/findings?${qs}` : `/api/cloud-security/accounts/${accountId}/findings`;
  const res = await secureFetch(apiUrl(url));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch cloud findings: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCloudFindingStatus(
  findingId: string,
  payload: CloudFindingStatusUpdate
): Promise<CloudFinding> {
  const res = await secureFetch(apiUrl(`/api/cloud-security/findings/${findingId}`), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update cloud finding status: ${res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------
// Phase 9: Reports and Export Engine
// ---------------------------------------------------------

export async function fetchReportSummary(): Promise<ReportSummaryResponse> {
  const res = await secureFetch(apiUrl('/api/reports/summary'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch report summary: ${res.statusText}`);
  }
  return res.json();
}

export function getExecutiveReportUrl(): string {
  return apiUrl('/api/reports/executive');
}

export function getPdfExportUrl(reportType: string = 'executive'): string {
  return apiUrl(`/api/reports/export/pdf?report_type=${encodeURIComponent(reportType)}`);
}

export function getFindingsCsvExportUrl(): string {
  return apiUrl('/api/reports/export/csv');
}

export function getPostureJsonExportUrl(): string {
  return apiUrl('/api/reports/export/json');
}

// ---------------------------------------------------------
// Phase 10: Settings & Session Management
// ---------------------------------------------------------

export async function fetchProfile(): Promise<UserProfileResponse> {
  const res = await secureFetch(apiUrl('/api/settings/profile'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch user profile: ${res.statusText}`);
  }
  return res.json();
}

export async function updateProfile(payload: { full_name: string }): Promise<UserProfileResponse> {
  const res = await secureFetch(apiUrl('/api/settings/profile'), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update user profile: ${res.statusText}`);
  }
  return res.json();
}

export async function changePassword(payload: PasswordChangePayload): Promise<{ message: string }> {
  const res = await secureFetch(apiUrl('/api/settings/password'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to change password: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchActiveSessions(): Promise<UserSessionItem[]> {
  const res = await secureFetch(apiUrl('/api/settings/sessions'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch active sessions: ${res.statusText}`);
  }
  return res.json();
}

export async function revokeSession(sessionId: string): Promise<{ message: string }> {
  const res = await secureFetch(apiUrl(`/api/settings/sessions/${sessionId}`), {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to revoke session: ${res.statusText}`);
  }
  return res.json();
}

export async function revokeOtherSessions(): Promise<{ message: string; revoked_count: number }> {
  const res = await secureFetch(apiUrl('/api/settings/sessions/revoke-others'), {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to revoke other sessions: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchUserPreferences(): Promise<UserSettingsResponse> {
  const res = await secureFetch(apiUrl('/api/settings/preferences'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch preferences: ${res.statusText}`);
  }
  return res.json();
}

export async function updateUserPreferences(payload: UserSettingsUpdatePayload): Promise<UserSettingsResponse> {
  const res = await secureFetch(apiUrl('/api/settings/preferences'), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update preferences: ${res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------
// Phase 11: Integrations and Automation
// ---------------------------------------------------------

export async function fetchWebhooks(): Promise<WebhookEndpoint[]> {
  const res = await secureFetch(apiUrl('/api/integrations/webhooks'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch webhooks: ${res.statusText}`);
  }
  return res.json();
}

export async function createWebhook(payload: WebhookCreatePayload): Promise<WebhookEndpoint> {
  const res = await secureFetch(apiUrl('/api/integrations/webhooks'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create webhook: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteWebhook(webhookId: string): Promise<void> {
  const res = await secureFetch(apiUrl(`/api/integrations/webhooks/${webhookId}`), {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete webhook: ${res.statusText}`);
  }
}

export async function testWebhook(webhookId: string): Promise<WebhookTestResult> {
  const res = await secureFetch(apiUrl(`/api/integrations/webhooks/${webhookId}/test`), {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to test webhook: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSchedules(): Promise<ScanSchedule[]> {
  const res = await secureFetch(apiUrl('/api/integrations/schedules'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch scan schedules: ${res.statusText}`);
  }
  return res.json();
}

export async function createSchedule(payload: ScanScheduleCreatePayload): Promise<ScanSchedule> {
  const res = await secureFetch(apiUrl('/api/integrations/schedules'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create scan schedule: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteSchedule(scheduleId: string): Promise<void> {
  const res = await secureFetch(apiUrl(`/api/integrations/schedules/${scheduleId}`), {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete scan schedule: ${res.statusText}`);
  }
}

export async function executeScanSchedule(scheduleId: string): Promise<{ message: string; schedule_id: string; last_run_at: string; next_run_at: string }> {
  const res = await secureFetch(apiUrl(`/api/integrations/schedules/${scheduleId}/run`), {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to trigger scheduled scan: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSiemEvents(): Promise<SiemLogItem[]> {
  const res = await secureFetch(apiUrl('/api/integrations/siem/events'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch SIEM events: ${res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------
// Phase 12: Enterprise Governance & Multi-Tenant Workspaces
// ---------------------------------------------------------

export async function createWorkspace(payload: WorkspaceCreatePayload): Promise<Workspace> {
  const res = await secureFetch(apiUrl('/api/workspaces'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create workspace: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchWorkspaces(): Promise<Workspace[]> {
  const res = await secureFetch(apiUrl('/api/workspaces'));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch workspaces: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchWorkspace(workspaceId: string): Promise<Workspace> {
  const res = await secureFetch(apiUrl(`/api/workspaces/${workspaceId}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch workspace: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchWorkspaceMembers(workspaceId: string): Promise<WorkspaceMember[]> {
  const res = await secureFetch(apiUrl(`/api/workspaces/${workspaceId}/members`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch workspace members: ${res.statusText}`);
  }
  return res.json();
}

export async function inviteWorkspaceMember(
  workspaceId: string,
  payload: WorkspaceInvitePayload
): Promise<WorkspaceMember> {
  const res = await secureFetch(apiUrl(`/api/workspaces/${workspaceId}/members`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to invite member: ${res.statusText}`);
  }
  return res.json();
}

export async function updateWorkspaceMemberRole(
  workspaceId: string,
  userId: string,
  role: WorkspaceRole
): Promise<WorkspaceMember> {
  const res = await secureFetch(apiUrl(`/api/workspaces/${workspaceId}/members/${userId}`), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update member role: ${res.statusText}`);
  }
  return res.json();
}

export async function removeWorkspaceMember(workspaceId: string, userId: string): Promise<void> {
  const res = await secureFetch(apiUrl(`/api/workspaces/${workspaceId}/members/${userId}`), {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to remove member: ${res.statusText}`);
  }
}

export async function fetchWorkspaceAuditLogs(workspaceId: string): Promise<WorkspaceAuditLog[]> {
  const res = await secureFetch(apiUrl(`/api/workspaces/${workspaceId}/audit-logs`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch audit logs: ${res.statusText}`);
  }
  return res.json();
}
