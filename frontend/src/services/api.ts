import type { SystemHealth } from '../types/system';
import type { Project, ProjectCreate, ProjectUpdate } from '../types/project';
import type { Scan, ScanSummary } from '../types/scan';
import type { Finding, FindingStatus } from '../types/finding';
import type { User, LoginPayload, RegisterPayload, ProfileUpdatePayload, AuthResponse } from '../types/auth';

/**
 * In production (Vercel), VITE_API_BASE_URL is set to the full backend origin
 * including the /api prefix, e.g. "https://sentriq.onrender.com/api".
 *
 * In local development the variable is absent, so API_BASE is an empty string
 * and every fetch('/api/...') is handled by the Vite dev-server proxy.
 *
 * We strip a trailing slash so that path concatenation is always clean.
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
  status: FindingStatus
): Promise<Finding> {
  const res = await secureFetch(apiUrl(`/api/findings/${findingId}`), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error(`Failed to update finding status: ${res.statusText}`);
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
