import type { SystemHealth } from '../types/system';
import type { Project, ProjectCreate } from '../types/project';
import type { Scan, ScanSummary } from '../types/scan';
import type { Finding, FindingStatus } from '../types/finding';

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

export async function fetchSystemHealth(): Promise<{
  data: SystemHealth | null;
  error: string | null;
  latencyMs: number;
}> {
  const start = performance.now();
  try {
    const response = await fetch(apiUrl('/api/system/health'), {
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

export async function fetchProjects(): Promise<Project[]> {
  const res = await fetch(apiUrl('/api/projects'));
  if (!res.ok) throw new Error(`Failed to fetch projects: ${res.statusText}`);
  return res.json();
}

export async function createProject(payload: ProjectCreate): Promise<Project> {
  const res = await fetch(apiUrl('/api/projects'), {
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
  const res = await fetch(apiUrl(`/api/projects/${id}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch project: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerScan(projectId: string): Promise<Scan> {
  const res = await fetch(apiUrl(`/api/projects/${projectId}/scans`), {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to trigger scan: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScan(scanId: string): Promise<Scan> {
  const res = await fetch(apiUrl(`/api/scans/${scanId}`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch scan: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScanFindings(scanId: string): Promise<Finding[]> {
  const res = await fetch(apiUrl(`/api/scans/${scanId}/findings`));
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch findings: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScanSummary(scanId: string): Promise<ScanSummary> {
  const res = await fetch(apiUrl(`/api/scans/${scanId}/summary`));
  if (!res.ok) throw new Error(`Failed to fetch scan summary: ${res.statusText}`);
  return res.json();
}

export async function updateFindingStatus(
  findingId: string,
  status: FindingStatus
): Promise<Finding> {
  const res = await fetch(apiUrl(`/api/findings/${findingId}`), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error(`Failed to update finding status: ${res.statusText}`);
  return res.json();
}
