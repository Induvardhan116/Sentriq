import { SystemHealth } from '../types/system';
import { Project, ProjectCreate } from '../types/project';
import { Scan, ScanSummary } from '../types/scan';
import { Finding, FindingStatus } from '../types/finding';

/**
 * In production (Vercel), VITE_API_BASE_URL is set to the full backend origin
 * including the /api prefix, e.g. "https://sentriq.onrender.com/api".
 *
 * In local development the variable is absent, so API_BASE is an empty string
 * and every fetch('/api/...') is handled by the Vite dev-server proxy.
 *
 * We strip a trailing slash so that path concatenation is always clean.
 */
const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');

/**
 * Build a full URL for a given API path segment.
 *
 * @param path - must start with '/api/...'  (matches the Vite proxy pattern)
 *
 * When API_BASE is empty (local dev), the path is used as-is → proxy handles it.
 * When API_BASE is "https://sentriq.onrender.com/api", the leading "/api" in
 * the path is stripped to avoid "/api/api/..." duplication.
 */
function apiUrl(path: string): string {
  if (!API_BASE) return path;          // local dev – rely on Vite proxy
  // API_BASE already ends with "/api", so remove the leading "/api" from path
  const stripped = path.startsWith('/api') ? path.slice(4) : path;
  return `${API_BASE}${stripped}`;
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
  if (!res.ok) throw new Error(`Failed to fetch project: ${res.statusText}`);
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
  if (!res.ok) throw new Error(`Failed to fetch scan: ${res.statusText}`);
  return res.json();
}

export async function fetchScanFindings(scanId: string): Promise<Finding[]> {
  const res = await fetch(apiUrl(`/api/scans/${scanId}/findings`));
  if (!res.ok) throw new Error(`Failed to fetch findings: ${res.statusText}`);
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
