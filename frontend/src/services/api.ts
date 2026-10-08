import { SystemHealth } from '../types/system';
import { Project, ProjectCreate } from '../types/project';
import { Scan, ScanSummary } from '../types/scan';
import { Finding, FindingStatus } from '../types/finding';

export async function fetchSystemHealth(): Promise<{
  data: SystemHealth | null;
  error: string | null;
  latencyMs: number;
}> {
  const start = performance.now();
  try {
    const response = await fetch('/api/system/health', {
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
  const res = await fetch('/api/projects');
  if (!res.ok) throw new Error(`Failed to fetch projects: ${res.statusText}`);
  return res.json();
}

export async function createProject(payload: ProjectCreate): Promise<Project> {
  const res = await fetch('/api/projects', {
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
  const res = await fetch(`/api/projects/${id}`);
  if (!res.ok) throw new Error(`Failed to fetch project: ${res.statusText}`);
  return res.json();
}

export async function triggerScan(projectId: string): Promise<Scan> {
  const res = await fetch(`/api/projects/${projectId}/scans`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to trigger scan: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScan(scanId: string): Promise<Scan> {
  const res = await fetch(`/api/scans/${scanId}`);
  if (!res.ok) throw new Error(`Failed to fetch scan: ${res.statusText}`);
  return res.json();
}

export async function fetchScanFindings(scanId: string): Promise<Finding[]> {
  const res = await fetch(`/api/scans/${scanId}/findings`);
  if (!res.ok) throw new Error(`Failed to fetch findings: ${res.statusText}`);
  return res.json();
}

export async function fetchScanSummary(scanId: string): Promise<ScanSummary> {
  const res = await fetch(`/api/scans/${scanId}/summary`);
  if (!res.ok) throw new Error(`Failed to fetch scan summary: ${res.statusText}`);
  return res.json();
}

export async function updateFindingStatus(
  findingId: string,
  status: FindingStatus
): Promise<Finding> {
  const res = await fetch(`/api/findings/${findingId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error(`Failed to update finding status: ${res.statusText}`);
  return res.json();
}
