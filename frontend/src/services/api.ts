import { SystemHealth } from '../types/system';

export async function fetchSystemHealth(): Promise<{ data: SystemHealth | null; error: string | null; latencyMs: number }> {
  const start = performance.now();
  try {
    const response = await fetch('/api/system/health', {
      headers: {
        'Accept': 'application/json',
      },
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
