import type { Finding } from '../types/finding';

export interface FindingStatusSummary {
  total: number;
  open: number;
  inProgress: number;
  resolved: number;
  falsePositive: number;
}

/**
 * Computes aggregate counts for finding lifecycle statuses.
 * Source of truth is the current array of findings for the scan.
 */
export function calculateFindingStatusSummary(findings?: Finding[] | null): FindingStatusSummary {
  if (!findings || !Array.isArray(findings)) {
    return {
      total: 0,
      open: 0,
      inProgress: 0,
      resolved: 0,
      falsePositive: 0,
    };
  }
  let open = 0;
  let inProgress = 0;
  let resolved = 0;
  let falsePositive = 0;

  for (const f of findings) {
    const raw = f?.status ? String(f.status).toLowerCase().trim() : '';
    const status = raw.replace(/[-\s]+/g, '_');
    if (status === 'open') {
      open++;
    } else if (status === 'in_progress') {
      inProgress++;
    } else if (status === 'resolved') {
      resolved++;
    } else if (status === 'false_positive') {
      falsePositive++;
    }
  }

  return {
    total: findings.length,
    open,
    inProgress,
    resolved,
    falsePositive,
  };
}
