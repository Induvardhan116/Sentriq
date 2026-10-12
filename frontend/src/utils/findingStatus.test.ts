import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { calculateFindingStatusSummary } from './findingStatus.ts';
import type { Finding } from '../types/finding.ts';

describe('Finding Status Aggregation: calculateFindingStatusSummary', () => {
  it('correctly aggregates findings by lifecycle status and computes total', () => {
    const findings: Finding[] = [
      {
        id: 'f-1',
        scan_id: 's-1',
        source: 'web',
        category: 'headers',
        title: 'Missing HSTS',
        description: 'HSTS header missing',
        severity: 'high',
        confidence: 1.0,
        risk_score: 80,
        status: 'open',
        created_at: '2026-10-12T00:00:00Z',
        updated_at: '2026-10-12T00:00:00Z',
      },
      {
        id: 'f-2',
        scan_id: 's-1',
        source: 'web',
        category: 'cookies',
        title: 'Missing HttpOnly',
        description: 'Cookie missing HttpOnly',
        severity: 'medium',
        confidence: 0.9,
        risk_score: 50,
        status: 'in_progress',
        created_at: '2026-10-12T00:00:00Z',
        updated_at: '2026-10-12T00:00:00Z',
      },
      {
        id: 'f-3',
        scan_id: 's-1',
        source: 'web',
        category: 'headers',
        title: 'Missing CSP',
        description: 'CSP missing',
        severity: 'high',
        confidence: 1.0,
        risk_score: 75,
        status: 'resolved',
        created_at: '2026-10-12T00:00:00Z',
        updated_at: '2026-10-12T00:00:00Z',
      },
      {
        id: 'f-4',
        scan_id: 's-1',
        source: 'web',
        category: 'info',
        title: 'Server Banner Disclosed',
        description: 'Server banner visible',
        severity: 'low',
        confidence: 0.8,
        risk_score: 20,
        status: 'false_positive',
        created_at: '2026-10-12T00:00:00Z',
        updated_at: '2026-10-12T00:00:00Z',
      },
      {
        id: 'f-5',
        scan_id: 's-1',
        source: 'web',
        category: 'tls',
        title: 'TLS 1.0 Enabled',
        description: 'Legacy TLS protocol',
        severity: 'critical',
        confidence: 1.0,
        risk_score: 95,
        status: 'open',
        created_at: '2026-10-12T00:00:00Z',
        updated_at: '2026-10-12T00:00:00Z',
      },
    ];

    const summary = calculateFindingStatusSummary(findings);

    assert.equal(summary.total, 5);
    assert.equal(summary.open, 2);
    assert.equal(summary.inProgress, 1);
    assert.equal(summary.resolved, 1);
    assert.equal(summary.falsePositive, 1);
  });

  it('handles empty findings array cleanly with all zeros', () => {
    const summary = calculateFindingStatusSummary([]);

    assert.deepEqual(summary, {
      total: 0,
      open: 0,
      inProgress: 0,
      resolved: 0,
      falsePositive: 0,
    });
  });

  it('handles null and undefined input gracefully without throwing', () => {
    assert.deepEqual(calculateFindingStatusSummary(null), {
      total: 0,
      open: 0,
      inProgress: 0,
      resolved: 0,
      falsePositive: 0,
    });

    assert.deepEqual(calculateFindingStatusSummary(undefined), {
      total: 0,
      open: 0,
      inProgress: 0,
      resolved: 0,
      falsePositive: 0,
    });
  });

  it('normalizes status casing, hyphens, and whitespace', () => {
    const findings = [
      { id: '1', status: 'OPEN' },
      { id: '2', status: 'in-progress' },
      { id: '3', status: 'In Progress' },
      { id: '4', status: 'RESOLVED' },
      { id: '5', status: 'false-positive' },
      { id: '6', status: 'False Positive' },
    ] as Finding[];

    const summary = calculateFindingStatusSummary(findings);

    assert.equal(summary.total, 6);
    assert.equal(summary.open, 1);
    assert.equal(summary.inProgress, 2);
    assert.equal(summary.resolved, 1);
    assert.equal(summary.falsePositive, 2);
  });

  it('counts unknown status toward total without corrupting specific buckets', () => {
    const findings = [
      { id: '1', status: 'open' },
      { id: '2', status: 'custom_unknown_status' as any },
    ] as Finding[];

    const summary = calculateFindingStatusSummary(findings);

    assert.equal(summary.total, 2);
    assert.equal(summary.open, 1);
    assert.equal(summary.inProgress, 0);
    assert.equal(summary.resolved, 0);
    assert.equal(summary.falsePositive, 0);
  });
});
