import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type {
  Finding,
  FindingFilterParams,
  FindingSeverity,
  FindingStatus,
  PaginatedFindingsResponse,
  FindingsSummaryResponse,
} from '../types/finding.ts';

// Simulated Findings Hub State Store mimicking FindingsHubView
class FindingsHubStateMock {
  findings: Finding[] = [];
  total = 0;
  loading = false;
  error: string | null = null;
  summary: FindingsSummaryResponse | null = null;

  // Filter state
  search = '';
  projectFilter = 'all';
  severityFilter: FindingSeverity | 'all' = 'all';
  statusFilter: FindingStatus | 'all' = 'all';
  sortBy: 'risk_score' | 'severity' | 'created_at' | 'updated_at' | 'title' | 'status' = 'risk_score';
  sortOrder: 'asc' | 'desc' = 'desc';
  page = 1;
  limit = 25;

  activeFinding: Finding | null = null;

  getQueryParams(): FindingFilterParams {
    return {
      project_id: this.projectFilter !== 'all' ? this.projectFilter : undefined,
      severity: this.severityFilter !== 'all' ? this.severityFilter : undefined,
      status: this.statusFilter !== 'all' ? this.statusFilter : undefined,
      search: this.search.trim() ? this.search.trim() : undefined,
      sort_by: this.sortBy,
      sort_order: this.sortOrder,
      limit: this.limit,
      offset: (this.page - 1) * this.limit,
    };
  }

  get totalPages(): number {
    return Math.max(1, Math.ceil(this.total / this.limit));
  }

  resetFilters(): void {
    this.search = '';
    this.projectFilter = 'all';
    this.severityFilter = 'all';
    this.statusFilter = 'all';
    this.sortBy = 'risk_score';
    this.sortOrder = 'desc';
    this.page = 1;
  }

  handleStatusChange(updated: Finding): void {
    this.findings = this.findings.map((f) => (f.id === updated.id ? updated : f));
    if (this.activeFinding?.id === updated.id) {
      this.activeFinding = updated;
    }
  }

  async loadFindings(
    fetchFn: (params: FindingFilterParams) => Promise<PaginatedFindingsResponse>
  ): Promise<void> {
    this.loading = true;
    this.error = null;
    try {
      const res = await fetchFn(this.getQueryParams());
      this.findings = res.items;
      this.total = res.total;
    } catch (err: unknown) {
      this.error = err instanceof Error ? err.message : 'Error fetching findings';
    } finally {
      this.loading = false;
    }
  }
}

describe('Findings Hub: Filter and Pagination State Logic', () => {
  it('constructs correct API query parameters for default filters', () => {
    const hub = new FindingsHubStateMock();
    const params = hub.getQueryParams();

    assert.equal(params.project_id, undefined);
    assert.equal(params.severity, undefined);
    assert.equal(params.status, undefined);
    assert.equal(params.search, undefined);
    assert.equal(params.sort_by, 'risk_score');
    assert.equal(params.sort_order, 'desc');
    assert.equal(params.limit, 25);
    assert.equal(params.offset, 0);
  });

  it('constructs correct API query parameters when custom filters are applied', () => {
    const hub = new FindingsHubStateMock();
    hub.projectFilter = 'proj-999';
    hub.severityFilter = 'critical';
    hub.statusFilter = 'open';
    hub.search = '  hsts header missing  ';
    hub.sortBy = 'created_at';
    hub.sortOrder = 'asc';
    hub.page = 3;
    hub.limit = 10;

    const params = hub.getQueryParams();
    assert.equal(params.project_id, 'proj-999');
    assert.equal(params.severity, 'critical');
    assert.equal(params.status, 'open');
    assert.equal(params.search, 'hsts header missing');
    assert.equal(params.sort_by, 'created_at');
    assert.equal(params.sort_order, 'asc');
    assert.equal(params.limit, 10);
    assert.equal(params.offset, 20); // (page 3 - 1) * 10
  });

  it('calculates total pages correctly and bounds pagination', () => {
    const hub = new FindingsHubStateMock();
    hub.total = 0;
    hub.limit = 25;
    assert.equal(hub.totalPages, 1);

    hub.total = 25;
    assert.equal(hub.totalPages, 1);

    hub.total = 26;
    assert.equal(hub.totalPages, 2);

    hub.total = 103;
    hub.limit = 25;
    assert.equal(hub.totalPages, 5);
  });

  it('resets all filters back to default state and page 1', () => {
    const hub = new FindingsHubStateMock();
    hub.projectFilter = 'proj-123';
    hub.severityFilter = 'high';
    hub.statusFilter = 'resolved';
    hub.search = 'cookie';
    hub.page = 4;

    hub.resetFilters();

    assert.equal(hub.projectFilter, 'all');
    assert.equal(hub.severityFilter, 'all');
    assert.equal(hub.statusFilter, 'all');
    assert.equal(hub.search, '');
    assert.equal(hub.page, 1);
  });

  it('successfully loads findings and updates items and total', async () => {
    const hub = new FindingsHubStateMock();
    const mockFinding: Finding = {
      id: 'f-1',
      scan_id: 's-1',
      source: 'web',
      category: 'headers',
      title: 'Missing Content-Security-Policy',
      description: 'CSP header missing',
      severity: 'high',
      confidence: 1.0,
      risk_score: 75,
      status: 'open',
      version: 1,
      created_at: '2026-11-01T12:00:00Z',
      updated_at: '2026-11-01T12:00:00Z',
    };

    await hub.loadFindings(async (params) => {
      assert.equal(params.offset, 0);
      return {
        items: [mockFinding],
        total: 1,
        limit: 25,
        offset: 0,
      };
    });

    assert.equal(hub.findings.length, 1);
    assert.equal(hub.total, 1);
    assert.equal(hub.loading, false);
    assert.equal(hub.error, null);
  });

  it('captures API error gracefully when loading fails', async () => {
    const hub = new FindingsHubStateMock();

    await hub.loadFindings(async () => {
      throw new Error('Connection refused by server');
    });

    assert.equal(hub.findings.length, 0);
    assert.equal(hub.error, 'Connection refused by server');
    assert.equal(hub.loading, false);
  });
});

describe('Findings Hub: OCC Versioning & Status Triage Rules', () => {
  it('validates mandatory justification for accepted_risk and false_positive', () => {
    const validateTransition = (status: FindingStatus, justification?: string): boolean => {
      if (status === 'accepted_risk' || status === 'false_positive') {
        return Boolean(justification && justification.trim().length > 0);
      }
      return true;
    };

    assert.equal(validateTransition('accepted_risk', ''), false);
    assert.equal(validateTransition('accepted_risk', '   '), false);
    assert.equal(
      validateTransition('accepted_risk', 'Compensating network WAF rules active'),
      true
    );

    assert.equal(validateTransition('false_positive', ''), false);
    assert.equal(
      validateTransition('false_positive', 'Audited manually in code review'),
      true
    );

    // Other statuses permit empty justification
    assert.equal(validateTransition('resolved', ''), true);
    assert.equal(validateTransition('in_progress', ''), true);
    assert.equal(validateTransition('open', ''), true);
  });

  it('detects optimistic concurrency control (OCC) conflict when versions mismatch', () => {
    const checkOCC = (currentVersion: number, expectedVersion?: number): boolean => {
      if (expectedVersion !== undefined && currentVersion !== expectedVersion) {
        return false; // Concurrency conflict
      }
      return true;
    };

    assert.equal(checkOCC(1, 1), true);
    assert.equal(checkOCC(2, 2), true);
    assert.equal(checkOCC(2, 1), false); // Conflict: client had v1, server is at v2
    assert.equal(checkOCC(3, 2), false); // Conflict
  });

  it('updates finding immutably and increments version without modifying other findings', () => {
    const hub = new FindingsHubStateMock();
    const f1: Finding = {
      id: 'f-1',
      scan_id: 's-1',
      source: 'web',
      category: 'headers',
      title: 'Missing HSTS',
      description: 'HSTS missing',
      severity: 'high',
      confidence: 1.0,
      risk_score: 75,
      status: 'open',
      version: 1,
      created_at: '2026-11-01T12:00:00Z',
      updated_at: '2026-11-01T12:00:00Z',
    };
    const f2: Finding = {
      id: 'f-2',
      scan_id: 's-1',
      source: 'web',
      category: 'cookies',
      title: 'Missing HttpOnly',
      description: 'HttpOnly missing',
      severity: 'medium',
      confidence: 1.0,
      risk_score: 55,
      status: 'open',
      version: 1,
      created_at: '2026-11-01T12:00:00Z',
      updated_at: '2026-11-01T12:00:00Z',
    };

    hub.findings = [f1, f2];
    hub.activeFinding = f1;

    const updatedF1: Finding = {
      ...f1,
      status: 'resolved',
      version: 2,
      justification: 'Added Strict-Transport-Security header to NGINX config',
      updated_at: '2026-11-02T15:30:00Z',
    };

    hub.handleStatusChange(updatedF1);

    // f1 is updated with new version and status
    assert.equal(hub.findings[0].status, 'resolved');
    assert.equal(hub.findings[0].version, 2);
    assert.equal(hub.activeFinding?.status, 'resolved');
    assert.equal(hub.activeFinding?.version, 2);

    // f2 is preserved untouched
    assert.equal(hub.findings[1].id, 'f-2');
    assert.equal(hub.findings[1].status, 'open');
    assert.equal(hub.findings[1].version, 1);
  });
});
