import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { Scan } from '../types/scan.ts';
import type { Finding } from '../types/finding.ts';
import { calculateFindingStatusSummary } from '../utils/findingStatus.ts';

// Simulated state store mimicking ScanDetailView refresh and rescan behaviors
class ScanDetailViewStateMock {
  scan: Scan | null = null;
  findings: Finding[] = [];
  loading = true;
  loadError: string | null = null;
  isRefreshing = false;
  refreshError: string | null = null;
  isFetching = false;
  selectedFinding: Finding | null = null;
  currentRouteScanId: string;

  constructor(scanId: string) {
    this.currentRouteScanId = scanId;
  }

  get statusSummary() {
    return calculateFindingStatusSummary(this.findings);
  }

  handleStatusChange(updated: Finding) {
    this.findings = this.findings.map((f) => (f.id === updated.id ? updated : f));
    if (this.selectedFinding?.id === updated.id) {
      this.selectedFinding = updated;
    }
  }

  async loadScanData(
    isManualRefresh: boolean,
    fetchScanFn: (id: string) => Promise<Scan>,
    fetchFindingsFn: (id: string) => Promise<Finding[]>
  ) {
    // Prevent duplicate simultaneous requests
    if (this.isFetching) return;
    this.isFetching = true;

    if (isManualRefresh) {
      this.isRefreshing = true;
      this.refreshError = null;
    } else if (!this.scan) {
      this.loading = true;
      this.loadError = null;
    }

    try {
      const [scanData, findingsData] = await Promise.all([
        fetchScanFn(this.currentRouteScanId),
        fetchFindingsFn(this.currentRouteScanId),
      ]);
      this.scan = scanData;
      this.findings = findingsData;
      this.refreshError = null;
      this.loadError = null;

      // Sync selected finding if open in modal
      if (this.selectedFinding) {
        const match = findingsData.find((f) => f.id === this.selectedFinding!.id);
        if (match) this.selectedFinding = match;
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Failed to load scan.';
      if (this.scan) {
        // Non-destructive error: preserve existing scan data in view
        this.refreshError = errMsg;
      } else {
        this.loadError = errMsg;
      }
    } finally {
      this.loading = false;
      if (isManualRefresh) {
        this.isRefreshing = false;
      }
      this.isFetching = false;
    }
  }

  async handleRescan(
    triggerScanFn: (projectId: string) => Promise<Scan>
  ): Promise<string | null> {
    if (!this.scan) return null;
    const newScan = await triggerScanFn(this.scan.project_id);
    // Navigation to new scan ID
    this.currentRouteScanId = newScan.id;
    return newScan.id;
  }
}

describe('ScanDetailView Refresh Flow', () => {
  const initialScan: Scan = {
    id: 'scan-100',
    project_id: 'proj-1',
    target_url: 'https://app.example.com',
    status: 'running',
    overall_score: null,
    score_grade: null,
    findings_count: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    info_count: 0,
    created_at: '2026-10-09T10:00:00Z',
  };

  const completedScan: Scan = {
    ...initialScan,
    status: 'completed',
    overall_score: 85,
    score_grade: 'B',
    findings_count: 2,
    critical_count: 0,
    high_count: 1,
    medium_count: 1,
    low_count: 0,
    info_count: 0,
  };

  const initialFindings: Finding[] = [
    {
      id: 'f-1',
      scan_id: 'scan-100',
      source: 'web',
      category: 'headers',
      title: 'Missing Content-Security-Policy',
      description: 'CSP header not set',
      severity: 'high',
      confidence: 1.0,
      risk_score: 75,
      status: 'open',
      created_at: '2026-10-09T10:01:00Z',
    },
    {
      id: 'f-2',
      scan_id: 'scan-100',
      source: 'web',
      category: 'cookies',
      title: 'Missing Secure Flag',
      description: 'Cookie set without secure flag',
      severity: 'medium',
      confidence: 0.9,
      risk_score: 45,
      status: 'open',
      created_at: '2026-10-09T10:01:00Z',
    },
  ];

  it('successful refresh updates scan status, posture score, severity counts, and finding statuses', async () => {
    const view = new ScanDetailViewStateMock('scan-100');
    view.scan = initialScan;
    view.findings = initialFindings;
    view.selectedFinding = initialFindings[0];

    // Backend returns completed scan with resolved finding
    const updatedFindings: Finding[] = [
      { ...initialFindings[0], status: 'resolved' },
      { ...initialFindings[1], status: 'false_positive' },
    ];

    let fetchScanCalls = 0;
    let fetchFindingsCalls = 0;

    const mockFetchScan = async (id: string) => {
      fetchScanCalls++;
      assert.equal(id, 'scan-100');
      return completedScan;
    };
    const mockFetchFindings = async (id: string) => {
      fetchFindingsCalls++;
      assert.equal(id, 'scan-100');
      return updatedFindings;
    };

    await view.loadScanData(true, mockFetchScan, mockFetchFindings);

    // Verify all updated metrics
    assert.equal(fetchScanCalls, 1);
    assert.equal(fetchFindingsCalls, 1);
    assert.equal(view.scan?.status, 'completed');
    assert.equal(view.scan?.overall_score, 85);
    assert.equal(view.scan?.score_grade, 'B');
    assert.equal(view.scan?.high_count, 1);
    assert.equal(view.findings[0].status, 'resolved');
    assert.equal(view.findings[1].status, 'false_positive');
    assert.equal(view.selectedFinding?.status, 'resolved');
    assert.equal(view.refreshError, null);
    assert.equal(view.isRefreshing, false);
    // Preserves scan ID
    assert.equal(view.currentRouteScanId, 'scan-100');
  });

  it('failed refresh retains existing scan data and sets visible refreshError without fatal unmount', async () => {
    const view = new ScanDetailViewStateMock('scan-100');
    view.scan = completedScan;
    view.findings = initialFindings;

    const mockFailingFetch = async () => {
      throw new Error('502 Bad Gateway: Backend temporarily unavailable');
    };

    await view.loadScanData(true, mockFailingFetch, async () => initialFindings);

    // View is preserved, not replaced by fatal error card
    assert.notEqual(view.scan, null);
    assert.equal(view.scan?.id, 'scan-100');
    assert.equal(view.loadError, null);
    // Non-destructive visible refresh error is set
    assert.equal(view.refreshError, '502 Bad Gateway: Backend temporarily unavailable');
    assert.equal(view.isRefreshing, false);
    assert.equal(view.isFetching, false);
  });

  it('prevents duplicate simultaneous refresh requests while a request is in flight', async () => {
    const view = new ScanDetailViewStateMock('scan-100');
    view.scan = initialScan;

    let networkCalls = 0;
    let resolveNetwork: (s: Scan) => void;
    const delayedFetch = () =>
      new Promise<Scan>((res) => {
        networkCalls++;
        resolveNetwork = res;
      });

    // Fire first refresh request (slow network)
    const req1 = view.loadScanData(true, delayedFetch, async () => []);
    assert.equal(view.isRefreshing, true);
    assert.equal(view.isFetching, true);

    // Rapid second click (should be dropped / blocked by isFetching guard)
    const req2 = view.loadScanData(true, delayedFetch, async () => []);

    // Resolve first request
    resolveNetwork!(completedScan);
    await Promise.all([req1, req2]);

    // Exactly 1 network request was dispatched, second duplicate was dropped
    assert.equal(networkCalls, 1);
    assert.equal(view.isRefreshing, false);
    assert.equal(view.isFetching, false);
  });

  it('refresh preserves current scan ID while separate Rescan creates a new scan', async () => {
    const view = new ScanDetailViewStateMock('scan-100');
    view.scan = completedScan;

    // Refresh preserves scan ID
    await view.loadScanData(
      true,
      async () => completedScan,
      async () => initialFindings
    );
    assert.equal(view.currentRouteScanId, 'scan-100');

    // Separate Rescan generates a brand new scan record with new ID
    const newScanId = await view.handleRescan(async (projId: string) => {
      assert.equal(projId, 'proj-1');
      return {
        ...initialScan,
        id: 'scan-200',
        created_at: '2026-10-09T10:15:00Z',
      };
    });

    assert.equal(newScanId, 'scan-200');
    assert.equal(view.currentRouteScanId, 'scan-200');
  });
});

describe('ScanDetailView Finding Status Summary', () => {
  const sampleScan: Scan = {
    id: 'scan-300',
    project_id: 'proj-1',
    target_url: 'https://security.example.com',
    status: 'completed',
    overall_score: 72,
    score_grade: 'C',
    findings_count: 4,
    critical_count: 1,
    high_count: 1,
    medium_count: 1,
    low_count: 1,
    info_count: 0,
    created_at: '2026-10-12T10:00:00Z',
  };

  const sampleFindings: Finding[] = [
    {
      id: 'f-101',
      scan_id: 'scan-300',
      source: 'web',
      category: 'tls',
      title: 'Expired Certificate',
      description: 'TLS certificate is expired',
      severity: 'critical',
      confidence: 1.0,
      risk_score: 95,
      status: 'open',
      created_at: '2026-10-12T10:01:00Z',
    },
    {
      id: 'f-102',
      scan_id: 'scan-300',
      source: 'web',
      category: 'headers',
      title: 'Missing CSP',
      description: 'Content-Security-Policy not configured',
      severity: 'high',
      confidence: 1.0,
      risk_score: 75,
      status: 'in_progress',
      created_at: '2026-10-12T10:01:00Z',
    },
    {
      id: 'f-103',
      scan_id: 'scan-300',
      source: 'web',
      category: 'cookies',
      title: 'Missing SameSite Flag',
      description: 'SameSite not specified on cookie',
      severity: 'medium',
      confidence: 0.9,
      risk_score: 50,
      status: 'resolved',
      created_at: '2026-10-12T10:01:00Z',
    },
    {
      id: 'f-104',
      scan_id: 'scan-300',
      source: 'web',
      category: 'info',
      title: 'Server Banner Disclosed',
      description: 'nginx version exposed in header',
      severity: 'low',
      confidence: 0.8,
      risk_score: 25,
      status: 'false_positive',
      created_at: '2026-10-12T10:01:00Z',
    },
  ];

  it('calculates correct aggregate counts for all finding lifecycle statuses on initial load', async () => {
    const view = new ScanDetailViewStateMock('scan-300');
    await view.loadScanData(
      false,
      async () => sampleScan,
      async () => sampleFindings
    );

    const summary = view.statusSummary;
    assert.equal(summary.total, 4);
    assert.equal(summary.open, 1);
    assert.equal(summary.inProgress, 1);
    assert.equal(summary.resolved, 1);
    assert.equal(summary.falsePositive, 1);

    // Existing severity counters remain intact and unchanged
    assert.equal(view.scan?.critical_count, 1);
    assert.equal(view.scan?.high_count, 1);
    assert.equal(view.scan?.medium_count, 1);
    assert.equal(view.scan?.low_count, 1);
    assert.equal(view.scan?.info_count, 0);
  });

  it('updates status summary immediately when finding status is changed', async () => {
    const view = new ScanDetailViewStateMock('scan-300');
    await view.loadScanData(
      false,
      async () => sampleScan,
      async () => sampleFindings
    );

    // Initial state: 1 open, 1 in_progress, 1 resolved, 1 false_positive
    assert.equal(view.statusSummary.open, 1);
    assert.equal(view.statusSummary.resolved, 1);

    // User marks open finding (f-101) as resolved
    const resolvedFinding: Finding = {
      ...sampleFindings[0],
      status: 'resolved',
    };
    view.handleStatusChange(resolvedFinding);

    // Immediately updates without page reload: open becomes 0, resolved becomes 2
    const updatedSummary = view.statusSummary;
    assert.equal(updatedSummary.total, 4);
    assert.equal(updatedSummary.open, 0);
    assert.equal(updatedSummary.inProgress, 1);
    assert.equal(updatedSummary.resolved, 2);
    assert.equal(updatedSummary.falsePositive, 1);

    // Severity counters remain unchanged
    assert.equal(view.scan?.critical_count, 1);
  });

  it('maintains correct summary across multiple status transitions', async () => {
    const view = new ScanDetailViewStateMock('scan-300');
    await view.loadScanData(
      false,
      async () => sampleScan,
      async () => sampleFindings
    );

    // Move in_progress finding to false_positive
    view.handleStatusChange({
      ...sampleFindings[1],
      status: 'false_positive',
    });

    let summary = view.statusSummary;
    assert.equal(summary.inProgress, 0);
    assert.equal(summary.falsePositive, 2);
    assert.equal(summary.total, 4);

    // Move open finding to in_progress
    view.handleStatusChange({
      ...sampleFindings[0],
      status: 'in_progress',
    });

    summary = view.statusSummary;
    assert.equal(summary.open, 0);
    assert.equal(summary.inProgress, 1);
    assert.equal(summary.resolved, 1);
    assert.equal(summary.falsePositive, 2);
    assert.equal(summary.total, 4);
  });

  it('reload behavior stays correct using backend data as source of truth', async () => {
    const view = new ScanDetailViewStateMock('scan-300');
    await view.loadScanData(
      false,
      async () => sampleScan,
      async () => sampleFindings
    );

    // Backend persisted findings after resolutions made via API
    const persistedBackendFindings: Finding[] = sampleFindings.map((f) => {
      if (f.id === 'f-101') return { ...f, status: 'resolved' };
      if (f.id === 'f-102') return { ...f, status: 'resolved' };
      return f;
    });

    // User triggers manual reload/refresh
    await view.loadScanData(
      true,
      async () => sampleScan,
      async () => persistedBackendFindings
    );

    const reloadedSummary = view.statusSummary;
    assert.equal(reloadedSummary.total, 4);
    assert.equal(reloadedSummary.open, 0);
    assert.equal(reloadedSummary.inProgress, 0);
    assert.equal(reloadedSummary.resolved, 3);
    assert.equal(reloadedSummary.falsePositive, 1);
    assert.equal(view.refreshError, null);
  });

  it('handles empty findings correctly with zero for all counts', async () => {
    const emptyScan: Scan = {
      ...sampleScan,
      id: 'scan-clean',
      findings_count: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      info_count: 0,
    };

    const view = new ScanDetailViewStateMock('scan-clean');
    await view.loadScanData(
      false,
      async () => emptyScan,
      async () => []
    );

    assert.equal(view.findings.length, 0);
    const summary = view.statusSummary;
    assert.deepEqual(summary, {
      total: 0,
      open: 0,
      inProgress: 0,
      resolved: 0,
      falsePositive: 0,
    });
  });

  it('computes status summary during initial loading state when scan is null to prevent conditional hook errors', () => {
    const view = new ScanDetailViewStateMock('scan-loading');
    // Prior to loading completing: scan is null, loading is true, findings is []
    assert.equal(view.scan, null);
    assert.equal(view.loading, true);
    // statusSummary must be safe to compute and available without throwing
    const summary = view.statusSummary;
    assert.deepEqual(summary, {
      total: 0,
      open: 0,
      inProgress: 0,
      resolved: 0,
      falsePositive: 0,
    });
  });

  it('ensures status summary remains available across transition from loading to completed scan without hook drift', async () => {
    const view = new ScanDetailViewStateMock('scan-lifecycle');
    // Phase 1: Initial uninitialized / loading render (scan is null, loading is true)
    assert.equal(view.loading, true);
    assert.equal(view.scan, null);
    const initialSummary = view.statusSummary;
    assert.equal(initialSummary.total, 0);

    // Phase 2: Asynchronous completion transition (scan loaded, findings resolved)
    await view.loadScanData(
      false,
      async () => sampleScan,
      async () => sampleFindings
    );

    assert.equal(view.loading, false);
    assert.notEqual(view.scan, null);
    const completedSummary = view.statusSummary;
    assert.equal(completedSummary.total, 4);
    assert.equal(completedSummary.open, 1);
    assert.equal(completedSummary.inProgress, 1);
    assert.equal(completedSummary.resolved, 1);
    assert.equal(completedSummary.falsePositive, 1);
  });
});


