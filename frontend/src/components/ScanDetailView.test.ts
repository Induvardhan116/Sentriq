import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { Scan } from '../types/scan.ts';
import type { Finding } from '../types/finding.ts';

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
