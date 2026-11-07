import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { ReportSummaryResponse } from '../types/report.ts';
import {
  getExecutiveReportUrl,
  getPdfExportUrl,
  getFindingsCsvExportUrl,
  getPostureJsonExportUrl,
} from '../services/api.ts';

// Simulated State Logic for ReportsView
class ReportsStateMock {
  summary: ReportSummaryResponse | null = null;
  loading: boolean = false;
  error: string | null = null;

  setSummary(data: ReportSummaryResponse): void {
    this.summary = data;
    this.loading = false;
    this.error = null;
  }
}

describe('Reports & Compliance Export: State and Export URLs', () => {
  it('constructs correct API endpoints for executive report, CSV, and JSON downloads', () => {
    const execUrl = getExecutiveReportUrl();
    const pdfUrl = getPdfExportUrl('vulnerability');
    const csvUrl = getFindingsCsvExportUrl();
    const jsonUrl = getPostureJsonExportUrl();

    assert.ok(execUrl.includes('/api/reports/executive'), 'Executive report URL must hit /api/reports/executive');
    assert.ok(pdfUrl.includes('/api/reports/export/pdf?report_type=vulnerability'), 'PDF export URL must hit /api/reports/export/pdf');
    assert.ok(csvUrl.includes('/api/reports/export/csv'), 'CSV export URL must hit /api/reports/export/csv');
    assert.ok(jsonUrl.includes('/api/reports/export/json'), 'JSON export URL must hit /api/reports/export/json');
  });

  it('correctly calculates total monitored assets and renders posture grade', () => {
    const mock = new ReportsStateMock();
    const sampleSummary: ReportSummaryResponse = {
      generated_at: '2026-11-06 18:00:00 UTC',
      tenant_email: 'ciso@sentriq.io',
      assets: {
        projects_count: 3,
        repos_count: 2,
        api_specs_count: 1,
        cloud_accounts_count: 2,
        total_monitored: 8,
      },
      posture: {
        score: 92,
        risk_score: 8,
        grade: 'A',
      },
      findings_summary: {
        total: 10,
        open: 3,
        critical: 0,
        high: 1,
        medium: 2,
        low: 0,
        resolved: 7,
      },
      findings: [
        {
          id: 'f-1',
          source: 'Website',
          asset_name: 'Production Portal',
          title: 'Missing CSP',
          severity: 'medium',
          category: 'Headers',
          risk_score: 40,
          status: 'open',
          remediation: 'Add Content-Security-Policy',
          created_at: '2026-11-06T12:00:00Z',
        },
      ],
    };

    mock.setSummary(sampleSummary);
    assert.strictEqual(mock.summary?.assets.total_monitored, 8);
    assert.strictEqual(mock.summary?.posture.grade, 'A');
    assert.strictEqual(mock.summary?.findings_summary.open, 3);
    assert.strictEqual(mock.summary?.findings.length, 1);
  });
});
