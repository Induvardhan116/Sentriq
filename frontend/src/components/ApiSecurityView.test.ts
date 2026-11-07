import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type {
  ApiSpec,
  ApiEndpoint,
  ApiFinding,
} from '../types/apiSecurity.ts';

// Simulated State Logic for ApiSecurityView
class ApiSecurityStateMock {
  specs: ApiSpec[] = [];
  selectedSpecId: string | null = null;
  endpoints: ApiEndpoint[] = [];
  findings: ApiFinding[] = [];
  severityFilter: string = 'all';
  statusFilter: string = 'all';

  get filteredFindings(): ApiFinding[] {
    return this.findings.filter((f) => {
      if (this.severityFilter !== 'all' && f.severity !== this.severityFilter) return false;
      if (this.statusFilter !== 'all' && f.status !== this.statusFilter) return false;
      return true;
    });
  }

  addSpec(spec: ApiSpec): void {
    this.specs.unshift(spec);
    this.selectedSpecId = spec.id;
  }

  deleteSpec(specId: string): void {
    this.specs = this.specs.filter((s) => s.id !== specId);
    if (this.selectedSpecId === specId) {
      this.selectedSpecId = this.specs[0]?.id || null;
    }
  }

  updateFindingStatus(findingId: string, newStatus: ApiFinding['status'], justification?: string): void {
    if ((newStatus === 'accepted_risk' || newStatus === 'false_positive') && (!justification || justification.trim().length < 10)) {
      throw new Error('A detailed justification of at least 10 characters is required for risk acceptance or false positives.');
    }
    this.findings = this.findings.map((f) =>
      f.id === findingId ? { ...f, status: newStatus, justification: justification?.trim() } : f
    );
  }
}

describe('API Security Assessment: State and Triage Logic', () => {
  it('manages API spec lifecycle and selected spec transitions', () => {
    const mock = new ApiSecurityStateMock();
    const spec1: ApiSpec = {
      id: 'spec-1',
      title: 'Customer Accounts API',
      version: '1.2.0',
      description: 'Account microservice',
      base_url: 'https://api.sentriq.io/v1',
      spec_format: 'openapi_3',
      endpoint_count: 5,
      posture_score: 85,
      risk_score: 15,
      last_scanned_at: '2026-11-06T12:00:00Z',
      created_at: '2026-11-06T12:00:00Z',
      updated_at: '2026-11-06T12:00:00Z',
    };
    const spec2: ApiSpec = {
      id: 'spec-2',
      title: 'Payments Gateway API',
      version: '3.0.0',
      description: 'Payments microservice',
      base_url: 'https://pay.sentriq.io/v1',
      spec_format: 'openapi_3',
      endpoint_count: 8,
      posture_score: 60,
      risk_score: 40,
      last_scanned_at: '2026-11-06T12:00:00Z',
      created_at: '2026-11-06T12:00:00Z',
      updated_at: '2026-11-06T12:00:00Z',
    };

    mock.addSpec(spec1);
    assert.strictEqual(mock.specs.length, 1);
    assert.strictEqual(mock.selectedSpecId, 'spec-1');

    mock.addSpec(spec2);
    assert.strictEqual(mock.specs.length, 2);
    assert.strictEqual(mock.selectedSpecId, 'spec-2');

    mock.deleteSpec('spec-2');
    assert.strictEqual(mock.specs.length, 1);
    assert.strictEqual(mock.selectedSpecId, 'spec-1');
  });

  it('filters vulnerabilities by severity and status correctly', () => {
    const mock = new ApiSecurityStateMock();
    mock.findings = [
      {
        id: 'f-1',
        spec_id: 'spec-1',
        path: '/v1/users',
        method: 'POST',
        owasp_category: 'API1:2023-Broken-Auth',
        title: 'Missing Auth on Mutation',
        description: 'Endpoint accepts POST without security scheme',
        severity: 'critical',
        confidence: 0.95,
        risk_score: 90,
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
      {
        id: 'f-2',
        spec_id: 'spec-1',
        path: '/v1/users',
        method: 'GET',
        owasp_category: 'API3:2023-Sensitive-Data',
        title: 'Sensitive Field Exposed',
        description: 'Schema includes password_hash field',
        severity: 'high',
        confidence: 0.9,
        risk_score: 75,
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
      {
        id: 'f-3',
        spec_id: 'spec-1',
        path: '/v1/health',
        method: 'GET',
        owasp_category: 'API8:2023-Misconfig',
        title: 'Debug Header Detected',
        description: 'Server returns X-Debug header',
        severity: 'low',
        confidence: 0.8,
        risk_score: 20,
        status: 'resolved',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
    ];

    assert.strictEqual(mock.filteredFindings.length, 3);

    mock.severityFilter = 'critical';
    assert.strictEqual(mock.filteredFindings.length, 1);
    assert.strictEqual(mock.filteredFindings[0].id, 'f-1');

    mock.severityFilter = 'all';
    mock.statusFilter = 'resolved';
    assert.strictEqual(mock.filteredFindings.length, 1);
    assert.strictEqual(mock.filteredFindings[0].id, 'f-3');
  });

  it('validates mandatory justification when triaging to accepted risk or false positive', () => {
    const mock = new ApiSecurityStateMock();
    mock.findings = [
      {
        id: 'f-1',
        spec_id: 'spec-1',
        path: '/v1/transfer',
        method: 'POST',
        owasp_category: 'API1:2023-Broken-Auth',
        title: 'Missing Auth',
        description: 'No auth',
        severity: 'critical',
        confidence: 1.0,
        risk_score: 95,
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
    ];

    // Must fail without justification
    assert.throws(
      () => mock.updateFindingStatus('f-1', 'accepted_risk', ''),
      /detailed justification/i
    );

    // Must fail with too short justification (< 10 chars)
    assert.throws(
      () => mock.updateFindingStatus('f-1', 'false_positive', 'too short'),
      /detailed justification/i
    );

    // Must succeed with detailed justification
    mock.updateFindingStatus('f-1', 'accepted_risk', 'Internal isolated VPC network with IP whitelist');
    assert.strictEqual(mock.findings[0].status, 'accepted_risk');
    assert.strictEqual(mock.findings[0].justification, 'Internal isolated VPC network with IP whitelist');
  });
});
