import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type {
  CloudAccount,
  CloudFinding,
} from '../types/cloudSecurity.ts';

// Simulated State Logic for CloudSecurityView
class CloudSecurityStateMock {
  accounts: CloudAccount[] = [];
  selectedAccountId: string | null = null;
  findings: CloudFinding[] = [];
  serviceFilter: string = 'all';
  severityFilter: string = 'all';
  statusFilter: string = 'all';

  get filteredFindings(): CloudFinding[] {
    return this.findings.filter((f) => {
      if (this.serviceFilter !== 'all' && f.service !== this.serviceFilter) return false;
      if (this.severityFilter !== 'all' && f.severity !== this.severityFilter) return false;
      if (this.statusFilter !== 'all' && f.status !== this.statusFilter) return false;
      return true;
    });
  }

  addAccount(acc: CloudAccount): void {
    this.accounts.unshift(acc);
    this.selectedAccountId = acc.id;
  }

  deleteAccount(accId: string): void {
    this.accounts = this.accounts.filter((a) => a.id !== accId);
    if (this.selectedAccountId === accId) {
      this.selectedAccountId = this.accounts[0]?.id || null;
    }
  }

  updateFindingStatus(findingId: string, newStatus: CloudFinding['status'], justification?: string): void {
    if ((newStatus === 'accepted_risk' || newStatus === 'false_positive') && (!justification || justification.trim().length < 10)) {
      throw new Error('A detailed justification of at least 10 characters is required for risk acceptance or false positives.');
    }
    this.findings = this.findings.map((f) =>
      f.id === findingId ? { ...f, status: newStatus, justification: justification?.trim() } : f
    );
  }
}

describe('Cloud Security (CSPM): State and Compliance Triage Logic', () => {
  it('manages cloud account lifecycle and selection transitions', () => {
    const mock = new CloudSecurityStateMock();
    const acc1: CloudAccount = {
      id: 'acc-1',
      provider: 'aws',
      name: 'Prod AWS Infrastructure',
      account_identifier: '111122223333',
      role_arn_or_ref: 'arn:aws:iam::111122223333:role/SentriqAudit',
      region: 'us-east-1',
      is_active: true,
      posture_score: 90,
      risk_score: 10,
      findings_count: 2,
      last_scanned_at: '2026-11-06T12:00:00Z',
      created_at: '2026-11-06T12:00:00Z',
      updated_at: '2026-11-06T12:00:00Z',
    };
    const acc2: CloudAccount = {
      id: 'acc-2',
      provider: 'supabase',
      name: 'Prod Supabase Instance',
      account_identifier: 'sb-proj-prod',
      role_arn_or_ref: 'sb_secret_****_9918',
      region: 'us-east-1',
      is_active: true,
      posture_score: 75,
      risk_score: 25,
      findings_count: 4,
      last_scanned_at: '2026-11-06T12:00:00Z',
      created_at: '2026-11-06T12:00:00Z',
      updated_at: '2026-11-06T12:00:00Z',
    };

    mock.addAccount(acc1);
    assert.strictEqual(mock.accounts.length, 1);
    assert.strictEqual(mock.selectedAccountId, 'acc-1');

    mock.addAccount(acc2);
    assert.strictEqual(mock.accounts.length, 2);
    assert.strictEqual(mock.selectedAccountId, 'acc-2');

    mock.deleteAccount('acc-2');
    assert.strictEqual(mock.accounts.length, 1);
    assert.strictEqual(mock.selectedAccountId, 'acc-1');
  });

  it('filters compliance findings by cloud service, severity, and status', () => {
    const mock = new CloudSecurityStateMock();
    mock.findings = [
      {
        id: 'cf-1',
        account_id: 'acc-1',
        service: 'storage',
        resource_id: 'company-public-bucket',
        resource_type: 'storage_bucket',
        benchmark_ref: 'CIS-STORAGE-PUBLIC-ACCESS',
        title: 'S3 Bucket Publicly Readable',
        description: 'Bucket ACL permits world read',
        severity: 'critical',
        confidence: 1.0,
        risk_score: 90,
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
      {
        id: 'cf-2',
        account_id: 'acc-1',
        service: 'iam',
        resource_id: 'root-account',
        resource_type: 'iam_user',
        benchmark_ref: 'CIS-IAM-ROOT-MFA',
        title: 'Root MFA Disabled',
        description: 'No hardware MFA configured',
        severity: 'critical',
        confidence: 1.0,
        risk_score: 95,
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
      {
        id: 'cf-3',
        account_id: 'acc-1',
        service: 'network',
        resource_id: 'sg-ssh',
        resource_type: 'security_group',
        benchmark_ref: 'CIS-NET-OPEN-SSH',
        title: 'Open SSH to World',
        description: '0.0.0.0/0 on port 22',
        severity: 'high',
        confidence: 1.0,
        risk_score: 80,
        status: 'resolved',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
    ];

    assert.strictEqual(mock.filteredFindings.length, 3);

    // Filter by service
    mock.serviceFilter = 'storage';
    assert.strictEqual(mock.filteredFindings.length, 1);
    assert.strictEqual(mock.filteredFindings[0].id, 'cf-1');

    // Filter by status
    mock.serviceFilter = 'all';
    mock.statusFilter = 'resolved';
    assert.strictEqual(mock.filteredFindings.length, 1);
    assert.strictEqual(mock.filteredFindings[0].id, 'cf-3');
  });

  it('strictly validates justification length before accepting cloud risk', () => {
    const mock = new CloudSecurityStateMock();
    mock.findings = [
      {
        id: 'cf-1',
        account_id: 'acc-1',
        service: 'database',
        resource_id: 'user_profiles',
        resource_type: 'supabase_table',
        benchmark_ref: 'CIS-SUPABASE-RLS-DISABLED',
        title: 'Table Missing RLS',
        description: 'Public read allowed',
        severity: 'critical',
        confidence: 1.0,
        risk_score: 95,
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
    ];

    assert.throws(
      () => mock.updateFindingStatus('cf-1', 'accepted_risk', ''),
      /detailed justification/i
    );

    assert.throws(
      () => mock.updateFindingStatus('cf-1', 'false_positive', 'ignored'),
      /detailed justification/i
    );

    mock.updateFindingStatus(
      'cf-1',
      'accepted_risk',
      'Table contains exclusively public marketing catalog items by design'
    );
    assert.strictEqual(mock.findings[0].status, 'accepted_risk');
    assert.strictEqual(
      mock.findings[0].justification,
      'Table contains exclusively public marketing catalog items by design'
    );
  });
});
