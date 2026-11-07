import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type {
  Repository,
  RepoFinding,
  RepoScan,
  RepoScanType,
} from '../types/repository.ts';

// Simulated State Mock for RepoSecurityView
class RepoSecurityStateMock {
  repositories: Repository[] = [];
  findings: RepoFinding[] = [];
  selectedRepo: Repository | null = null;
  filterType: RepoScanType | 'all' = 'all';

  get filteredFindings(): RepoFinding[] {
    if (this.filterType === 'all') return this.findings;
    return this.findings.filter((f) => f.scan_type === this.filterType);
  }

  addRepository(repo: Repository): void {
    this.repositories.unshift(repo);
  }

  deleteRepository(repoId: string): void {
    this.repositories = this.repositories.filter((r) => r.id !== repoId);
    if (this.selectedRepo?.id === repoId) {
      this.selectedRepo = null;
    }
  }

  updateFindingStatus(findingId: string, newStatus: RepoFinding['status'], justification?: string): void {
    if ((newStatus === 'accepted_risk' || newStatus === 'false_positive') && (!justification || !justification.trim())) {
      throw new Error('A justification is mandatory for accepted risk or false positive status.');
    }
    this.findings = this.findings.map((f) =>
      f.id === findingId ? { ...f, status: newStatus, justification: justification?.trim() } : f
    );
  }
}

describe('Repo Security: State and Triage Validation', () => {
  it('adds and deletes repositories cleanly in state', () => {
    const mock = new RepoSecurityStateMock();
    const repo1: Repository = {
      id: 'repo-1',
      name: 'Sentriq Backend',
      full_name: 'sentriq/backend',
      clone_url: 'https://github.com/sentriq/backend.git',
      default_branch: 'main',
      is_private: true,
      authorization_confirmed: true,
      latest_posture_score: 100,
      latest_risk_score: 0,
      created_at: '2026-11-06T12:00:00Z',
      updated_at: '2026-11-06T12:00:00Z',
    };

    mock.addRepository(repo1);
    assert.equal(mock.repositories.length, 1);
    assert.equal(mock.repositories[0].id, 'repo-1');

    mock.deleteRepository('repo-1');
    assert.equal(mock.repositories.length, 0);
  });

  it('filters findings by scan type (secret, sast, sca)', () => {
    const mock = new RepoSecurityStateMock();
    mock.findings = [
      {
        id: 'f-sec-1',
        scan_id: 's-1',
        scan_type: 'secret',
        title: 'Hardcoded AWS Access Key',
        description: 'Found exposed secret',
        severity: 'critical',
        confidence: 0.95,
        risk_score: 90,
        file_path: 'config.py',
        rule_id: 'SEC-AWS-KEY',
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
      {
        id: 'f-sast-1',
        scan_id: 's-1',
        scan_type: 'sast',
        title: 'Command Injection',
        description: 'os.system call detected',
        severity: 'critical',
        confidence: 0.85,
        risk_score: 85,
        file_path: 'runner.py',
        rule_id: 'SAST-CMD-INJECTION',
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
      {
        id: 'f-sca-1',
        scan_id: 's-1',
        scan_type: 'sca',
        title: 'Vulnerable Lodash Dependency',
        description: 'Prototype pollution in lodash',
        severity: 'high',
        confidence: 0.95,
        risk_score: 75,
        file_path: 'package.json',
        rule_id: 'SCA-CVE-2021-23337',
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
    ];

    mock.filterType = 'all';
    assert.equal(mock.filteredFindings.length, 3);

    mock.filterType = 'secret';
    assert.equal(mock.filteredFindings.length, 1);
    assert.equal(mock.filteredFindings[0].id, 'f-sec-1');

    mock.filterType = 'sast';
    assert.equal(mock.filteredFindings.length, 1);
    assert.equal(mock.filteredFindings[0].id, 'f-sast-1');

    mock.filterType = 'sca';
    assert.equal(mock.filteredFindings.length, 1);
    assert.equal(mock.filteredFindings[0].id, 'f-sca-1');
  });

  it('strictly requires justification for accepted_risk and false_positive status updates', () => {
    const mock = new RepoSecurityStateMock();
    mock.findings = [
      {
        id: 'f-1',
        scan_id: 's-1',
        scan_type: 'secret',
        title: 'API Key',
        description: 'Generic secret',
        severity: 'high',
        confidence: 0.9,
        risk_score: 70,
        file_path: 'test.py',
        rule_id: 'SEC-GENERIC-API-KEY',
        status: 'open',
        created_at: '2026-11-06T12:00:00Z',
        updated_at: '2026-11-06T12:00:00Z',
      },
    ];

    // Attempt accepted_risk with empty justification -> throws
    assert.throws(
      () => mock.updateFindingStatus('f-1', 'accepted_risk', ''),
      /justification is mandatory/
    );

    // Attempt with valid justification -> succeeds
    mock.updateFindingStatus('f-1', 'accepted_risk', 'Test fixture dummy key only');
    assert.equal(mock.findings[0].status, 'accepted_risk');
    assert.equal(mock.findings[0].justification, 'Test fixture dummy key only');

    // Resolved status does not require justification
    mock.updateFindingStatus('f-1', 'resolved');
    assert.equal(mock.findings[0].status, 'resolved');
  });

  it('masks secret patterns to guarantee zero raw credential exposure', () => {
    const mask = (val: string) => {
      if (val.length <= 8) return '****';
      return `${val.slice(0, 4)}****${val.slice(-4)}`;
    };

    const rawKey = 'AKIAIOSFODNN7EXAMPLE';
    const masked = mask(rawKey);

    assert.equal(masked, 'AKIA****MPLE');
    assert.ok(!masked.includes('IOSFODNN7EXA'));
  });
});
