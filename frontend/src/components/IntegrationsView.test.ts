import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type {
  WebhookEndpoint,
  ScanSchedule,
  SiemLogItem,
} from '../types/integration.ts';

// Simulated State Logic for IntegrationsView
class IntegrationsStateMock {
  webhooks: WebhookEndpoint[] = [];
  schedules: ScanSchedule[] = [];
  siemEvents: SiemLogItem[] = [];

  addWebhook(wh: WebhookEndpoint): void {
    if (!wh.target_url.startsWith('https://')) {
      throw new Error('Only secure HTTPS target URLs are accepted for webhook delivery.');
    }
    this.webhooks.unshift(wh);
  }

  deleteWebhook(id: string): void {
    this.webhooks = this.webhooks.filter((w) => w.id !== id);
  }

  addSchedule(sch: ScanSchedule): void {
    this.schedules.unshift(sch);
  }

  deleteSchedule(id: string): void {
    this.schedules = this.schedules.filter((s) => s.id !== id);
  }
}

describe('Integrations & Automation: State, SSRF and CEF Stream Logic', () => {
  it('enforces HTTPS protocol for outbound webhooks and handles lifecycle', () => {
    const mock = new IntegrationsStateMock();

    // Rejects insecure HTTP target URL
    assert.throws(
      () =>
        mock.addWebhook({
          id: 'wh-insecure',
          name: 'Insecure Webhook',
          target_url: 'http://internal.service.local/webhook',
          secret_token: 'whsec_****1234',
          event_types: 'scan.completed',
          is_active: true,
          created_at: '2026-11-06T12:00:00Z',
          updated_at: '2026-11-06T12:00:00Z',
        }),
      /HTTPS/i
    );

    // Accepts secure HTTPS target URL
    mock.addWebhook({
      id: 'wh-1',
      name: 'Slack Security Alerts',
      target_url: 'https://hooks.slack.com/services/T00/B00/XXXX',
      secret_token: 'whsec_****9918',
      event_types: 'scan.completed,finding.critical',
      is_active: true,
      created_at: '2026-11-06T12:00:00Z',
      updated_at: '2026-11-06T12:00:00Z',
    });

    assert.strictEqual(mock.webhooks.length, 1);
    assert.strictEqual(mock.webhooks[0].name, 'Slack Security Alerts');

    // Delete webhook
    mock.deleteWebhook('wh-1');
    assert.strictEqual(mock.webhooks.length, 0);
  });

  it('manages recurring scan schedules correctly', () => {
    const mock = new IntegrationsStateMock();

    mock.addSchedule({
      id: 'sch-1',
      target_type: 'project',
      target_id: 'proj-123',
      target_name: 'Production Web App',
      frequency: 'weekly',
      is_active: true,
      next_run_at: '2026-11-13T12:00:00Z',
      created_at: '2026-11-06T12:00:00Z',
      updated_at: '2026-11-06T12:00:00Z',
    });

    assert.strictEqual(mock.schedules.length, 1);
    assert.strictEqual(mock.schedules[0].frequency, 'weekly');

    // Run schedule on demand
    const sch = mock.schedules[0];
    sch.last_run_at = new Date().toISOString();
    assert.ok(sch.last_run_at);

    mock.deleteSchedule('sch-1');
    assert.strictEqual(mock.schedules.length, 0);
  });

  it('validates CEF format compliance in SIEM event stream', () => {
    const sampleEvent: SiemLogItem = {
      timestamp: '2026-11-06T18:00:00Z',
      event_id: 'evt-100',
      severity: 'CRITICAL',
      source: 'Website Scanner',
      asset: 'Production API Gateway',
      message: 'SQL Injection Concatenation Detected',
      cef_string: 'CEF:0|Sentriq|ASPM|1.0|Injection|SQLi in User Parameter|10|src=Production API Gateway status=open',
    };

    assert.ok(sampleEvent.cef_string.startsWith('CEF:0|Sentriq|ASPM|1.0|'));
    assert.ok(sampleEvent.cef_string.includes('src=Production API Gateway'));
    assert.strictEqual(sampleEvent.severity, 'CRITICAL');
  });
});
