import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { UserProfileResponse, UserSessionItem } from '../types/settings.ts';

// Simulated State Logic for SettingsView
class SettingsStateMock {
  profile: UserProfileResponse | null = null;
  sessions: UserSessionItem[] = [];

  updateProfileName(name: string): void {
    if (!name || name.trim().length < 2) {
      throw new Error('Name must be at least 2 characters long.');
    }
    if (this.profile) {
      this.profile.full_name = name.trim();
    }
  }

  validatePasswordChange(current: string, next: string, confirm: string): void {
    if (!current) throw new Error('Current password is required.');
    if (next.length < 8) throw new Error('New password must be at least 8 characters long.');
    if (next !== confirm) throw new Error('New passwords do not match.');
  }

  revokeSession(sessionId: string): void {
    this.sessions = this.sessions.filter((s) => s.id !== sessionId);
  }

  revokeOtherSessions(): number {
    const beforeCount = this.sessions.length;
    this.sessions = this.sessions.filter((s) => s.is_current);
    return beforeCount - this.sessions.length;
  }
}

describe('Settings & Session Management: Validation and State Logic', () => {
  it('validates profile updates and rejects empty or too short names', () => {
    const mock = new SettingsStateMock();
    mock.profile = {
      id: 'usr-1',
      email: 'security.lead@sentriq.io',
      full_name: 'Original Name',
      is_active: true,
      is_verified: true,
      is_superuser: false,
      created_at: '2026-11-06T12:00:00Z',
      updated_at: '2026-11-06T12:00:00Z',
    };

    assert.throws(() => mock.updateProfileName(''), /at least 2 characters/i);
    assert.throws(() => mock.updateProfileName('a'), /at least 2 characters/i);

    mock.updateProfileName('Lead Cybersecurity Architect');
    assert.strictEqual(mock.profile.full_name, 'Lead Cybersecurity Architect');
  });

  it('enforces password change validation rules', () => {
    const mock = new SettingsStateMock();

    // Rejects missing current password
    assert.throws(
      () => mock.validatePasswordChange('', 'NewSecurePass123!', 'NewSecurePass123!'),
      /current password is required/i
    );

    // Rejects password shorter than 8 chars
    assert.throws(
      () => mock.validatePasswordChange('oldpass123', 'short', 'short'),
      /at least 8 characters/i
    );

    // Rejects mismatched passwords
    assert.throws(
      () => mock.validatePasswordChange('oldpass123', 'NewSecurePass123!', 'Mismatched123!'),
      /passwords do not match/i
    );

    // Succeeds with valid inputs
    assert.doesNotThrow(() =>
      mock.validatePasswordChange('oldpass123', 'NewSecurePass123!', 'NewSecurePass123!')
    );
  });

  it('revokes individual sessions and all other sessions cleanly', () => {
    const mock = new SettingsStateMock();
    mock.sessions = [
      {
        id: 'sess-current',
        ip_address: '127.0.0.1',
        user_agent: 'Chrome Desktop',
        created_at: '2026-11-06T12:00:00Z',
        expires_at: '2026-11-13T12:00:00Z',
        is_current: true,
      },
      {
        id: 'sess-mobile',
        ip_address: '192.168.1.10',
        user_agent: 'Safari iOS',
        created_at: '2026-11-06T11:00:00Z',
        expires_at: '2026-11-13T11:00:00Z',
        is_current: false,
      },
      {
        id: 'sess-laptop',
        ip_address: '10.0.0.5',
        user_agent: 'Firefox Linux',
        created_at: '2026-11-05T10:00:00Z',
        expires_at: '2026-11-12T10:00:00Z',
        is_current: false,
      },
    ];

    assert.strictEqual(mock.sessions.length, 3);

    // Revoke single session
    mock.revokeSession('sess-mobile');
    assert.strictEqual(mock.sessions.length, 2);
    assert.ok(!mock.sessions.some((s) => s.id === 'sess-mobile'));

    // Revoke all other sessions
    const revoked = mock.revokeOtherSessions();
    assert.strictEqual(revoked, 1);
    assert.strictEqual(mock.sessions.length, 1);
    assert.strictEqual(mock.sessions[0].id, 'sess-current');
    assert.strictEqual(mock.sessions[0].is_current, true);
  });

  it('manages scanner and notification preferences state and validation', () => {
    interface Preferences {
      scanner_timeout_seconds: number;
      scanner_max_redirects: number;
      scanner_verify_ssl: boolean;
      scanner_strict_headers: boolean;
      notify_email_scan_completed: boolean;
      notify_email_critical_finding: boolean;
      notify_webhook_enabled: boolean;
      default_scan_cadence: string;
      session_timeout_minutes: number;
    }

    const defaultPrefs: Preferences = {
      scanner_timeout_seconds: 30,
      scanner_max_redirects: 5,
      scanner_verify_ssl: true,
      scanner_strict_headers: true,
      notify_email_scan_completed: true,
      notify_email_critical_finding: true,
      notify_webhook_enabled: true,
      default_scan_cadence: 'weekly',
      session_timeout_minutes: 10080,
    };

    const validatePrefs = (p: Partial<Preferences>) => {
      if (p.scanner_timeout_seconds !== undefined && (p.scanner_timeout_seconds < 5 || p.scanner_timeout_seconds > 120)) {
        throw new Error('Scanner timeout must be between 5 and 120 seconds.');
      }
      if (p.default_scan_cadence !== undefined && !['daily', 'weekly', 'monthly'].includes(p.default_scan_cadence)) {
        throw new Error('Invalid scan cadence.');
      }
    };

    assert.doesNotThrow(() => validatePrefs({ scanner_timeout_seconds: 45, default_scan_cadence: 'daily' }));
    assert.throws(() => validatePrefs({ scanner_timeout_seconds: 2 }), /between 5 and 120/i);
    assert.throws(() => validatePrefs({ default_scan_cadence: 'hourly' }), /Invalid scan cadence/i);
  });
});
