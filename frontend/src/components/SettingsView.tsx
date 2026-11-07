import React, { useEffect, useState, useCallback } from 'react';
import {
  User,
  KeyRound,
  Laptop,
  CheckCircle2,
  AlertCircle,
  LogOut,
  RefreshCw,
  Sliders,
} from 'lucide-react';
import {
  fetchProfile,
  updateProfile,
  changePassword,
  fetchActiveSessions,
  revokeSession,
  revokeOtherSessions,
  fetchUserPreferences,
  updateUserPreferences,
} from '../services/api';
import { UserProfileResponse, UserSessionItem, UserSettingsResponse } from '../types/settings';

export const SettingsView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'sessions' | 'preferences'>('profile');

  // Profile state
  const [profile, setProfile] = useState<UserProfileResponse | null>(null);
  const [fullName, setFullName] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);
  const [profileMsg, setProfileMsg] = useState<{ text: string; isError: boolean } | null>(null);

  // Security / Password state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changingPass, setChangingPass] = useState(false);
  const [passwordMsg, setPasswordMsg] = useState<{ text: string; isError: boolean } | null>(null);

  // Sessions state
  const [sessions, setSessions] = useState<UserSessionItem[]>([]);
  const [loadingSessions, setLoadingSessions] = useState(false);
  const [sessionMsg, setSessionMsg] = useState<{ text: string; isError: boolean } | null>(null);

  // Preferences state
  const [preferences, setPreferences] = useState<UserSettingsResponse | null>(null);
  const [savingPrefs, setSavingPrefs] = useState(false);
  const [prefsMsg, setPrefsMsg] = useState<{ text: string; isError: boolean } | null>(null);

  const loadProfile = useCallback(async () => {
    try {
      const data = await fetchProfile();
      setProfile(data);
      setFullName(data.full_name || '');
    } catch (err) {
      console.error('Failed to load profile:', err);
    }
  }, []);

  const loadSessions = useCallback(async () => {
    try {
      setLoadingSessions(true);
      const data = await fetchActiveSessions();
      setSessions(data);
    } catch (err) {
      console.error('Failed to load sessions:', err);
    } finally {
      setLoadingSessions(false);
    }
  }, []);

  const loadPreferences = useCallback(async () => {
    try {
      const data = await fetchUserPreferences();
      setPreferences(data);
    } catch (err) {
      console.error('Failed to load user preferences:', err);
    }
  }, []);

  useEffect(() => {
    loadProfile();
    loadSessions();
    loadPreferences();
  }, [loadProfile, loadSessions, loadPreferences]);

  const handleUpdatePreferences = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!preferences) return;

    try {
      setSavingPrefs(true);
      setPrefsMsg(null);
      const updated = await updateUserPreferences({
        scanner_timeout_seconds: preferences.scanner_timeout_seconds,
        scanner_max_redirects: preferences.scanner_max_redirects,
        scanner_verify_ssl: preferences.scanner_verify_ssl,
        scanner_strict_headers: preferences.scanner_strict_headers,
        notify_email_scan_completed: preferences.notify_email_scan_completed,
        notify_email_critical_finding: preferences.notify_email_critical_finding,
        notify_webhook_enabled: preferences.notify_webhook_enabled,
        default_scan_cadence: preferences.default_scan_cadence,
        theme: preferences.theme,
        session_timeout_minutes: preferences.session_timeout_minutes,
      });
      setPreferences(updated);
      setPrefsMsg({ text: 'Preferences saved successfully.', isError: false });
    } catch (err) {
      setPrefsMsg({
        text: err instanceof Error ? err.message : 'Failed to save preferences.',
        isError: true,
      });
    } finally {
      setSavingPrefs(false);
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fullName.trim()) return;

    try {
      setSavingProfile(true);
      setProfileMsg(null);
      const updated = await updateProfile({ full_name: fullName.trim() });
      setProfile(updated);
      setProfileMsg({ text: 'Profile updated successfully.', isError: false });
    } catch (err) {
      setProfileMsg({
        text: err instanceof Error ? err.message : 'Failed to update profile.',
        isError: true,
      });
    } finally {
      setSavingProfile(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentPassword || !newPassword) return;

    if (newPassword.length < 8) {
      setPasswordMsg({ text: 'New password must be at least 8 characters long.', isError: true });
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordMsg({ text: 'New passwords do not match.', isError: true });
      return;
    }

    try {
      setChangingPass(true);
      setPasswordMsg(null);
      await changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setPasswordMsg({ text: 'Password changed successfully.', isError: false });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setPasswordMsg({
        text: err instanceof Error ? err.message : 'Failed to change password.',
        isError: true,
      });
    } finally {
      setChangingPass(false);
    }
  };

  const handleRevokeSession = async (sessionId: string) => {
    if (!window.confirm('Are you sure you want to revoke this session?')) return;
    try {
      await revokeSession(sessionId);
      setSessions((prev) => prev.filter((s) => s.id !== sessionId));
      setSessionMsg({ text: 'Session revoked.', isError: false });
    } catch (err) {
      setSessionMsg({
        text: err instanceof Error ? err.message : 'Failed to revoke session.',
        isError: true,
      });
    }
  };

  const handleRevokeOtherSessions = async () => {
    if (!window.confirm('Are you sure you want to sign out of all other devices?')) return;
    try {
      const res = await revokeOtherSessions();
      setSessions((prev) => prev.filter((s) => s.is_current));
      setSessionMsg({
        text: `Successfully revoked ${res.revoked_count} other active session(s).`,
        isError: false,
      });
    } catch (err) {
      setSessionMsg({
        text: err instanceof Error ? err.message : 'Failed to revoke other sessions.',
        isError: true,
      });
    }
  };

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Account Settings & Sessions
          </h1>
          <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>
            Phase 10 Active
          </span>
        </div>
        <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
          Manage your personal profile, security credentials, and active device sessions.
        </p>
      </div>

      {/* Tabs Row */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
        <button
          className={`btn-tab ${activeTab === 'profile' ? 'active' : ''}`}
          onClick={() => setActiveTab('profile')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'profile' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            color: activeTab === 'profile' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            padding: '6px 14px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <User size={15} />
          <span>Profile</span>
        </button>

        <button
          className={`btn-tab ${activeTab === 'security' ? 'active' : ''}`}
          onClick={() => setActiveTab('security')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'security' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            color: activeTab === 'security' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            padding: '6px 14px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <KeyRound size={15} />
          <span>Password & Security</span>
        </button>

        <button
          className={`btn-tab ${activeTab === 'sessions' ? 'active' : ''}`}
          onClick={() => setActiveTab('sessions')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'sessions' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            color: activeTab === 'sessions' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            padding: '6px 14px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Laptop size={15} />
          <span>Active Sessions ({sessions.length})</span>
        </button>

        <button
          className={`btn-tab ${activeTab === 'preferences' ? 'active' : ''}`}
          onClick={() => setActiveTab('preferences')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'preferences' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            color: activeTab === 'preferences' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            padding: '6px 14px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Sliders size={15} />
          <span>Scanner & Alerts Preferences</span>
        </button>
      </div>

      {/* Tab 1: Profile */}
      {activeTab === 'profile' && (
        <div className="surface-card" style={{ padding: '24px', maxWidth: '580px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 16px 0' }}>
            User Profile
          </h3>

          {profileMsg && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                marginBottom: '16px',
                backgroundColor: profileMsg.isError ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                color: profileMsg.isError ? '#ef4444' : '#22c55e',
                fontSize: '0.82rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              {profileMsg.isError ? <AlertCircle size={15} /> : <CheckCircle2 size={15} />}
              <span>{profileMsg.text}</span>
            </div>
          )}

          <form onSubmit={handleUpdateProfile} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Account Email
              </label>
              <input
                type="email"
                value={profile?.email || ''}
                disabled
                className="input-field"
                style={{ width: '100%', boxSizing: 'border-box', opacity: 0.7, cursor: 'not-allowed' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Full Display Name *
              </label>
              <input
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                required
                className="input-field"
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '4px' }}>
              <span className="badge badge-secondary" style={{ fontSize: '0.74rem' }}>
                {profile?.is_superuser ? 'Super Administrator' : 'Standard Tenant'}
              </span>
              <span
                className="badge"
                style={{
                  fontSize: '0.74rem',
                  backgroundColor: profile?.is_verified ? 'rgba(34, 197, 94, 0.1)' : 'rgba(234, 179, 8, 0.1)',
                  color: profile?.is_verified ? '#22c55e' : '#eab308',
                }}
              >
                {profile?.is_verified ? 'Verified Email' : 'Unverified Email'}
              </span>
            </div>

            <div style={{ marginTop: '12px' }}>
              <button type="submit" className="btn-primary" disabled={savingProfile}>
                {savingProfile ? 'Saving...' : 'Save Profile Changes'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Tab 2: Password & Security */}
      {activeTab === 'security' && (
        <div className="surface-card" style={{ padding: '24px', maxWidth: '580px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 16px 0' }}>
            Change Password
          </h3>

          {passwordMsg && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                marginBottom: '16px',
                backgroundColor: passwordMsg.isError ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                color: passwordMsg.isError ? '#ef4444' : '#22c55e',
                fontSize: '0.82rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              {passwordMsg.isError ? <AlertCircle size={15} /> : <CheckCircle2 size={15} />}
              <span>{passwordMsg.text}</span>
            </div>
          )}

          <form onSubmit={handleChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Current Password *
              </label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
                className="input-field"
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                New Password (minimum 8 characters) *
              </label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                className="input-field"
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Confirm New Password *
              </label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                className="input-field"
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>

            <div style={{ marginTop: '12px' }}>
              <button type="submit" className="btn-primary" disabled={changingPass}>
                {changingPass ? 'Updating Password...' : 'Update Password'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Tab 3: Active Sessions */}
      {activeTab === 'sessions' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '780px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Active Devices & Sessions
              </h3>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                Sessions are secured with HttpOnly cookies and SHA-256 server hashes.
              </p>
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                className="btn-secondary"
                onClick={loadSessions}
                disabled={loadingSessions}
                style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem', padding: '4px 10px' }}
              >
                <RefreshCw size={13} className={loadingSessions ? 'spin' : ''} /> Refresh
              </button>
              {sessions.length > 1 && (
                <button
                  className="btn-secondary"
                  onClick={handleRevokeOtherSessions}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem', padding: '4px 10px', color: 'var(--accent-rose)' }}
                >
                  <LogOut size={13} /> Sign Out All Other Devices
                </button>
              )}
            </div>
          </div>

          {sessionMsg && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                backgroundColor: sessionMsg.isError ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                color: sessionMsg.isError ? '#ef4444' : '#22c55e',
                fontSize: '0.82rem',
              }}
            >
              {sessionMsg.text}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {sessions.map((s) => (
              <div
                key={s.id}
                className="surface-card"
                style={{
                  padding: '14px 18px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  borderLeft: s.is_current ? '3px solid var(--accent-cyan)' : '1px solid var(--border-color)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <Laptop size={20} color={s.is_current ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {s.user_agent || 'Unknown Browser / Client'}
                      </span>
                      {s.is_current && (
                        <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                          This Device (Current)
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                      IP: {s.ip_address || '127.0.0.1'} • Signed in: {new Date(s.created_at).toLocaleString()}
                    </div>
                  </div>
                </div>

                {!s.is_current && (
                  <button
                    className="btn-secondary"
                    onClick={() => handleRevokeSession(s.id)}
                    style={{ fontSize: '0.75rem', padding: '4px 10px', color: 'var(--accent-rose)' }}
                  >
                    Revoke
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Scanner & Alert Preferences */}
      {activeTab === 'preferences' && preferences && (
        <div className="surface-card" style={{ padding: '24px', maxWidth: '640px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 6px 0' }}>
            Scanner, Notification & Security Controls
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0 0 16px 0' }}>
            Configure default scanner bounds, automated notification preferences, and account timeout policies.
          </p>

          {prefsMsg && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                marginBottom: '16px',
                backgroundColor: prefsMsg.isError ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                color: prefsMsg.isError ? '#ef4444' : '#22c55e',
                fontSize: '0.82rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              {prefsMsg.isError ? <AlertCircle size={15} /> : <CheckCircle2 size={15} />}
              <span>{prefsMsg.text}</span>
            </div>
          )}

          <form onSubmit={handleUpdatePreferences} style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
            {/* Section 1: Scanner Parameters */}
            <div>
              <h4 style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--accent-cyan)', margin: '0 0 10px 0' }}>
                Website & Repo Scanner Controls
              </h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    HTTP Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    min={5}
                    max={120}
                    value={preferences.scanner_timeout_seconds}
                    onChange={(e) => setPreferences({ ...preferences, scanner_timeout_seconds: parseInt(e.target.value) || 30 })}
                    className="input-field"
                    style={{ width: '100%' }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    Max HTTP Redirects
                  </label>
                  <input
                    type="number"
                    min={0}
                    max={20}
                    value={preferences.scanner_max_redirects}
                    onChange={(e) => setPreferences({ ...preferences, scanner_max_redirects: parseInt(e.target.value) || 5 })}
                    className="input-field"
                    style={{ width: '100%' }}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={preferences.scanner_verify_ssl}
                    onChange={(e) => setPreferences({ ...preferences, scanner_verify_ssl: e.target.checked })}
                  />
                  <span>Enforce Strict TLS / SSL Certificate Verification</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={preferences.scanner_strict_headers}
                    onChange={(e) => setPreferences({ ...preferences, scanner_strict_headers: e.target.checked })}
                  />
                  <span>Strict HTTP Security Headers Evaluation (CSP, HSTS, Permissions-Policy)</span>
                </label>
              </div>
            </div>

            {/* Section 2: Notifications */}
            <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '14px' }}>
              <h4 style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--accent-cyan)', margin: '0 0 10px 0' }}>
                Notification & Alert Channels
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={preferences.notify_email_scan_completed}
                    onChange={(e) => setPreferences({ ...preferences, notify_email_scan_completed: e.target.checked })}
                  />
                  <span>Email Notification on Assessment Completion</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={preferences.notify_email_critical_finding}
                    onChange={(e) => setPreferences({ ...preferences, notify_email_critical_finding: e.target.checked })}
                  />
                  <span>Instant Email Alert on Critical Vulnerability Detection</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={preferences.notify_webhook_enabled}
                    onChange={(e) => setPreferences({ ...preferences, notify_webhook_enabled: e.target.checked })}
                  />
                  <span>Dispatch Security Events to Active Outbound Webhooks</span>
                </label>
              </div>
            </div>

            {/* Section 3: Default Cadence & Session Timeout */}
            <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '14px' }}>
              <h4 style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--accent-cyan)', margin: '0 0 10px 0' }}>
                Default Cadence & Account Session Policy
              </h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    Default Scheduled Cadence
                  </label>
                  <select
                    value={preferences.default_scan_cadence}
                    onChange={(e) => setPreferences({ ...preferences, default_scan_cadence: e.target.value })}
                    className="input-field"
                    style={{ width: '100%' }}
                  >
                    <option value="daily">Daily Assessment</option>
                    <option value="weekly">Weekly Assessment</option>
                    <option value="monthly">Monthly Assessment</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    Session Expiration (Minutes)
                  </label>
                  <input
                    type="number"
                    min={60}
                    max={43200}
                    value={preferences.session_timeout_minutes}
                    onChange={(e) => setPreferences({ ...preferences, session_timeout_minutes: parseInt(e.target.value) || 10080 })}
                    className="input-field"
                    style={{ width: '100%' }}
                  />
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '6px' }}>
              <button type="submit" className="btn-primary" disabled={savingPrefs}>
                {savingPrefs ? 'Saving Preferences...' : 'Save Preferences'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
