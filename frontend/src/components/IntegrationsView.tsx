import React, { useEffect, useState, useCallback } from 'react';
import {
  Webhook,
  Calendar,
  Terminal,
  Plus,
  Trash2,
  Send,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Copy,
  Clock,
  X,
  Play,
} from 'lucide-react';
import {
  fetchWebhooks,
  createWebhook,
  deleteWebhook,
  testWebhook,
  fetchSchedules,
  createSchedule,
  deleteSchedule,
  executeScanSchedule,
  fetchSiemEvents,
  fetchProjects,
} from '../services/api';
import {
  WebhookEndpoint,
  ScanSchedule,
  SiemLogItem,
} from '../types/integration';
import { Project } from '../types/project';

export const IntegrationsView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'webhooks' | 'schedules' | 'siem'>('webhooks');

  // Webhooks state
  const [webhooks, setWebhooks] = useState<WebhookEndpoint[]>([]);
  const [loadingWebhooks, setLoadingWebhooks] = useState(false);
  const [isAddWebhookOpen, setIsAddWebhookOpen] = useState(false);
  const [webhookName, setWebhookName] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookEvents, setWebhookEvents] = useState('scan.completed,finding.critical,posture.degraded');
  const [submittingWebhook, setSubmittingWebhook] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; success: boolean; msg: string } | null>(null);

  // Schedules state
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loadingSchedules, setLoadingSchedules] = useState(false);
  const [isAddScheduleOpen, setIsAddScheduleOpen] = useState(false);
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [frequency, setFrequency] = useState<'daily' | 'weekly' | 'monthly'>('weekly');
  const [submittingSchedule, setSubmittingSchedule] = useState(false);
  const [runningScheduleId, setRunningScheduleId] = useState<string | null>(null);

  // SIEM state
  const [siemEvents, setSiemEvents] = useState<SiemLogItem[]>([]);
  const [loadingSiem, setLoadingSiem] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const [error, setError] = useState<string | null>(null);

  const loadWebhooks = useCallback(async () => {
    try {
      setLoadingWebhooks(true);
      const data = await fetchWebhooks();
      setWebhooks(data);
    } catch (err) {
      console.error('Failed to load webhooks:', err);
    } finally {
      setLoadingWebhooks(false);
    }
  }, []);

  const loadSchedules = useCallback(async () => {
    try {
      setLoadingSchedules(true);
      const [scheds, projs] = await Promise.all([
        fetchSchedules(),
        fetchProjects(),
      ]);
      setSchedules(scheds);
      setProjects(projs);
      if (projs.length > 0 && !selectedProjectId) {
        setSelectedProjectId(projs[0].id);
      }
    } catch (err) {
      console.error('Failed to load schedules:', err);
    } finally {
      setLoadingSchedules(false);
    }
  }, [selectedProjectId]);

  const loadSiem = useCallback(async () => {
    try {
      setLoadingSiem(true);
      const data = await fetchSiemEvents();
      setSiemEvents(data);
    } catch (err) {
      console.error('Failed to load SIEM logs:', err);
    } finally {
      setLoadingSiem(false);
    }
  }, []);

  useEffect(() => {
    loadWebhooks();
    loadSchedules();
    loadSiem();
  }, [loadWebhooks, loadSchedules, loadSiem]);

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!webhookName.trim() || !webhookUrl.trim()) return;

    try {
      setSubmittingWebhook(true);
      setError(null);
      const created = await createWebhook({
        name: webhookName.trim(),
        target_url: webhookUrl.trim(),
        event_types: webhookEvents.trim(),
      });
      setWebhooks((prev) => [created, ...prev]);
      setIsAddWebhookOpen(false);
      setWebhookName('');
      setWebhookUrl('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create webhook');
    } finally {
      setSubmittingWebhook(false);
    }
  };

  const handleDeleteWebhook = async (id: string) => {
    if (!window.confirm('Delete this webhook endpoint?')) return;
    try {
      await deleteWebhook(id);
      setWebhooks((prev) => prev.filter((w) => w.id !== id));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete webhook');
    }
  };

  const handleTestWebhook = async (id: string) => {
    try {
      setTestingId(id);
      setTestResult(null);
      const res = await testWebhook(id);
      setTestResult({ id, success: res.success, msg: res.message });
      await loadWebhooks();
    } catch (err) {
      setTestResult({
        id,
        success: false,
        msg: err instanceof Error ? err.message : 'Delivery failed',
      });
    } finally {
      setTestingId(null);
    }
  };

  const handleCreateSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    const proj = projects.find((p) => p.id === selectedProjectId);
    if (!proj) return;

    try {
      setSubmittingSchedule(true);
      setError(null);
      const created = await createSchedule({
        target_type: 'project',
        target_id: proj.id,
        target_name: proj.name,
        frequency,
      });
      setSchedules((prev) => [created, ...prev]);
      setIsAddScheduleOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create schedule');
    } finally {
      setSubmittingSchedule(false);
    }
  };

  const handleDeleteSchedule = async (id: string) => {
    if (!window.confirm('Delete this recurring scan schedule?')) return;
    try {
      await deleteSchedule(id);
      setSchedules((prev) => prev.filter((s) => s.id !== id));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete schedule');
    }
  };

  const handleRunScheduleNow = async (id: string) => {
    try {
      setRunningScheduleId(id);
      const res = await executeScanSchedule(id);
      alert(res.message);
      await loadSchedules();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to execute scheduled scan');
    } finally {
      setRunningScheduleId(null);
    }
  };

  const handleCopyCef = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Integrations, Webhooks & Automation
            </h1>
            <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>
              Phase 11 Active
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
            Real-time outbound security alerts, automated recurring scan schedules, and SIEM CEF event streaming.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          {activeTab === 'webhooks' && (
            <button
              className="btn-primary"
              onClick={() => setIsAddWebhookOpen(true)}
              style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
            >
              <Plus size={14} /> Add Webhook
            </button>
          )}
          {activeTab === 'schedules' && (
            <button
              className="btn-primary"
              onClick={() => setIsAddScheduleOpen(true)}
              style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
            >
              <Plus size={14} /> Schedule Scan
            </button>
          )}
          {activeTab === 'siem' && (
            <button
              className="btn-secondary"
              onClick={loadSiem}
              disabled={loadingSiem}
              style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
            >
              <RefreshCw size={14} className={loadingSiem ? 'spin' : ''} /> Refresh Stream
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="surface-card" style={{ padding: '12px 16px', borderLeft: '4px solid var(--accent-rose)', color: 'var(--accent-rose)' }}>
          {error}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
        <button
          className={`btn-tab ${activeTab === 'webhooks' ? 'active' : ''}`}
          onClick={() => setActiveTab('webhooks')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'webhooks' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            color: activeTab === 'webhooks' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            padding: '6px 14px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Webhook size={15} />
          <span>Outbound Webhooks ({webhooks.length})</span>
        </button>

        <button
          className={`btn-tab ${activeTab === 'schedules' ? 'active' : ''}`}
          onClick={() => setActiveTab('schedules')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'schedules' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            color: activeTab === 'schedules' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            padding: '6px 14px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Calendar size={15} />
          <span>Scan Scheduling ({schedules.length})</span>
        </button>

        <button
          className={`btn-tab ${activeTab === 'siem' ? 'active' : ''}`}
          onClick={() => setActiveTab('siem')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'siem' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            color: activeTab === 'siem' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            padding: '6px 14px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Terminal size={15} />
          <span>SIEM & CEF Stream ({siemEvents.length})</span>
        </button>
      </div>

      {/* Tab 1: Webhooks */}
      {activeTab === 'webhooks' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {loadingWebhooks && webhooks.length === 0 ? (
            <div className="surface-card" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading webhooks...
            </div>
          ) : webhooks.length === 0 ? (
            <div className="surface-card" style={{ padding: '36px', textAlign: 'center' }}>
              <Webhook size={32} color="var(--text-muted)" style={{ margin: '0 auto 8px' }} />
              <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 600, margin: '0 0 4px' }}>
                No webhooks configured
              </p>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0 0 16px' }}>
                Deliver real-time notifications to Slack, Discord, or Microsoft Teams when critical vulnerabilities are detected.
              </p>
              <button className="btn-secondary" onClick={() => setIsAddWebhookOpen(true)} style={{ fontSize: '0.8rem', padding: '6px 12px' }}>
                Add First Webhook
              </button>
            </div>
          ) : (
            webhooks.map((wh) => (
              <div
                key={wh.id}
                className="surface-card"
                style={{
                  padding: '16px 20px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '12px',
                  borderLeft: '3px solid var(--accent-cyan)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {wh.name}
                    </span>
                    <span className="badge badge-secondary" style={{ fontSize: '0.7rem' }}>
                      HMAC: {wh.secret_token}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'monospace', margin: '4px 0' }}>
                    {wh.target_url}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                    <span>Topics: {wh.event_types}</span>
                    {wh.last_status_code && (
                      <>
                        <span>•</span>
                        <span style={{ color: wh.last_status_code >= 200 && wh.last_status_code < 300 ? '#22c55e' : '#ef4444' }}>
                          Last Delivery: HTTP {wh.last_status_code}
                        </span>
                      </>
                    )}
                  </div>

                  {testResult && testResult.id === wh.id && (
                    <div
                      style={{
                        marginTop: '8px',
                        fontSize: '0.76rem',
                        color: testResult.success ? '#22c55e' : '#ef4444',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                      }}
                    >
                      {testResult.success ? <CheckCircle2 size={13} /> : <AlertCircle size={13} />}
                      <span>{testResult.msg}</span>
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    className="btn-secondary"
                    onClick={() => handleTestWebhook(wh.id)}
                    disabled={testingId === wh.id}
                    style={{ fontSize: '0.78rem', padding: '4px 10px', display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <Send size={13} className={testingId === wh.id ? 'spin' : ''} />
                    {testingId === wh.id ? 'Sending...' : 'Test Ping'}
                  </button>
                  <button
                    className="btn-icon"
                    onClick={() => handleDeleteWebhook(wh.id)}
                    title="Delete webhook"
                    style={{ color: 'var(--text-muted)' }}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 2: Scan Schedules */}
      {activeTab === 'schedules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {loadingSchedules && schedules.length === 0 ? (
            <div className="surface-card" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading schedules...
            </div>
          ) : schedules.length === 0 ? (
            <div className="surface-card" style={{ padding: '36px', textAlign: 'center' }}>
              <Calendar size={32} color="var(--text-muted)" style={{ margin: '0 auto 8px' }} />
              <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 600, margin: '0 0 4px' }}>
                No automated scan schedules
              </p>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0 0 16px' }}>
                Schedule daily, weekly, or monthly automated security assessments for your projects.
              </p>
              <button className="btn-secondary" onClick={() => setIsAddScheduleOpen(true)} style={{ fontSize: '0.8rem', padding: '6px 12px' }}>
                Schedule First Scan
              </button>
            </div>
          ) : (
            schedules.map((s) => (
              <div
                key={s.id}
                className="surface-card"
                style={{
                  padding: '16px 20px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '12px',
                  borderLeft: '3px solid #3b82f6',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {s.target_name}
                    </span>
                    <span className="badge badge-cyan" style={{ fontSize: '0.7rem', textTransform: 'uppercase' }}>
                      {s.frequency}
                    </span>
                    <span className="badge badge-secondary" style={{ fontSize: '0.7rem' }}>
                      {s.target_type}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }}>
                    <Clock size={13} />
                    <span>Next execution: {s.next_run_at ? new Date(s.next_run_at).toLocaleString() : 'Pending'}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    className="btn-secondary"
                    onClick={() => handleRunScheduleNow(s.id)}
                    disabled={runningScheduleId === s.id}
                    style={{ fontSize: '0.78rem', padding: '4px 10px', display: 'flex', alignItems: 'center', gap: '6px' }}
                    title="Execute assessment immediately"
                  >
                    <Play size={13} className={runningScheduleId === s.id ? 'spin' : ''} />
                    {runningScheduleId === s.id ? 'Executing...' : 'Run Now'}
                  </button>
                  <button
                    className="btn-icon"
                    onClick={() => handleDeleteSchedule(s.id)}
                    title="Delete schedule"
                    style={{ color: 'var(--text-muted)' }}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 3: SIEM & CEF Log Stream */}
      {activeTab === 'siem' && (
        <div className="surface-card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Common Event Format (CEF) / ArcSight / Splunk Log Stream
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Format: CEF:0|Sentriq|ASPM|1.0|Category|Name|Severity|Extensions
            </span>
          </div>

          <div
            style={{
              padding: '16px',
              backgroundColor: 'rgba(0, 0, 0, 0.4)',
              fontFamily: 'monospace',
              fontSize: '0.78rem',
              lineHeight: 1.6,
              maxHeight: '480px',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}
          >
            {siemEvents.map((ev, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  backgroundColor: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(255, 255, 255, 0.05)',
                  gap: '12px',
                }}
              >
                <div style={{ wordBreak: 'break-all', color: '#94a3b8' }}>
                  <span style={{ color: '#06b6d4' }}>[{ev.timestamp}]</span>{' '}
                  <span style={{ color: ev.severity === 'CRITICAL' ? '#ef4444' : ev.severity === 'HIGH' ? '#f97316' : '#22c55e', fontWeight: 600 }}>
                    {ev.severity}
                  </span>{' '}
                  <span style={{ color: '#cbd5e1' }}>{ev.cef_string}</span>
                </div>

                <button
                  onClick={() => handleCopyCef(ev.cef_string, idx)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: copiedIndex === idx ? '#22c55e' : 'var(--text-muted)',
                    cursor: 'pointer',
                    padding: '2px 4px',
                    flexShrink: 0,
                  }}
                  title="Copy CEF string"
                >
                  {copiedIndex === idx ? <CheckCircle2 size={13} /> : <Copy size={13} />}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Add Webhook Modal */}
      {isAddWebhookOpen && (
        <div className="modal-backdrop" onClick={() => setIsAddWebhookOpen(false)}>
          <div className="modal-card" style={{ maxWidth: '520px', width: '100%' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Add Outbound Webhook
              </h3>
              <button className="btn-icon" onClick={() => setIsAddWebhookOpen(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleCreateWebhook} style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Channel Name *
                </label>
                <input
                  type="text"
                  placeholder="e.g. Corporate Slack Security Alerts"
                  value={webhookName}
                  onChange={(e) => setWebhookName(e.target.value)}
                  required
                  className="input-field"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Destination HTTPS URL * (Protected against SSRF)
                </label>
                <input
                  type="url"
                  placeholder="https://hooks.slack.com/services/..."
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  required
                  className="input-field"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Subscribed Event Topics
                </label>
                <input
                  type="text"
                  value={webhookEvents}
                  onChange={(e) => setWebhookEvents(e.target.value)}
                  className="input-field"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
                <button type="button" className="btn-secondary" onClick={() => setIsAddWebhookOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={submittingWebhook}>
                  {submittingWebhook ? 'Saving...' : 'Add Webhook'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Schedule Modal */}
      {isAddScheduleOpen && (
        <div className="modal-backdrop" onClick={() => setIsAddScheduleOpen(false)}>
          <div className="modal-card" style={{ maxWidth: '480px', width: '100%' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Schedule Automated Recurring Scan
              </h3>
              <button className="btn-icon" onClick={() => setIsAddScheduleOpen(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleCreateSchedule} style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Select Project Target *
                </label>
                <select
                  value={selectedProjectId}
                  onChange={(e) => setSelectedProjectId(e.target.value)}
                  className="input-field"
                  style={{ width: '100%' }}
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.target_url})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Frequency
                </label>
                <select
                  value={frequency}
                  onChange={(e) => setFrequency(e.target.value as 'daily' | 'weekly' | 'monthly')}
                  className="input-field"
                  style={{ width: '100%' }}
                >
                  <option value="daily">Daily (Every 24 hours)</option>
                  <option value="weekly">Weekly (Every 7 days)</option>
                  <option value="monthly">Monthly (Every 30 days)</option>
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
                <button type="button" className="btn-secondary" onClick={() => setIsAddScheduleOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={submittingSchedule}>
                  {submittingSchedule ? 'Scheduling...' : 'Save Schedule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
