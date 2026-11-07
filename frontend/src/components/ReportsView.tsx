import React, { useEffect, useState, useCallback } from 'react';
import {
  FileText,
  Download,
  ExternalLink,
  RefreshCw,
  FileSpreadsheet,
  FileCode,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import {
  fetchReportSummary,
  getExecutiveReportUrl,
  getPdfExportUrl,
  getFindingsCsvExportUrl,
  getPostureJsonExportUrl,
} from '../services/api';
import { ReportSummaryResponse } from '../types/report';

export const ReportsView: React.FC = () => {
  const [summary, setSummary] = useState<ReportSummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedReportType, setSelectedReportType] = useState<string>('executive');

  const loadSummary = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchReportSummary();
      setSummary(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch report summary');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  const handleOpenExecutiveReport = () => {
    window.open(getExecutiveReportUrl(), '_blank');
  };

  const handleDownloadPdf = (type?: string) => {
    const target = type || selectedReportType;
    window.location.href = getPdfExportUrl(target);
  };

  const handleDownloadCsv = () => {
    window.location.href = getFindingsCsvExportUrl();
  };

  const handleDownloadJson = () => {
    window.location.href = getPostureJsonExportUrl();
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      default:
        return 'badge-low';
    }
  };

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Reports & Compliance Export Engine
            </h1>
            <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>
              Phase 9 Active
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
            Automated executive PDF reporting, CSV spreadsheet export, and machine-readable SIEM posture bundles.
          </p>
        </div>

        <button
          className="btn-secondary"
          onClick={loadSummary}
          disabled={loading}
          style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
        >
          <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
        </button>
      </div>

      {error && (
        <div className="surface-card" style={{ padding: '12px 16px', borderLeft: '4px solid var(--accent-rose)', color: 'var(--accent-rose)' }}>
          {error}
        </div>
      )}

      {/* 3 Main Export Action Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
        {/* Card 1: Downloadable PDF */}
        <div
          className="surface-card"
          style={{
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            gap: '16px',
            borderTop: '3px solid var(--accent-cyan)',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  backgroundColor: 'rgba(6, 182, 212, 0.1)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-cyan)',
                }}
              >
                <FileText size={18} />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Downloadable PDF Reports
              </h3>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.5, margin: '0 0 12px 0' }}>
              Board-ready PDF security audits with posture grade, asset breakdown, OWASP/CIS compliance alignment, and prioritized remediation actions.
            </p>

            <div>
              <label style={{ display: 'block', fontSize: '0.74rem', color: 'var(--text-muted)', marginBottom: '4px', textTransform: 'uppercase', fontWeight: 600 }}>
                Select Report Scope
              </label>
              <select
                value={selectedReportType}
                onChange={(e) => setSelectedReportType(e.target.value)}
                className="input-field"
                style={{ width: '100%', fontSize: '0.8rem', padding: '6px 8px' }}
              >
                <option value="executive">Executive Cybersecurity Posture</option>
                <option value="project">Project & Web Application Security</option>
                <option value="vulnerability">Comprehensive Vulnerability Catalog</option>
                <option value="risk">Risk Analytics & Scoring Formulas</option>
                <option value="repo">Repository Security (SAST & SCA)</option>
                <option value="api">API Security (OWASP Top 10)</option>
                <option value="cloud">Cloud Security Posture (CSPM)</option>
                <option value="compliance">Compliance Evidence & Mapping</option>
              </select>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <button
              className="btn-primary"
              onClick={() => handleDownloadPdf()}
              style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
            >
              <Download size={14} /> Download PDF (.pdf)
            </button>
            <button
              className="btn-secondary"
              onClick={handleOpenExecutiveReport}
              style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', fontSize: '0.78rem' }}
            >
              <ExternalLink size={13} /> View Printable HTML
            </button>
          </div>
        </div>

        {/* Card 2: CSV Export */}
        <div
          className="surface-card"
          style={{
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            gap: '16px',
            borderTop: '3px solid #22c55e',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  backgroundColor: 'rgba(34, 197, 94, 0.1)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#22c55e',
                }}
              >
                <FileSpreadsheet size={18} />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Findings CSV Spreadsheet
              </h3>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.5, margin: 0 }}>
              UTF-8 BOM encoded spreadsheet listing all cross-domain vulnerabilities with finding IDs, severity scores, CWE tags, and remediation guidance for Excel or BI tools.
            </p>
          </div>

          <button
            className="btn-secondary"
            onClick={handleDownloadCsv}
            style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
          >
            <Download size={14} /> Download CSV (.csv)
          </button>
        </div>

        {/* Card 3: JSON SIEM Bundle */}
        <div
          className="surface-card"
          style={{
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            gap: '16px',
            borderTop: '3px solid #3b82f6',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  backgroundColor: 'rgba(59, 130, 246, 0.1)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#3b82f6',
                }}
              >
                <FileCode size={18} />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                SIEM / Posture JSON Bundle
              </h3>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.5, margin: 0 }}>
              Full machine-readable cybersecurity bundle including posture indices, asset inventory, OWASP Web/API mappings, and CIS cloud compliance controls.
            </p>
          </div>

          <button
            className="btn-secondary"
            onClick={handleDownloadJson}
            style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
          >
            <Download size={14} /> Download JSON (.json)
          </button>
        </div>
      </div>

      {/* Live Report Scorecard & Findings Preview */}
      {summary && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Sparkles size={16} color="var(--accent-cyan)" /> Live Audit Summary (Tenant: {summary.tenant_email})
          </div>

          {/* Metric KPI cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
            <div className="surface-card" style={{ padding: '16px' }}>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Overall Posture</div>
              <div style={{ fontSize: '1.6rem', fontWeight: 800, color: summary.posture.score >= 80 ? '#22c55e' : summary.posture.score >= 50 ? '#eab308' : '#ef4444', marginTop: '4px' }}>
                {summary.posture.score}%
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                Grade {summary.posture.grade}
              </div>
            </div>

            <div className="surface-card" style={{ padding: '16px' }}>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Monitored Assets</div>
              <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '4px' }}>
                {summary.assets.total_monitored}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                {summary.assets.projects_count} Web • {summary.assets.repos_count} Repo • {summary.assets.api_specs_count} API • {summary.assets.cloud_accounts_count} Cloud
              </div>
            </div>

            <div className="surface-card" style={{ padding: '16px' }}>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Open Vulnerabilities</div>
              <div style={{ fontSize: '1.6rem', fontWeight: 800, color: summary.findings_summary.open > 0 ? '#ef4444' : '#22c55e', marginTop: '4px' }}>
                {summary.findings_summary.open}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                {summary.findings_summary.critical} Crit • {summary.findings_summary.high} High • {summary.findings_summary.medium} Med
              </div>
            </div>

            <div className="surface-card" style={{ padding: '16px' }}>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Mitigated & Resolved</div>
              <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#22c55e', marginTop: '4px' }}>
                {summary.findings_summary.resolved}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                Triage audit history preserved
              </div>
            </div>
          </div>

          {/* Findings Table Preview */}
          <div className="surface-card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Cross-Domain Vulnerability Inventory ({summary.findings.length})
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Generated: {summary.generated_at}
              </span>
            </div>

            {summary.findings.length === 0 ? (
              <div style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
                <ShieldCheck size={36} color="#22c55e" style={{ margin: '0 auto 8px' }} />
                <p style={{ margin: 0, fontSize: '0.85rem' }}>No vulnerability findings recorded for this tenant.</p>
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                <thead>
                  <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Severity</th>
                    <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Vulnerability</th>
                    <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Source & Asset</th>
                    <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Standard</th>
                    <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.findings.slice(0, 15).map((f) => (
                    <tr key={f.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '10px 14px' }}>
                        <span className={`badge ${getSeverityBadgeClass(f.severity)}`}>
                          {f.severity.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '10px 14px', fontWeight: 500, color: 'var(--text-primary)' }}>
                        {f.title}
                      </td>
                      <td style={{ padding: '10px 14px', color: 'var(--text-secondary)' }}>
                        {f.asset_name} ({f.source})
                      </td>
                      <td style={{ padding: '10px 14px', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
                        {f.category}
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <span style={{ textTransform: 'uppercase', fontSize: '0.72rem', color: f.status === 'open' ? '#ef4444' : '#22c55e', fontWeight: 600 }}>
                          {f.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
