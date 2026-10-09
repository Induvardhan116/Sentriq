import React, { useState, useEffect, useCallback } from 'react';
import {
  ArrowLeft,
  RefreshCw,
  Play,
  ShieldCheck,
  AlertOctagon,
  Clock,
  Globe,
  ChevronRight,
} from 'lucide-react';
import { Scan } from '../types/scan';
import { Finding } from '../types/finding';
import { fetchScan, fetchScanFindings, triggerScan } from '../services/api';
import { navigate } from '../utils/routing';
import { FindingDetailModal } from './FindingDetailModal';

interface ScanDetailViewProps {
  scanId: string;
  initialFindingId?: string;
  onBack: () => void;
  onSelectFinding?: (findingId: string | null) => void;
}

export const ScanDetailView: React.FC<ScanDetailViewProps> = ({
  scanId,
  initialFindingId,
  onBack,
  onSelectFinding,
}) => {
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isRescanning, setIsRescanning] = useState<boolean>(false);

  const isFetchingRef = React.useRef<boolean>(false);
  const scanRef = React.useRef<Scan | null>(null);
  scanRef.current = scan;

  const loadScanData = useCallback(
    async (isManualRefresh = false) => {
      // Prevent duplicate simultaneous requests
      if (isFetchingRef.current) return;
      isFetchingRef.current = true;

      if (isManualRefresh) {
        setIsRefreshing(true);
        setRefreshError(null);
      } else if (!scanRef.current) {
        setLoading(true);
        setLoadError(null);
      }

      try {
        const [scanData, findingsData] = await Promise.all([
          fetchScan(scanId),
          fetchScanFindings(scanId),
        ]);

        setScan(scanData);
        setFindings(findingsData);
        setRefreshError(null);
        setLoadError(null);

        // Keep finding details modal synchronized with fresh data / updated status
        setSelectedFinding((prev) => {
          if (prev) {
            const updated = findingsData.find((f) => f.id === prev.id);
            return updated || prev;
          }
          if (initialFindingId) {
            const match = findingsData.find((f) => f.id === initialFindingId);
            return match || null;
          }
          return null;
        });
      } catch (err) {
        console.error('Failed to load scan details:', err);
        const errMsg = err instanceof Error ? err.message : 'Failed to refresh scan details.';
        if (scanRef.current) {
          setRefreshError(errMsg);
        } else {
          setLoadError(errMsg);
        }
      } finally {
        setLoading(false);
        if (isManualRefresh) {
          setIsRefreshing(false);
        }
        isFetchingRef.current = false;
      }
    },
    [scanId, initialFindingId]
  );

  const handleRescan = async () => {
    if (!scan) return;
    setIsRescanning(true);
    try {
      const newScan = await triggerScan(scan.project_id);
      navigate({ view: 'scan', scanId: newScan.id });
    } catch (err) {
      console.error('Failed to trigger rescan:', err);
    } finally {
      setIsRescanning(false);
    }
  };

  useEffect(() => {
    loadScanData(false);

    // Auto-poll if scan is running or queued
    const interval = setInterval(() => {
      if (scan?.status === 'running' || scan?.status === 'queued') {
        loadScanData(false);
      }
    }, 2500);

    return () => clearInterval(interval);
  }, [loadScanData, scan?.status]);

  if (loading && !scan) {
    return (
      <div className="surface-card" style={{ padding: '40px', textAlign: 'center' }}>
        <RefreshCw size={24} style={{ animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
        <div>Loading assessment results...</div>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="surface-card" style={{ padding: '40px', textAlign: 'center' }}>
        <AlertOctagon size={36} color="var(--accent-rose)" style={{ margin: '0 auto 12px' }} />
        <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
          {loadError}
        </p>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '20px' }}>
          The scan ID in the URL may be invalid or the scan may have been deleted.
        </p>
        <button className="btn-secondary" onClick={onBack}>
          <ArrowLeft size={14} /> Back to Projects
        </button>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="surface-card" style={{ padding: '40px', textAlign: 'center' }}>
        <AlertOctagon size={36} color="var(--accent-rose)" style={{ margin: '0 auto 12px' }} />
        <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
          Scan not found.
        </p>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '20px' }}>
          The scan ID in the URL may be invalid or the scan may have been deleted.
        </p>
        <button className="btn-secondary" onClick={onBack}>
          <ArrowLeft size={14} /> Back to Projects
        </button>
      </div>
    );
  }

  const isRunning = scan.status === 'running' || scan.status === 'queued';

  const getScoreColor = (score?: number | null) => {
    if (score == null) return 'var(--text-muted)';
    if (score >= 90) return 'var(--accent-emerald)';
    if (score >= 75) return 'var(--accent-cyan)';
    if (score >= 50) return 'var(--accent-amber)';
    return 'var(--accent-rose)';
  };

  const filteredFindings = findings.filter((f) => {
    if (filterSeverity === 'all') return true;
    return f.severity.toLowerCase() === filterSeverity.toLowerCase();
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top action row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button className="btn-secondary" onClick={onBack} style={{ padding: '6px 12px' }}>
          <ArrowLeft size={14} /> Back to Projects
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span
            className={`badge ${
              scan.status === 'completed'
                ? 'badge-emerald'
                : scan.status === 'failed'
                ? 'badge-rose'
                : 'badge-cyan'
            }`}
          >
            {scan.status.toUpperCase()}
          </span>

          <button
            className="btn-primary"
            onClick={handleRescan}
            disabled={isRescanning || isRunning}
            title="Run new assessment scan on this target"
            style={{ padding: '6px 12px', fontSize: '0.78rem' }}
          >
            <Play size={13} style={{ fill: 'currentColor' }} />
            <span>{isRescanning ? 'Starting...' : 'Rescan'}</span>
          </button>

          <button
            className="btn-secondary"
            onClick={() => loadScanData(true)}
            disabled={isRefreshing}
            title={isRefreshing ? 'Refreshing scan...' : 'Refresh scan'}
            style={{
              padding: '6px 10px',
              opacity: isRefreshing ? 0.7 : 1,
              cursor: isRefreshing ? 'not-allowed' : 'pointer',
            }}
          >
            <RefreshCw
              size={13}
              style={{
                animation: isRefreshing || isRunning ? 'spin 1s linear infinite' : 'none',
              }}
            />
          </button>
        </div>
      </div>

      {/* Refresh Error Alert Banner */}
      {refreshError && (
        <div
          className="surface-card"
          style={{
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderLeft: '4px solid var(--accent-rose)',
            backgroundColor: 'rgba(244, 63, 94, 0.08)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertOctagon size={16} color="var(--accent-rose)" />
            <span style={{ fontSize: '0.84rem', color: 'var(--accent-rose)', fontWeight: 500 }}>
              Failed to refresh scan: {refreshError}
            </span>
          </div>
          <button
            className="btn-secondary"
            onClick={() => setRefreshError(null)}
            style={{ padding: '2px 8px', fontSize: '0.74rem' }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Target & Score Hero Card */}
      <div className="hero-card" style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '20px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <Globe size={18} color="var(--accent-cyan)" />
            <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#fff' }}>
              {scan.target_url}
            </h1>
          </div>
          <p className="hero-subtitle">
            Defensive website security audit: HTTPS/TLS, security headers, cookie flags, CORS policies, and information disclosure.
          </p>

          <div style={{ display: 'flex', gap: '16px', marginTop: '14px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Clock size={13} /> Started:{' '}
              {scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : 'Queued'}
            </span>
            {scan.completed_at && (
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                Completed: {new Date(scan.completed_at).toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>

        {/* Posture Score Dial / Pill */}
        <div
          style={{
            minWidth: '160px',
            textAlign: 'center',
            padding: '16px 20px',
            borderRadius: '10px',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
            Security Posture
          </span>
          <div
            style={{
              fontSize: '2.4rem',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: getScoreColor(scan.overall_score),
              lineHeight: 1.1,
              margin: '6px 0',
            }}
          >
            {scan.overall_score != null ? scan.overall_score : '—'}
            <span style={{ fontSize: '1rem', color: 'var(--text-muted)', fontWeight: 400 }}>/100</span>
          </div>
          {scan.score_grade && (
            <span
              className="badge"
              style={{
                backgroundColor: 'rgba(255,255,255,0.06)',
                color: getScoreColor(scan.overall_score),
                fontSize: '0.7rem',
              }}
            >
              {scan.score_grade}
            </span>
          )}
        </div>
      </div>

      {/* Severity Counters Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>
        <div className="surface-card" style={{ padding: '14px', textAlign: 'center' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--accent-rose)', fontWeight: 700 }}>CRITICAL</span>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fff', marginTop: '4px' }}>
            {scan.critical_count}
          </div>
        </div>
        <div className="surface-card" style={{ padding: '14px', textAlign: 'center' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--accent-rose)', fontWeight: 700 }}>HIGH</span>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fff', marginTop: '4px' }}>
            {scan.high_count}
          </div>
        </div>
        <div className="surface-card" style={{ padding: '14px', textAlign: 'center' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--accent-amber)', fontWeight: 700 }}>MEDIUM</span>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fff', marginTop: '4px' }}>
            {scan.medium_count}
          </div>
        </div>
        <div className="surface-card" style={{ padding: '14px', textAlign: 'center' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>LOW</span>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fff', marginTop: '4px' }}>
            {scan.low_count}
          </div>
        </div>
        <div className="surface-card" style={{ padding: '14px', textAlign: 'center' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>INFO</span>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fff', marginTop: '4px' }}>
            {scan.info_count}
          </div>
        </div>
      </div>

      {/* Findings Section */}
      <div className="surface-card" style={{ gap: '20px' }}>
        <div className="card-header">
          <div className="card-title-group">
            <AlertOctagon size={18} color="var(--accent-cyan)" />
            <h2 className="card-title">Normalized Security Findings ({findings.length})</h2>
          </div>

          {/* Filter Pills */}
          <div style={{ display: 'flex', gap: '6px' }}>
            {['all', 'critical', 'high', 'medium', 'low', 'informational'].map((s) => (
              <button
                key={s}
                className={`btn-secondary ${filterSeverity === s ? 'active' : ''}`}
                style={{
                  padding: '4px 10px',
                  fontSize: '0.74rem',
                  textTransform: 'capitalize',
                  borderColor: filterSeverity === s ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                  color: filterSeverity === s ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                }}
                onClick={() => setFilterSeverity(s)}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {isRunning && (
          <div style={{ padding: '16px', borderRadius: '8px', backgroundColor: 'var(--accent-cyan-subtle)', border: '1px solid rgba(6, 182, 212, 0.3)', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <RefreshCw size={16} style={{ animation: 'spin 1s linear infinite' }} />
            <span style={{ fontSize: '0.84rem' }}>
              Defensive security scanner is running checks in real-time. Findings will appear dynamically upon completion.
            </span>
          </div>
        )}

        {scan.status === 'failed' ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <AlertOctagon size={36} color="var(--accent-rose)" style={{ margin: '0 auto 10px' }} />
            <p style={{ fontSize: '0.95rem', color: 'var(--accent-rose)', fontWeight: 600 }}>
              Security assessment failed
            </p>
            <p style={{ fontSize: '0.82rem', marginTop: '6px', color: 'var(--text-secondary)' }}>
              {scan.error_message || 'An error occurred during the assessment scan.'}
            </p>
          </div>
        ) : filteredFindings.length === 0 && !isRunning ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <ShieldCheck size={36} color="var(--accent-emerald)" style={{ margin: '0 auto 10px' }} />
            <p style={{ fontSize: '0.92rem', color: 'var(--text-primary)', fontWeight: 600 }}>
              {findings.length === 0
                ? 'No security issues were detected by the checks performed.'
                : 'No findings match the selected severity filter.'}
            </p>
            <p style={{ fontSize: '0.8rem', marginTop: '4px' }}>
              All evaluated attributes passed baseline defensive standards.
            </p>
          </div>
        ) : (
          <div className="diagnostic-list">
            {filteredFindings.map((finding) => (
              <div
                key={finding.id}
                className="finding-row"
                onClick={() => {
                  setSelectedFinding(finding);
                  onSelectFinding?.(finding.id);
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: 0 }}>
                  <span
                    className={`badge ${
                      finding.severity === 'critical' || finding.severity === 'high'
                        ? 'badge-rose'
                        : finding.severity === 'medium'
                        ? 'badge-amber'
                        : 'badge-cyan'
                    }`}
                    style={{ minWidth: '70px', justifyContent: 'center' }}
                  >
                    {finding.severity.toUpperCase()}
                  </span>

                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
                      {finding.title}
                    </div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', display: 'flex', gap: '10px', marginTop: '2px' }}>
                      <span>Category: {finding.category}</span>
                      {finding.cwe && <span>{finding.cwe}</span>}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                  <div style={{ textAlign: 'right' }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block' }}>RISK</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.9rem', color: 'var(--accent-cyan)' }}>
                      {finding.risk_score}
                    </span>
                  </div>

                  <span className="nav-link-badge" style={{ textTransform: 'uppercase' }}>
                    {finding.status}
                  </span>

                  <ChevronRight size={16} color="var(--text-muted)" />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Finding Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => {
          setSelectedFinding(null);
          onSelectFinding?.(null);
        }}
        onStatusChanged={(updated) => {
          setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
          setSelectedFinding(updated);
        }}
      />
    </div>
  );
};
