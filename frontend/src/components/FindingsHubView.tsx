import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  AlertOctagon,
  ShieldAlert,
  Search,
  Filter,
  ArrowUpDown,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Layers,
  CheckCircle2,
  AlertTriangle,
  FolderLock,
  X,
} from 'lucide-react';
import {
  Finding,
  FindingSeverity,
  FindingStatus,
  FindingsSummaryResponse,
} from '../types/finding';
import { Project } from '../types/project';
import { fetchFindings, fetchFindingsSummary, fetchProjects } from '../services/api';
import { FindingDetailModal } from './FindingDetailModal';

interface FindingsHubViewProps {
  initialFindingId?: string;
  onNavigateScan?: (scanId: string) => void;
  onNavigateProject?: (projectId: string) => void;
}

export const FindingsHubView: React.FC<FindingsHubViewProps> = ({
  initialFindingId,
  onNavigateScan,
  onNavigateProject,
}) => {
  // Findings data
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Summary & Projects metadata
  const [summary, setSummary] = useState<FindingsSummaryResponse | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);

  // Filters & Pagination
  const [search, setSearch] = useState<string>('');
  const [projectFilter, setProjectFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<FindingSeverity | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<FindingStatus | 'all'>('all');
  const [sortBy, setSortBy] = useState<
    'risk_score' | 'severity' | 'created_at' | 'updated_at' | 'title' | 'status'
  >('risk_score');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState<number>(1);
  const [limit, setLimit] = useState<number>(25);

  // Active finding for detail/triage modal
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);

  // Load Projects list for filter dropdown
  useEffect(() => {
    fetchProjects()
      .then(setProjects)
      .catch((err) => console.error('Failed to load projects for findings filter:', err));
  }, []);

  // Load aggregate metrics summary
  const loadSummary = useCallback(async () => {
    try {
      const data = await fetchFindingsSummary(
        projectFilter !== 'all' ? { project_id: projectFilter } : undefined
      );
      setSummary(data);
    } catch (err) {
      console.error('Failed to load findings summary:', err);
    }
  }, [projectFilter]);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  // Load paginated findings
  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const offset = (page - 1) * limit;
      const res = await fetchFindings({
        project_id: projectFilter !== 'all' ? projectFilter : undefined,
        severity: severityFilter !== 'all' ? severityFilter : undefined,
        status: statusFilter !== 'all' ? statusFilter : undefined,
        search: search.trim() ? search.trim() : undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
        limit,
        offset,
      });
      setFindings(res.items);
      setTotal(res.total);

      // If initialFindingId was passed in URL and matches an item, open it
      if (initialFindingId && !activeFinding) {
        const matched = res.items.find((f) => f.id === initialFindingId);
        if (matched) {
          setActiveFinding(matched);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to retrieve findings';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [projectFilter, severityFilter, statusFilter, search, sortBy, sortOrder, page, limit, initialFindingId]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  // Reset page to 1 whenever filters change
  const handleFilterChange = (setter: () => void) => {
    setPage(1);
    setter();
  };

  const handleResetFilters = () => {
    setSearch('');
    setProjectFilter('all');
    setSeverityFilter('all');
    setStatusFilter('all');
    setSortBy('risk_score');
    setSortOrder('desc');
    setPage(1);
  };

  const hasActiveFilters = useMemo(() => {
    return (
      search.trim() !== '' ||
      projectFilter !== 'all' ||
      severityFilter !== 'all' ||
      statusFilter !== 'all'
    );
  }, [search, projectFilter, severityFilter, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(total / limit));

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'badge-rose';
      case 'medium':
        return 'badge-amber';
      case 'low':
      case 'informational':
      default:
        return 'badge-cyan';
    }
  };

  const getStatusBadgeClass = (st: FindingStatus) => {
    switch (st) {
      case 'resolved':
        return 'badge-emerald';
      case 'in_progress':
        return 'badge-amber';
      case 'open':
        return 'badge-rose';
      case 'accepted_risk':
      case 'false_positive':
      default:
        return 'badge-cyan';
    }
  };

  return (
    <div className="findings-hub-view" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* View Header */}
      <section className="hero-card" style={{ marginBottom: '0' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-logo-badge" style={{ width: '38px', height: '38px' }}>
              <AlertOctagon size={20} color="var(--accent-cyan)" />
            </div>
            <div>
              <h1 className="hero-title" style={{ fontSize: '1.4rem' }}>
                Normalized Security Findings Hub
              </h1>
              <p className="hero-subtitle" style={{ fontSize: '0.84rem' }}>
                Centralized vulnerability triage, OCC lifecycle management, and audit tracking across all monitored assets.
              </p>
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'flex-end' }}>
          <span className="badge badge-cyan" style={{ fontSize: '0.78rem' }}>
            PHASE 4 ACTIVE
          </span>
          <button
            className="btn-secondary"
            onClick={() => {
              loadSummary();
              loadFindings();
            }}
            style={{ fontSize: '0.8rem', padding: '6px 12px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            <span>Refresh Findings</span>
          </button>
        </div>
      </section>

      {/* Summary KPI Cards Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
          gap: '12px',
        }}
      >
        {/* Total Card */}
        <div
          className="surface-card"
          onClick={() => {
            setSeverityFilter('all');
            setStatusFilter('all');
            setPage(1);
          }}
          style={{
            padding: '14px 16px',
            cursor: 'pointer',
            border: severityFilter === 'all' && statusFilter === 'all' ? '1px solid var(--accent-cyan)' : undefined,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>TOTAL</span>
            <Layers size={14} color="var(--text-secondary)" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
            {summary?.total ?? total}
          </div>
        </div>

        {/* Critical */}
        <div
          className="surface-card"
          onClick={() => {
            setSeverityFilter('critical');
            setPage(1);
          }}
          style={{
            padding: '14px 16px',
            cursor: 'pointer',
            border: severityFilter === 'critical' ? '1px solid var(--accent-rose)' : undefined,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent-rose)', fontWeight: 700 }}>CRITICAL</span>
            <ShieldAlert size={14} color="var(--accent-rose)" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-rose)', marginTop: '4px' }}>
            {summary?.by_severity?.['critical'] || 0}
          </div>
        </div>

        {/* High */}
        <div
          className="surface-card"
          onClick={() => {
            setSeverityFilter('high');
            setPage(1);
          }}
          style={{
            padding: '14px 16px',
            cursor: 'pointer',
            border: severityFilter === 'high' ? '1px solid var(--accent-rose)' : undefined,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent-rose)', fontWeight: 700 }}>HIGH</span>
            <ShieldAlert size={14} color="var(--accent-rose)" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-rose)', marginTop: '4px' }}>
            {summary?.by_severity?.['high'] || 0}
          </div>
        </div>

        {/* Medium */}
        <div
          className="surface-card"
          onClick={() => {
            setSeverityFilter('medium');
            setPage(1);
          }}
          style={{
            padding: '14px 16px',
            cursor: 'pointer',
            border: severityFilter === 'medium' ? '1px solid var(--accent-amber)' : undefined,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent-amber)', fontWeight: 700 }}>MEDIUM</span>
            <AlertTriangle size={14} color="var(--accent-amber)" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-amber)', marginTop: '4px' }}>
            {summary?.by_severity?.['medium'] || 0}
          </div>
        </div>

        {/* Low */}
        <div
          className="surface-card"
          onClick={() => {
            setSeverityFilter('low');
            setPage(1);
          }}
          style={{
            padding: '14px 16px',
            cursor: 'pointer',
            border: severityFilter === 'low' ? '1px solid var(--accent-cyan)' : undefined,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>LOW</span>
            <Layers size={14} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', marginTop: '4px' }}>
            {summary?.by_severity?.['low'] || 0}
          </div>
        </div>

        {/* Informational */}
        <div
          className="surface-card"
          onClick={() => {
            setSeverityFilter('informational');
            setPage(1);
          }}
          style={{
            padding: '14px 16px',
            cursor: 'pointer',
            border: severityFilter === 'informational' ? '1px solid var(--border-subtle)' : undefined,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 700 }}>INFO</span>
            <Layers size={14} color="var(--text-muted)" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', marginTop: '4px' }}>
            {summary?.by_severity?.['informational'] || 0}
          </div>
        </div>

        {/* Resolved */}
        <div
          className="surface-card"
          onClick={() => {
            setStatusFilter('resolved');
            setPage(1);
          }}
          style={{
            padding: '14px 16px',
            cursor: 'pointer',
            border: statusFilter === 'resolved' ? '1px solid var(--accent-emerald)' : undefined,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent-emerald)', fontWeight: 700 }}>RESOLVED</span>
            <CheckCircle2 size={14} color="var(--accent-emerald)" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-emerald)', marginTop: '4px' }}>
            {summary?.by_status?.['resolved'] || 0}
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div
        className="surface-card"
        style={{
          padding: '16px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
          }}
        >
          {/* Keyword Search Input */}
          <div
            style={{
              position: 'relative',
              flex: '1 1 280px',
              minWidth: '220px',
            }}
          >
            <Search
              size={15}
              style={{
                position: 'absolute',
                left: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--text-muted)',
              }}
            />
            <input
              type="text"
              className="form-input"
              placeholder="Search findings by title, description, or endpoint..."
              value={search}
              onChange={(e) => handleFilterChange(() => setSearch(e.target.value))}
              style={{
                width: '100%',
                paddingLeft: '34px',
                paddingRight: search ? '30px' : '12px',
                fontSize: '0.82rem',
              }}
            />
            {search && (
              <button
                type="button"
                onClick={() => handleFilterChange(() => setSearch(''))}
                style={{
                  position: 'absolute',
                  right: '10px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Project Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FolderLock size={15} color="var(--text-muted)" />
            <select
              className="form-input"
              value={projectFilter}
              onChange={(e) => handleFilterChange(() => setProjectFilter(e.target.value))}
              style={{ fontSize: '0.82rem', padding: '8px 12px' }}
            >
              <option value="all">All Projects</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          {/* Severity Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Filter size={15} color="var(--text-muted)" />
            <select
              className="form-input"
              value={severityFilter}
              onChange={(e) =>
                handleFilterChange(() => setSeverityFilter(e.target.value as FindingSeverity | 'all'))
              }
              style={{ fontSize: '0.82rem', padding: '8px 12px' }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
          </div>

          {/* Status Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <select
              className="form-input"
              value={statusFilter}
              onChange={(e) =>
                handleFilterChange(() => setStatusFilter(e.target.value as FindingStatus | 'all'))
              }
              style={{ fontSize: '0.82rem', padding: '8px 12px' }}
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="accepted_risk">Accepted Risk</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          {/* Sort By */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ArrowUpDown size={15} color="var(--text-muted)" />
            <select
              className="form-input"
              value={`${sortBy}_${sortOrder}`}
              onChange={(e) => {
                const val = e.target.value;
                if (val === 'risk_desc') {
                  setSortBy('risk_score');
                  setSortOrder('desc');
                } else if (val === 'risk_asc') {
                  setSortBy('risk_score');
                  setSortOrder('asc');
                } else if (val === 'date_desc') {
                  setSortBy('created_at');
                  setSortOrder('desc');
                } else if (val === 'date_asc') {
                  setSortBy('created_at');
                  setSortOrder('asc');
                } else if (val === 'title_asc') {
                  setSortBy('title');
                  setSortOrder('asc');
                } else if (val === 'status_asc') {
                  setSortBy('status');
                  setSortOrder('asc');
                }
              }}
              style={{ fontSize: '0.82rem', padding: '8px 12px' }}
            >
              <option value="risk_desc">Risk Score: Highest First</option>
              <option value="risk_asc">Risk Score: Lowest First</option>
              <option value="date_desc">Discovered: Most Recent</option>
              <option value="date_asc">Discovered: Oldest First</option>
              <option value="title_asc">Title: A &rarr; Z</option>
              <option value="status_asc">Status</option>
            </select>
          </div>

          {/* Reset Filters */}
          {hasActiveFilters && (
            <button
              className="btn-secondary"
              onClick={handleResetFilters}
              style={{ fontSize: '0.78rem', padding: '7px 12px' }}
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          style={{
            padding: '14px 18px',
            borderRadius: '8px',
            backgroundColor: 'rgba(244, 63, 94, 0.1)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            color: 'var(--accent-rose)',
            fontSize: '0.84rem',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
          }}
        >
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Findings Table Card */}
      <div className="surface-card" style={{ padding: '0', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <RefreshCw size={24} className="spin" style={{ margin: '0 auto 12px' }} />
            <p style={{ fontSize: '0.88rem' }}>Loading security findings...</p>
          </div>
        ) : findings.length === 0 ? (
          <div style={{ padding: '60px 20px', textAlign: 'center' }}>
            <AlertOctagon size={36} color="var(--text-muted)" style={{ margin: '0 auto 12px' }} />
            <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
              No findings discovered
            </p>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
              {hasActiveFilters
                ? 'No findings matched the selected filters. Try clearing search or filters.'
                : 'No security findings recorded yet. Run a website assessment to discover potential risks.'}
            </p>
            {hasActiveFilters && (
              <button className="btn-secondary" onClick={handleResetFilters}>
                Clear All Filters
              </button>
            )}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr
                  style={{
                    backgroundColor: 'var(--bg-card)',
                    borderBottom: '1px solid var(--border-subtle)',
                    fontSize: '0.74rem',
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                  }}
                >
                  <th style={{ padding: '12px 18px', width: '100px' }}>Severity</th>
                  <th style={{ padding: '12px 18px' }}>Finding & Vulnerability</th>
                  <th style={{ padding: '12px 18px', width: '200px' }}>Target / Project</th>
                  <th style={{ padding: '12px 18px', width: '110px' }}>Risk Score</th>
                  <th style={{ padding: '12px 18px', width: '130px' }}>Status</th>
                  <th style={{ padding: '12px 18px', width: '110px' }}>Updated</th>
                  <th style={{ padding: '12px 18px', width: '90px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setActiveFinding(f)}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      fontSize: '0.82rem',
                      cursor: 'pointer',
                      transition: 'background-color 0.15s ease',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.02)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }}
                  >
                    {/* Severity */}
                    <td style={{ padding: '12px 18px' }}>
                      <span className={`badge ${getSeverityBadgeClass(f.severity)}`}>
                        {f.severity.toUpperCase()}
                      </span>
                    </td>

                    {/* Finding Title & CWE */}
                    <td style={{ padding: '12px 18px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{f.title}</span>
                        {f.cwe && <span className="nav-link-badge" style={{ fontSize: '0.68rem' }}>{f.cwe}</span>}
                      </div>
                      <div
                        style={{
                          fontSize: '0.74rem',
                          color: 'var(--text-muted)',
                          marginTop: '3px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                        }}
                      >
                        <span>Category: {f.category}</span>
                        {f.endpoint && (
                          <span
                            className="code-block"
                            style={{
                              padding: '1px 6px',
                              fontSize: '0.7rem',
                              maxWidth: '300px',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {f.endpoint}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Target / Project */}
                    <td style={{ padding: '12px 18px' }}>
                      <div
                        style={{
                          fontWeight: 600,
                          color: onNavigateProject && f.project_id ? 'var(--accent-cyan)' : 'var(--text-primary)',
                          cursor: onNavigateProject && f.project_id ? 'pointer' : 'default',
                        }}
                        onClick={(e) => {
                          if (onNavigateProject && f.project_id) {
                            e.stopPropagation();
                            onNavigateProject(f.project_id);
                          }
                        }}
                      >
                        {f.project_name || 'Website'}
                      </div>
                      {f.target_url && (
                        <div
                          style={{
                            fontSize: '0.72rem',
                            color: 'var(--text-muted)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            maxWidth: '180px',
                            cursor: onNavigateScan && f.scan_id ? 'pointer' : 'default',
                          }}
                          onClick={(e) => {
                            if (onNavigateScan && f.scan_id) {
                              e.stopPropagation();
                              onNavigateScan(f.scan_id);
                            }
                          }}
                        >
                          {f.target_url}
                        </div>
                      )}
                    </td>

                    {/* Risk Score */}
                    <td style={{ padding: '12px 18px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 700,
                            color: f.risk_score >= 75 ? 'var(--accent-rose)' : f.risk_score >= 50 ? 'var(--accent-amber)' : 'var(--accent-cyan)',
                          }}
                        >
                          {f.risk_score}
                        </span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>/100</span>
                      </div>
                    </td>

                    {/* Status */}
                    <td style={{ padding: '12px 18px' }}>
                      <span className={`badge ${getStatusBadgeClass(f.status)}`}>
                        {f.status.replace('_', ' ').toUpperCase()}
                      </span>
                    </td>

                    {/* Updated */}
                    <td style={{ padding: '12px 18px', color: 'var(--text-muted)', fontSize: '0.76rem' }}>
                      {new Date(f.updated_at || f.created_at).toLocaleDateString()}
                    </td>

                    {/* Actions */}
                    <td style={{ padding: '12px 18px', textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={(e) => {
                          e.stopPropagation();
                          setActiveFinding(f);
                        }}
                        style={{ padding: '4px 10px', fontSize: '0.74rem' }}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {total > 0 && (
          <div
            style={{
              padding: '12px 20px',
              borderTop: '1px solid var(--border-subtle)',
              backgroundColor: 'var(--bg-card)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
            }}
          >
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Showing {Math.min((page - 1) * limit + 1, total)} to {Math.min(page * limit, total)} of {total} findings
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              {/* Limit selector */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                <span>Per page:</span>
                <select
                  className="form-input"
                  value={limit}
                  onChange={(e) => {
                    setLimit(Number(e.target.value));
                    setPage(1);
                  }}
                  style={{ padding: '4px 8px', fontSize: '0.76rem' }}
                >
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>

              {/* Page buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <button
                  type="button"
                  className="btn-secondary"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  style={{ padding: '4px 8px', fontSize: '0.76rem' }}
                >
                  <ChevronLeft size={14} />
                </button>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', padding: '0 4px' }}>
                  Page {page} of {totalPages}
                </span>
                <button
                  type="button"
                  className="btn-secondary"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  style={{ padding: '4px 8px', fontSize: '0.76rem' }}
                >
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Finding Detail Modal with OCC and Audit History */}
      {activeFinding && (
        <FindingDetailModal
          finding={activeFinding}
          onClose={() => setActiveFinding(null)}
          onStatusChanged={(updated) => {
            // Update table items in place
            setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
            setActiveFinding(updated);
            // Reload aggregate summary metrics
            loadSummary();
          }}
        />
      )}
    </div>
  );
};
