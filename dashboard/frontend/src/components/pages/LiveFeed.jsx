import React, { useState, useEffect, useRef } from 'react';
import { Filter, RefreshCw, AlertCircle } from 'lucide-react';
import { useAlerts, useLiveAlerts } from '../../hooks/useApi.js';
import { SeverityBadge, DetectionBadge, IPChip, TypeTag, Card, LiveDot, ConfidenceBar, EmptyState } from '../ui/index.jsx';
import { formatDate, SEVERITY } from '../../lib/constants.js';

const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const DETECTIONS = ['', 'RULE', 'AI_ONLY', 'RULE+AI', 'SLOW', 'DISTRIBUTED', 'CORRELATION'];

export default function LiveFeed() {
  const [filters, setFilters] = useState({ severity: '', type: '', source_ip: '' });
  const [localAlerts, setLocalAlerts] = useState([]);
  const [newIds, setNewIds] = useState(new Set());
  const [showFilters, setShowFilters] = useState(false);
  const initialized = useRef(false);

  const { alerts, loading, refetch } = useAlerts(
    Object.fromEntries(Object.entries(filters).filter(([,v]) => v)),
    100
  );

  useEffect(() => {
    if (!loading) {
      setLocalAlerts(alerts);
      initialized.current = true;
    }
  }, [alerts, loading]);

  useLiveAlerts((newAlert) => {
    if (!initialized.current) return;
    setLocalAlerts(prev => [newAlert, ...prev].slice(0, 200));
    setNewIds(prev => {
      const s = new Set(prev);
      s.add(String(newAlert._id));
      return s;
    });
    setTimeout(() => {
      setNewIds(prev => { const s = new Set(prev); s.delete(String(newAlert._id)); return s; });
    }, 1500);
  });

  const displayed = localAlerts.filter(a => {
    if (filters.severity && a.severity !== filters.severity) return false;
    if (filters.type && !a.type?.toLowerCase().includes(filters.type.toLowerCase())) return false;
    if (filters.source_ip && !a.source_ip?.includes(filters.source_ip)) return false;
    return true;
  });

  return (
    <div className="fade-in-up">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--font-display)', marginBottom: 2 }}>Live Alert Feed</h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <LiveDot />
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{displayed.length} alerts shown</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => setShowFilters(f => !f)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px',
              background: showFilters ? 'var(--accent)' : 'var(--bg-card)',
              color: showFilters ? '#fff' : 'var(--text-secondary)',
              border: '1px solid var(--border)', borderRadius: 7,
              fontSize: 13, fontWeight: 500, cursor: 'pointer',
            }}
          >
            <Filter size={14} /> Filters
          </button>
          <button
            onClick={refetch}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px',
              background: 'var(--bg-card)', color: 'var(--text-secondary)',
              border: '1px solid var(--border)', borderRadius: 7,
              fontSize: 13, fontWeight: 500, cursor: 'pointer',
            }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      {showFilters && (
        <Card style={{ padding: 16, marginBottom: 16, display: 'flex', gap: 12, flexWrap: 'wrap' }} className="slide-in">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>SEVERITY</label>
            <select
              value={filters.severity}
              onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', fontSize: 13, color: 'var(--text-primary)', cursor: 'pointer' }}
            >
              {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All severities'}</option>)}
            </select>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>TYPE</label>
            <input
              placeholder="Filter by type..."
              value={filters.type}
              onChange={e => setFilters(f => ({ ...f, type: e.target.value }))}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', fontSize: 13, width: 160 }}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>SOURCE IP</label>
            <input
              placeholder="192.168.x.x"
              value={filters.source_ip}
              onChange={e => setFilters(f => ({ ...f, source_ip: e.target.value }))}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', fontSize: 13, fontFamily: 'var(--font-mono)', width: 140 }}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <button
              onClick={() => setFilters({ severity: '', type: '', source_ip: '' })}
              style={{ padding: '6px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', fontSize: 13, color: 'var(--text-secondary)', cursor: 'pointer' }}
            >
              Clear
            </button>
          </div>
        </Card>
      )}

      {/* Severity Summary Bar */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        {Object.entries(SEVERITY).map(([sev, cfg]) => {
          const count = displayed.filter(a => a.severity === sev).length;
          return (
            <button
              key={sev}
              onClick={() => setFilters(f => ({ ...f, severity: f.severity === sev ? '' : sev }))}
              style={{
                display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px',
                borderRadius: 999, border: `1px solid ${cfg.color}30`,
                background: filters.severity === sev ? cfg.bg : 'var(--bg-card)',
                cursor: 'pointer', transition: 'all 0.15s',
              }}
            >
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.dot }} />
              <span style={{ fontSize: 11, fontWeight: 600, color: cfg.color }}>{sev}</span>
              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{count}</span>
            </button>
          );
        })}
      </div>

      {/* Alert Table */}
      <Card>
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading alerts...</div>
        ) : displayed.length === 0 ? (
          <EmptyState icon={AlertCircle} message="No alerts match the current filters" />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border)' }}>
                  {['Timestamp','Type','Source IP','Target IP','Severity','Detection','AI Confidence'].map(col => (
                    <th key={col} style={{
                      padding: '10px 14px', textAlign: 'left',
                      fontSize: 10, fontWeight: 700, color: 'var(--text-muted)',
                      letterSpacing: '0.08em', textTransform: 'uppercase', whiteSpace: 'nowrap',
                    }}>
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayed.map((alert, i) => {
                  const id = String(alert._id);
                  const isNew = newIds.has(id);
                  return (
                    <tr
                      key={id}
                      className={isNew ? 'new-row' : ''}
                      style={{
                        borderBottom: '1px solid var(--border)',
                        transition: 'background 0.15s',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                      onMouseLeave={e => e.currentTarget.style.background = ''}
                    >
                      <td style={{ padding: '10px 14px', fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                        {formatDate(alert.timestamp)}
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <TypeTag type={alert.type} />
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <IPChip ip={alert.source_ip} />
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <IPChip ip={alert.target_ip} />
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <DetectionBadge detection={alert.detection} />
                      </td>
                      <td style={{ padding: '10px 14px', minWidth: 120 }}>
                        <ConfidenceBar value={alert.ai_confidence} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
