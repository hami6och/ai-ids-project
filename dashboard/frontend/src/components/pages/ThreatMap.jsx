import React, { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useTopIPs, useAlerts } from '../../hooks/useApi.js';
import { Card, SeverityBadge, TypeTag, IPChip, EmptyState } from '../ui/index.jsx';
import { formatDate, SEVERITY } from '../../lib/constants.js';
import { Map } from 'lucide-react';

function IPRow({ entry, alerts }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = SEVERITY[entry.top_severity] || SEVERITY.LOW;
  const ipAlerts = alerts.filter(a => a.source_ip === entry.ip).slice(0, 10);

  return (
    <>
      <tr
        onClick={() => setExpanded(e => !e)}
        style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer', transition: 'background 0.1s' }}
        onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
        onMouseLeave={e => e.currentTarget.style.background = expanded ? 'var(--bg-hover)' : ''}
      >
        <td style={{ padding: '11px 14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {expanded ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}
            <IPChip ip={entry.ip} />
          </div>
        </td>
        <td style={{ padding: '11px 14px' }}>
          <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
            {entry.types.slice(0, 3).map(t => <TypeTag key={t} type={t} />)}
            {entry.types.length > 3 && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>+{entry.types.length - 3}</span>
            )}
          </div>
        </td>
        <td style={{ padding: '11px 14px' }}>
          <SeverityBadge severity={entry.top_severity} />
        </td>
        <td style={{ padding: '11px 14px', fontFamily: 'var(--font-mono)', fontSize: 18, fontWeight: 800, color: cfg.color }}>
          {entry.count}
        </td>
        <td style={{ padding: '11px 14px', fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          {formatDate(entry.first_seen)}
        </td>
        <td style={{ padding: '11px 14px', fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
          {formatDate(entry.last_seen)}
        </td>
      </tr>
      {expanded && (
        <tr style={{ background: 'var(--bg)' }}>
          <td colSpan={6} style={{ padding: '0 14px 14px 40px' }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.06em', marginBottom: 8, marginTop: 10 }}>
              RECENT ALERTS FROM {entry.ip}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {ipAlerts.length === 0 ? (
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No detail available</div>
              ) : ipAlerts.map((a, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  background: 'var(--bg-card)', borderRadius: 6, padding: '7px 12px',
                  border: '1px solid var(--border)',
                }}>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', minWidth: 130 }}>
                    {formatDate(a.timestamp)}
                  </span>
                  <TypeTag type={a.type} />
                  <SeverityBadge severity={a.severity} />
                  {a.pps && (
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto', fontFamily: 'var(--font-mono)' }}>
                      {a.pps} pps
                    </span>
                  )}
                </div>
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function ThreatMap() {
  const { ips, loading } = useTopIPs();
  const { alerts } = useAlerts({}, 200);

  const criticalIPs = ips.filter(ip => ip.top_severity === 'CRITICAL').length;
  const highIPs     = ips.filter(ip => ip.top_severity === 'HIGH').length;

  return (
    <div className="fade-in-up">
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--font-display)', marginBottom: 4 }}>Threat Map</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Active attacker IPs ranked by alert count</p>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Total IPs', value: ips.length, color: 'var(--text-primary)' },
          { label: 'Critical IPs', value: criticalIPs, color: 'var(--critical)' },
          { label: 'High IPs', value: highIPs, color: 'var(--high)' },
          { label: 'Top IP Alerts', value: ips[0]?.count || 0, color: 'var(--accent)' },
        ].map(({ label, value, color }) => (
          <Card key={label} style={{ padding: '16px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 5 }}>{label}</div>
            <div style={{ fontSize: 26, fontWeight: 800, fontFamily: 'var(--font-display)', color }}>{value}</div>
          </Card>
        ))}
      </div>

      {/* Table */}
      <Card>
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading threat data...</div>
        ) : ips.length === 0 ? (
          <EmptyState icon={Map} message="No attacker IPs recorded" />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border)' }}>
                  {['Source IP', 'Attack Types', 'Top Severity', 'Total Alerts', 'First Seen', 'Last Seen'].map(col => (
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
                {ips.map(entry => (
                  <IPRow key={entry.ip} entry={entry} alerts={alerts} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
