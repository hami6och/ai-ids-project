import React from 'react';
import { useDetectors } from '../../hooks/useApi.js';
import { Card } from '../ui/index.jsx';
import { formatDate } from '../../lib/constants.js';

const DETECTOR_META = {
  syn:        { color: '#D0021B', icon: '⚡', label: 'SYN',        types: ['SYN_FLOOD','SYN_SCAN','SLOW_SYN_SCAN'] },
  arp:        { color: '#8B5CF6', icon: '🔀', label: 'ARP',        types: ['ARP_SPOOFING'] },
  icmp:       { color: '#1A6FB3', icon: '📡', label: 'ICMP',       types: ['ICMP_FLOOD','ICMP_REDIRECT'] },
  dns:        { color: '#1A8B5A', icon: '🌐', label: 'DNS',        types: ['DNS_FLOOD','DNS_TUNNEL','DNS_AI','SLOW_DNS_FLOOD'] },
  bruteforce: { color: '#D4620A', icon: '🔑', label: 'Bruteforce', types: ['BRUTE_FORCE','CREDENTIAL_STUFFING','MULTI_SOURCE_BRUTE','SLOW_BRUTE_FORCE'] },
  ftp:        { color: '#B08B00', icon: '📁', label: 'FTP',        types: ['FTP_BRUTE_FORCE','FTP_BOUNCE'] },
  dhcp:       { color: '#5A6472', icon: '🖧',  label: 'DHCP',       types: ['DHCP_STARVATION','DHCP_ROGUE_SERVER','DHCP_DECLINE_FLOOD','DHCP_RAPID_CYCLING'] },
};

const CONFIG_META = {
  flood_rate:           { label: 'Flood Rate',           min: 1,   max: 200, step: 1    },
  port_scan_threshold:  { label: 'Port Scan Threshold',  min: 1,   max: 100, step: 1    },
  request_threshold:    { label: 'Request Threshold',    min: 1,   max: 200, step: 1    },
  attempt_threshold:    { label: 'Attempt Threshold',    min: 1,   max: 200, step: 1    },
  bounce_threshold:     { label: 'Bounce Threshold',     min: 1,   max: 20,  step: 1    },
  alert_threshold:      { label: 'Alert Threshold',      min: 1,   max: 50,  step: 1    },
  rate_threshold:       { label: 'Rate Threshold',       min: 1,   max: 100, step: 1    },
  starvation_pps:       { label: 'Starvation PPS',       min: 1,   max: 200, step: 1    },
  starvation_mac_count: { label: 'Starvation MAC Count', min: 1,   max: 100, step: 1    },
  tunnel_qname_len:     { label: 'Tunnel QNAME Length',  min: 20,  max: 200, step: 1    },
  alert_cooldown:       { label: 'Alert Cooldown (s)',   min: 5,   max: 300, step: 5    },
  ai_threshold:         { label: 'AI Threshold',         min: 0.1, max: 1.0, step: 0.05 },
  time_window:          { label: 'Time Window (s)',      min: 1,   max: 60,  step: 1    },
};

function BreakdownBar({ types, byType, color }) {
  const total = types.reduce((s, t) => s + (byType[t] || 0), 0);
  if (total === 0) return (
    <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>No alerts yet</div>
  );
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
      {types.filter(t => byType[t] > 0).map(t => {
        const count = byType[t] || 0;
        const pct   = Math.round(count / total * 100);
        return (
          <div key={t}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                {t.replace(/_/g, ' ')}
              </span>
              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {count}
              </span>
            </div>
            <div style={{ height: 4, background: 'var(--border)', borderRadius: 999, overflow: 'hidden' }}>
              <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 999, transition: 'width 0.4s' }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DetectorCard({ detector }) {
  const meta   = DETECTOR_META[detector.name] || { color: '#888', icon: '🔍', label: detector.name, types: [] };
  const byType = detector.by_type || {};

  return (
    <Card style={{ overflow: 'hidden' }}>
      <div style={{ height: 3, background: meta.color }} />
      <div style={{ padding: '16px 18px' }}>

        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 38, height: 38, borderRadius: 9,
              background: `${meta.color}15`,
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
            }}>
              {meta.icon}
            </div>
            <div>
              <div style={{ fontWeight: 700, fontFamily: 'var(--font-display)', fontSize: 15, letterSpacing: '0.04em' }}>
                {meta.label}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
                {detector.last_type || '—'}
              </div>
            </div>
          </div>
          <div style={{
            width: 8, height: 8, borderRadius: '50%', marginTop: 4,
            background: detector.enabled ? '#1A8B5A' : '#9E9A93',
            boxShadow: detector.enabled ? '0 0 6px #1A8B5A80' : 'none',
          }} />
        </div>

        {/* Alert count */}
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 4 }}>
            Total Alerts
          </div>
          <div style={{ fontSize: 36, fontWeight: 800, fontFamily: 'var(--font-display)', color: meta.color, lineHeight: 1 }}>
            {detector.alert_count}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            Last: {formatDate(detector.last_alert) || '—'}
          </div>
        </div>

        {/* Alert breakdown */}
        <div style={{ paddingTop: 14, borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 10 }}>
            Alert Breakdown
          </div>
          <BreakdownBar types={meta.types} byType={byType} color={meta.color} />
        </div>

      </div>
    </Card>
  );
}

export default function Detectors() {
  const { detectors, loading } = useDetectors();
  const totalAlerts  = detectors.reduce((s, d) => s + (d.alert_count || 0), 0);
  const enabledCount = detectors.filter(d => d.enabled).length;

  return (
    <div className="fade-in-up">
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--font-display)', marginBottom: 4 }}>
          Detector Status
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          {enabledCount}/{detectors.length} detectors active · {totalAlerts} total alerts
        </p>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>Loading detectors...</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16 }}>
          {detectors.map(d => (
            <DetectorCard key={d.name} detector={d} />
          ))}
        </div>
      )}
    </div>
  );
}

