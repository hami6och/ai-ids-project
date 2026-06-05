import React from 'react';
import { useSystemStats } from '../../hooks/useApi.js';
import { Card } from '../ui/index.jsx';
import { CheckCircle, XCircle } from 'lucide-react';

function HealthRow({ label, value, ok, mono }) {
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      padding: '10px 0', borderBottom: '1px solid var(--border)',
    }}>
      <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{label}</span>
      <span style={{
        fontSize: 13, fontWeight: 600,
        fontFamily: mono ? 'var(--font-mono)' : 'var(--font-body)',
        color: ok === true ? 'var(--det-slow)' : ok === false ? 'var(--critical)' : 'var(--text-primary)',
      }}>
        {value}
      </span>
    </div>
  );
}

export default function SystemHealth() {
  const sys = useSystemStats();

  if (!sys) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
        Loading system stats...
      </div>
    );
  }

  return (
    <div className="fade-in-up">
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--font-display)', marginBottom: 4 }}>System Health</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Real-time IDS infrastructure monitoring</p>
      </div>

      {/* Status header */}
      <Card style={{ padding: '16px 20px', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 10,
          background: sys.mongodb_connected ? 'rgba(26,139,90,0.1)' : 'rgba(208,2,27,0.1)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          {sys.mongodb_connected
            ? <CheckCircle size={22} color="var(--det-slow)" />
            : <XCircle size={22} color="var(--critical)" />
          }
        </div>
        <div>
          <div style={{ fontWeight: 700, fontFamily: 'var(--font-display)', fontSize: 15 }}>
            {sys.mongodb_connected ? 'All Systems Operational' : 'SQLite Offline'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
            Uptime: {sys.uptime_human} · Interface: {sys.interface} · IDS IP: {sys.ids_ip}
          </div>
        </div>
      </Card>

      {/* Packet counters — only received + avg pps */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16, marginBottom: 20 }}>
        <Card style={{ padding: '20px 22px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 8 }}>Packets Received</div>
          <div style={{ fontSize: 28, fontWeight: 800, fontFamily: 'var(--font-display)', color: 'var(--text-primary)' }}>
            {sys.packets_received.toLocaleString()}
          </div>
        </Card>
        <Card style={{ padding: '20px 22px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 8 }}>Avg PPS</div>
          <div style={{ fontSize: 28, fontWeight: 800, fontFamily: 'var(--font-display)', color: 'var(--low)' }}>
            {sys.avg_pps}
          </div>
        </Card>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* MongoDB + Queue */}
        <Card style={{ padding: '20px 22px' }}>
          <div style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-display)', marginBottom: 14 }}>
            Infrastructure
          </div>
          <HealthRow label="MongoDB" value={sys.mongodb_connected ? 'Connected' : 'Offline'} ok={sys.mongodb_connected} />
          <HealthRow label="MongoDB URI" value="localhost:27017" mono />
          <HealthRow label="Queue Size" value={sys.queue_size} ok={sys.queue_size < 10} mono />
          <HealthRow label="Interface" value={sys.interface} mono />
          <HealthRow label="IDS Host" value={sys.ids_ip} mono />
          <HealthRow label="Uptime" value={sys.uptime_human} mono />
        </Card>

        {/* AI Models */}
        <Card style={{ padding: '20px 22px' }}>
          <div style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-display)', marginBottom: 14 }}>
            AI Models Loaded
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {sys.ai_models_loaded.map(model => (
              <div key={model} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '7px 10px', background: 'var(--bg)',
                borderRadius: 6, border: '1px solid var(--border)',
              }}>
                <CheckCircle size={13} color="var(--det-slow)" />
                <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                  {model}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

