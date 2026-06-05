import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area, CartesianGrid, Legend
} from 'recharts';
import { useStats } from '../../hooks/useApi.js';
import { StatCard, Card, SectionHeader } from '../ui/index.jsx';
import { AlertTriangle, Activity, Radio } from 'lucide-react';

const SEV_COLORS = {
  CRITICAL: '#D0021B', HIGH: '#D4620A', MEDIUM: '#B08B00', LOW: '#1A6FB3'
};
const DET_COLORS = {
  RULE: '#5A6472', AI_ONLY: '#6D4BC4', 'RULE+AI': '#B06A10',
  SLOW: '#1A8B5A', DISTRIBUTED: '#EF4444', CORRELATION: '#DC2626'
};
const DETECTOR_COLORS = ['#1A1A1E','#D0021B','#1A6FB3','#1A8B5A','#D4620A','#6D4BC4','#B08B00'];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '10px 14px', boxShadow: 'var(--shadow-md)', fontSize: 13,
    }}>
      <div style={{ fontWeight: 600, marginBottom: 4, color: 'var(--text-secondary)', fontSize: 11 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || p.fill, display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: p.color || p.fill, display: 'inline-block' }} />
          <span style={{ color: 'var(--text-secondary)' }}>{p.name || p.dataKey}:</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
};

// Traffic per detector bar
function ByDetectorCard({ traffic }) {
  if (!traffic?.by_detector?.length) return null;
  const data = traffic.by_detector.map((d, i) => ({
    name: d._id, total: d.total, attacks: d.attacks, normal: d.total - d.attacks,
  }));
  return (
    <Card style={{ padding: '20px 22px' }}>
      <SectionHeader title="Traffic by Detector" />
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ left: -20, right: 10 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }} />
          <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} />
          <Tooltip content={<CustomTooltip />} />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          <Bar dataKey="normal"  name="Normal"  stackId="a" fill="#E8E6E0" radius={[0,0,0,0]} />
          <Bar dataKey="attacks" name="Attacks" stackId="a" fill="#D0021B" radius={[4,4,0,0]} />
        </BarChart>
      </ResponsiveContainer>
    </Card>
  );
}

export default function Statistics() {
  const { stats, traffic, loading } = useStats();

  if (loading || !stats) {
    return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading statistics...</div>;
  }

  const byTypeData = Object.entries(stats.by_type || {})
    .sort((a, b) => b[1] - a[1]).slice(0, 12)
    .map(([name, count]) => ({ name: name.replace(/_/g, ' '), count }));

  const bySeverityData = Object.entries(stats.by_severity || {}).map(([name, value]) => ({ name, value }));
  const byDetectionData = Object.entries(stats.by_detection || {}).map(([name, count]) => ({ name, count }));

  // Traffic timeline — normal vs attacks per hour
  const timelineData = (traffic?.timeline || []).map(row => ({
    hour:    row._id ? row._id.slice(11,16) : '—',
    normal:  row.normal  || 0,
    attacks: row.attacks || 0,
    total:   row.total   || 0,
  }));

  return (
    <div className="fade-in-up">
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--font-display)', marginBottom: 4 }}>Statistics</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Alert analysis + full traffic breakdown</p>
      </div>

      {/* Alert stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <StatCard label="Total Alerts"    value={stats.total}    icon={Activity}      delay={0}   />
        <StatCard label="Critical"        value={stats.critical} icon={AlertTriangle}  color="var(--critical)" delay={60}  />
        <StatCard label="High"            value={stats.high}     icon={AlertTriangle}  color="var(--high)"     delay={120} />
        <StatCard label="Total Packets"   value={traffic?.total?.toLocaleString() || '—'} icon={Radio} color="var(--low)" delay={180} />
      </div>

      {/* Traffic timeline — normal vs attacks */}
      <Card style={{ padding: '20px 22px', marginBottom: 20 }}>
        <SectionHeader title="Traffic Timeline — Normal vs Attacks (24h)" />
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={timelineData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="gNormal"  x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#1A6FB3" stopOpacity={0.15} />
                <stop offset="95%" stopColor="#1A6FB3" stopOpacity={0}    />
              </linearGradient>
              <linearGradient id="gAttacks" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#D0021B" stopOpacity={0.20} />
                <stop offset="95%" stopColor="#D0021B" stopOpacity={0}    />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="hour" tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }} />
            <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} />
            <Tooltip content={<CustomTooltip />} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <Area type="monotone" dataKey="normal"  name="Normal"  stroke="#1A6FB3" strokeWidth={1.5} fill="url(#gNormal)"  dot={false} />
            <Area type="monotone" dataKey="attacks" name="Attacks" stroke="#D0021B" strokeWidth={2}   fill="url(#gAttacks)" dot={false} />
          </AreaChart>
        </ResponsiveContainer>
      </Card>

      {/* Traffic ratio + by detector — only by detector remains */}
      <div style={{ marginBottom: 16 }}>
        <ByDetectorCard traffic={traffic} />
      </div>

      {/* By severity only */}
      <div style={{ marginBottom: 16 }}>
        <Card style={{ padding: '20px 22px' }}>
          <SectionHeader title="By Severity" />
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={bySeverityData} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
                dataKey="value" nameKey="name" paddingAngle={3}>
                {bySeverityData.map(entry => (
                  <Cell key={entry.name} fill={SEV_COLORS[entry.name] || '#ccc'} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 8 }}>
            {bySeverityData.map(({ name, value }) => (
              <div key={name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: SEV_COLORS[name] }} />
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{name}</span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600 }}>{value}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Detection method */}
      <Card style={{ padding: '20px 22px' }}>
        <SectionHeader title="Detection Method Breakdown" />
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={byDetectionData} margin={{ left: -20, right: 10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }} />
            <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {byDetectionData.map(entry => (
                <Cell key={entry.name} fill={DET_COLORS[entry.name] || '#888'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        <div style={{ display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
          {byDetectionData.map(({ name, count }) => (
            <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ width: 8, height: 8, borderRadius: 2, background: DET_COLORS[name] || '#888' }} />
              <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{name}</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600 }}>{count}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

