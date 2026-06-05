import React from 'react';
import { SEVERITY, DETECTION } from '../../lib/constants.js';

// ─── Severity Badge ────────────────────────────────────────────────────────────
export function SeverityBadge({ severity }) {
  const cfg = SEVERITY[severity] || SEVERITY.LOW;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 8px', borderRadius: 999,
      background: cfg.bg, color: cfg.color,
      fontSize: 11, fontWeight: 600, letterSpacing: '0.03em',
      fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: cfg.dot, flexShrink: 0 }} />
      {severity}
    </span>
  );
}

// ─── Detection Badge ───────────────────────────────────────────────────────────
export function DetectionBadge({ detection }) {
  const cfg = DETECTION[detection] || DETECTION.RULE;
  return (
    <span style={{
      display: 'inline-block', padding: '2px 7px',
      borderRadius: 4, border: `1px solid ${cfg.color}22`,
      background: `${cfg.color}12`, color: cfg.color,
      fontSize: 10, fontWeight: 600, letterSpacing: '0.05em',
      fontFamily: 'var(--font-mono)',
    }}>
      {cfg.label}
    </span>
  );
}

// ─── Card ─────────────────────────────────────────────────────────────────────
export function Card({ children, style, className }) {
  return (
    <div className={className} style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', boxShadow: 'var(--shadow-sm)',
      ...style,
    }}>
      {children}
    </div>
  );
}

// ─── Stat Card ────────────────────────────────────────────────────────────────
export function StatCard({ label, value, sub, color, icon: Icon, delay = 0 }) {
  return (
    <Card style={{ padding: '20px 22px', animationDelay: `${delay}ms` }} className="fade-in-up">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 500, letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 6 }}>
            {label}
          </div>
          <div style={{ fontSize: 30, fontWeight: 700, fontFamily: 'var(--font-display)', color: color || 'var(--text-primary)', lineHeight: 1 }}>
            {value ?? '—'}
          </div>
          {sub && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 5 }}>{sub}</div>}
        </div>
        {Icon && (
          <div style={{ padding: 10, borderRadius: 8, background: color ? `${color}12` : 'var(--bg)', color: color || 'var(--text-secondary)' }}>
            <Icon size={18} />
          </div>
        )}
      </div>
    </Card>
  );
}

// ─── Section Header ───────────────────────────────────────────────────────────
export function SectionHeader({ title, action }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
      <h2 style={{ fontSize: 15, fontWeight: 600, fontFamily: 'var(--font-display)' }}>{title}</h2>
      {action}
    </div>
  );
}

// ─── IP Chip ──────────────────────────────────────────────────────────────────
export function IPChip({ ip }) {
  return (
    <span style={{
      fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 500,
      color: 'var(--text-primary)', background: 'var(--bg)',
      border: '1px solid var(--border)', borderRadius: 4,
      padding: '2px 7px', whiteSpace: 'nowrap',
    }}>
      {ip}
    </span>
  );
}

// ─── Type Tag ─────────────────────────────────────────────────────────────────
export function TypeTag({ type }) {
  return (
    <span style={{
      fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 500,
      color: 'var(--text-secondary)',
    }}>
      {type}
    </span>
  );
}

// ─── Loading Skeleton ─────────────────────────────────────────────────────────
export function Skeleton({ w = '100%', h = 16, style }) {
  return (
    <div style={{
      width: w, height: h, borderRadius: 4,
      background: 'linear-gradient(90deg, var(--border) 25%, var(--bg-hover) 50%, var(--border) 75%)',
      backgroundSize: '200% 100%',
      animation: 'shimmer 1.5s infinite',
      ...style,
    }} />
  );
}

// ─── Live Dot ─────────────────────────────────────────────────────────────────
export function LiveDot({ active = true }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span style={{
        width: 7, height: 7, borderRadius: '50%',
        background: active ? '#1A8B5A' : '#9E9A93',
        animation: active ? 'pulse-dot 1.5s ease-in-out infinite' : 'none',
      }} />
      <span style={{ fontSize: 11, color: active ? '#1A8B5A' : 'var(--text-muted)', fontWeight: 600 }}>
        {active ? 'LIVE' : 'OFFLINE'}
      </span>
    </span>
  );
}

// ─── Empty State ──────────────────────────────────────────────────────────────
export function EmptyState({ icon: Icon, message }) {
  return (
    <div style={{ textAlign: 'center', padding: '48px 24px', color: 'var(--text-muted)' }}>
      {Icon && <Icon size={32} style={{ marginBottom: 12, opacity: 0.4 }} />}
      <div style={{ fontSize: 13 }}>{message}</div>
    </div>
  );
}

// ─── Confidence Bar ───────────────────────────────────────────────────────────
export function ConfidenceBar({ value }) {
  const pct = Math.round((value || 0) * 100);
  const color = pct >= 80 ? 'var(--critical)' : pct >= 60 ? 'var(--high)' : pct >= 40 ? 'var(--medium)' : 'var(--low)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: 'var(--border)', borderRadius: 999, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 999, transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', minWidth: 30 }}>{pct}%</span>
    </div>
  );
}
