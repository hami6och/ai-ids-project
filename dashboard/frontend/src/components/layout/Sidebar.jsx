import React from 'react';
import {
  Activity, BarChart2, Shield, Map, Server, Zap, Settings
} from 'lucide-react';

const NAV = [
  { id: 'feed',      label: 'Live Feed',      icon: Activity  },
  { id: 'stats',     label: 'Statistics',     icon: BarChart2 },
  { id: 'detectors', label: 'Detectors',      icon: Shield    },
  { id: 'threats',   label: 'Threat Map',     icon: Map       },
  { id: 'system',    label: 'System Health',  icon: Server    },
  { id: 'settings',  label: 'Configuration',  icon: Settings  },
];

export default function Sidebar({ active, onNav, liveCount, criticalCount }) {
  return (
    <aside style={{
      width: 'var(--sidebar-w)', minHeight: '100vh',
      background: 'var(--bg-sidebar)', display: 'flex', flexDirection: 'column',
      position: 'fixed', left: 0, top: 0, bottom: 0, zIndex: 100,
    }}>
      {/* Logo */}
      <div style={{ padding: '22px 20px 18px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: 'rgba(255,255,255,0.10)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Zap size={16} color="#FFFFFF" />
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 14, color: '#FFFFFF', letterSpacing: '0.02em' }}>
              AI-IDS
            </div>
            <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', letterSpacing: '0.08em', marginTop: 1 }}>
              NETWORK SENTINEL
            </div>
          </div>
        </div>
      </div>

      {/* Live stats strip */}
      <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', gap: 12 }}>
        <div style={{ flex: 1, background: 'rgba(255,255,255,0.04)', borderRadius: 6, padding: '8px 10px' }}>
          <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', letterSpacing: '0.06em' }}>TODAY</div>
          <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-display)', color: '#FFFFFF', lineHeight: 1.2 }}>{liveCount}</div>
        </div>
        <div style={{ flex: 1, background: 'rgba(208,2,27,0.12)', borderRadius: 6, padding: '8px 10px' }}>
          <div style={{ fontSize: 10, color: 'rgba(208,2,27,0.6)', letterSpacing: '0.06em' }}>CRITICAL</div>
          <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-display)', color: '#FF4D4D', lineHeight: 1.2 }}>{criticalCount}</div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '12px 10px' }}>
        {NAV.map(({ id, label, icon: Icon }) => {
          const isActive = active === id;
          return (
            <button
              key={id}
              onClick={() => onNav(id)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                padding: '9px 12px', marginBottom: 2,
                background: isActive ? 'rgba(255,255,255,0.10)' : 'transparent',
                border: 'none', borderRadius: 7, cursor: 'pointer',
                color: isActive ? '#FFFFFF' : 'var(--text-sidebar)',
                fontSize: 13, fontWeight: isActive ? 600 : 400,
                fontFamily: 'var(--font-body)',
                transition: 'all 0.15s ease', textAlign: 'left',
              }}
              onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; }}
              onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent'; }}
            >
              <Icon size={16} />
              {label}
              {id === 'feed' && liveCount > 0 && (
                <span style={{
                  marginLeft: 'auto', fontSize: 10, fontWeight: 700,
                  background: '#D0021B', color: '#fff',
                  borderRadius: 999, padding: '1px 6px', fontFamily: 'var(--font-mono)',
                }}>
                  LIVE
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div style={{ padding: '14px 16px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.2)', letterSpacing: '0.04em' }}>
          IDS · 192.168.68.130 · eth0
        </div>
      </div>
    </aside>
  );
}
