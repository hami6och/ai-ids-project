import React, { useState, useEffect } from 'react';
import { Save, RotateCcw, CheckCircle } from 'lucide-react';
import { Card, SectionHeader } from '../ui/index.jsx';
import { API_BASE } from '../../lib/constants.js';

const SECTION_LABELS = {
  syn:        { label: 'SYN Detector',        color: '#D0021B', icon: '⚡' },
  icmp:       { label: 'ICMP Detector',        color: '#1A6FB3', icon: '📡' },
  dns:        { label: 'DNS Detector',         color: '#1A8B5A', icon: '🌐' },
  bruteforce: { label: 'Brute Force Detector', color: '#D4620A', icon: '🔑' },
  ftp:        { label: 'FTP Detector',         color: '#B08B00', icon: '📁' },
  arp:        { label: 'ARP Detector',         color: '#8B5CF6', icon: '🔀' },
  dhcp:       { label: 'DHCP Detector',        color: '#5A6472', icon: '🖧'  },
};

function ConfigRow({ item, onChange }) {
  const isFloat = item.step < 1;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>{item.label}</div>
        {item.unit && <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{item.unit}</div>}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, width: 280 }}>
        <input
          type="range"
          min={item.min} max={item.max} step={item.step}
          value={item.localValue}
          onChange={e => onChange(isFloat ? parseFloat(e.target.value) : parseInt(e.target.value))}
          style={{ flex: 1, accentColor: 'var(--accent)', cursor: 'pointer' }}
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <input
            type="number"
            min={item.min} max={item.max} step={item.step}
            value={item.localValue}
            onChange={e => onChange(isFloat ? parseFloat(e.target.value) : parseInt(e.target.value))}
            style={{
              width: 64, padding: '4px 6px', borderRadius: 6,
              border: '1px solid var(--border)', background: 'var(--bg)',
              fontSize: 12, fontFamily: 'var(--font-mono)', textAlign: 'center',
              color: item.localValue !== item.value ? 'var(--high)' : 'var(--text-primary)',
            }}
          />
          {item.unit && <span style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 30 }}>{item.unit}</span>}
        </div>
        {/* changed indicator */}
        {item.localValue !== item.value && (
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--high)', flexShrink: 0 }} />
        )}
      </div>
    </div>
  );
}

function DetectorSection({ section, items, onSave, saving, saved }) {
  const meta = SECTION_LABELS[section] || { label: section, color: '#888', icon: '🔧' };
  const hasChanges = items.some(i => i.localValue !== i.value);

  return (
    <Card style={{ overflow: 'hidden', marginBottom: 16 }}>
      <div style={{ height: 3, background: meta.color }} />
      <div style={{ padding: '16px 20px' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 7,
              background: `${meta.color}12`,
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16,
            }}>
              {meta.icon}
            </div>
            <div style={{ fontWeight: 700, fontFamily: 'var(--font-display)', fontSize: 14, letterSpacing: '0.03em' }}>
              {meta.label}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {saved === section && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--det-slow)' }}>
                <CheckCircle size={13} /> Saved
              </div>
            )}
            <button
              onClick={() => onSave(section)}
              disabled={!hasChanges || saving === section}
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '6px 14px', borderRadius: 6,
                background: hasChanges ? 'var(--accent)' : 'var(--border)',
                color: hasChanges ? '#fff' : 'var(--text-muted)',
                border: 'none', fontSize: 12, fontWeight: 600,
                cursor: hasChanges ? 'pointer' : 'not-allowed',
                opacity: saving === section ? 0.7 : 1,
              }}
            >
              <Save size={13} />
              {saving === section ? 'Saving...' : 'Apply'}
            </button>
          </div>
        </div>

        {/* Config rows */}
        <div>
          {items.map(item => (
            <ConfigRow key={item.key} item={item} onChange={v => item.onChange(v)} />
          ))}
        </div>
      </div>
    </Card>
  );
}

export default function Settings() {
  const [config, setConfig]   = useState({});
  const [local, setLocal]     = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving]   = useState(null);
  const [saved, setSaved]     = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/config`)
      .then(r => r.json())
      .then(res => {
        if (res.success) {
          setConfig(res.data);
          // init local copy
          const localCopy = {};
          Object.entries(res.data).forEach(([section, items]) => {
            items.forEach(item => { localCopy[item.key] = item.value; });
          });
          setLocal(localCopy);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const handleChange = (key, value) => {
    setLocal(prev => ({ ...prev, [key]: value }));
  };

  const handleSave = async (section) => {
    setSaving(section);
    try {
      const items = config[section] || [];
      const changed = items.filter(item => local[item.key] !== item.value);
      await Promise.all(changed.map(item =>
        fetch(`${API_BASE}/api/config/${item.key}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ value: local[item.key] }),
        })
      ));
      // update base config so "changed" indicators reset
      setConfig(prev => {
        const updated = { ...prev };
        updated[section] = updated[section].map(item => ({
          ...item, value: local[item.key]
        }));
        return updated;
      });
      setSaved(section);
      setTimeout(() => setSaved(null), 2000);
    } finally {
      setSaving(null);
    }
  };

  if (loading) return (
    <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading config...</div>
  );

  const totalChanges = Object.entries(config).reduce((sum, [section, items]) => {
    return sum + items.filter(item => local[item.key] !== item.value).length;
  }, 0);

  return (
    <div className="fade-in-up">
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--font-display)', marginBottom: 4 }}>
          Configuration
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          Live threshold tuning — changes apply instantly without restarting the IDS
          {totalChanges > 0 && (
            <span style={{ marginLeft: 10, color: 'var(--high)', fontWeight: 600 }}>
              · {totalChanges} unsaved change{totalChanges > 1 ? 's' : ''}
            </span>
          )}
        </p>
      </div>

      {Object.entries(config).map(([section, items]) => (
        <DetectorSection
          key={section}
          section={section}
          items={items.map(item => ({
            ...item,
            localValue: local[item.key] ?? item.value,
            onChange: (v) => handleChange(item.key, v),
          }))}
          onSave={handleSave}
          saving={saving}
          saved={saved}
        />
      ))}
    </div>
  );
}
