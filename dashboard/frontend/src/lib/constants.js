// Severity config
export const SEVERITY = {
  CRITICAL: { color: 'var(--critical)', bg: 'var(--critical-bg)', soft: 'var(--critical-soft)', dot: '#D0021B' },
  HIGH:     { color: 'var(--high)',     bg: 'var(--high-bg)',     soft: 'var(--high-soft)',     dot: '#D4620A' },
  MEDIUM:   { color: 'var(--medium)',   bg: 'var(--medium-bg)',   soft: 'var(--medium-soft)',   dot: '#B08B00' },
  LOW:      { color: 'var(--low)',      bg: 'var(--low-bg)',      soft: 'var(--low-soft)',      dot: '#1A6FB3' },
};

export const DETECTION = {
  RULE:        { color: 'var(--det-rule)',        label: 'RULE' },
  AI_ONLY:     { color: 'var(--det-ai)',          label: 'AI' },
  'RULE+AI':   { color: 'var(--det-ruleai)',      label: 'RULE+AI' },
  SLOW:        { color: 'var(--det-slow)',         label: 'SLOW' },
  DISTRIBUTED: { color: 'var(--det-distributed)', label: 'DIST' },
  CORRELATION: { color: 'var(--det-correlation)', label: 'CORR' },
};

export const ATTACK_GROUPS = {
  SYN:        ['SYN_SCAN','SYN_FLOOD','SLOW_SYN_SCAN'],
  ICMP:       ['ICMP_FLOOD','ICMP_REDIRECT'],
  DNS:        ['DNS_FLOOD','DNS_TUNNEL','DNS_AI','SLOW_DNS_FLOOD'],
  BRUTE:      ['BRUTE_FORCE','CREDENTIAL_STUFFING','MULTI_SOURCE_BRUTE','SLOW_BRUTE_FORCE'],
  FTP:        ['FTP_BRUTE_FORCE','FTP_BOUNCE'],
  ARP:        ['ARP_SPOOFING'],
  DHCP:       ['DHCP_STARVATION','DHCP_ROGUE_SERVER','DHCP_DECLINE_FLOOD','DHCP_RAPID_CYCLING'],
  ADVANCED:   ['ATTACK_CAMPAIGN','DISTRIBUTED_SYN_FLOOD','DISTRIBUTED_ICMP_FLOOD','DISTRIBUTED_DNS_FLOOD','DISTRIBUTED_BRUTE_FLOOD'],
};

export const API_BASE = 'http://localhost:3001';
export const WS_URL   = 'ws://localhost:3001';

export function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts.replace(' ', 'T'));
  if (isNaN(d)) return ts;
  return d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts.replace ? ts.replace(' ', 'T') : ts);
  if (isNaN(d)) return ts;
  return d.toLocaleString('fr-FR', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

export function formatUptime(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${h}h ${m}m ${s}s`;
}
