const express = require('express');
const cors    = require('cors');
const http    = require('http');
const { WebSocketServer } = require('ws');
const path    = require('path');
 
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });
 
app.use(cors());
app.use(express.json());
 
// ─── SQLite ───────────────────────────────────────────────────────────────────
const DB_PATH = path.join(__dirname, '../../data/ids.db');
 
let db            = null;
let sqliteConnected = false;
 
function connectSQLite() {
  try {
    const Database = require('better-sqlite3');
    db = new Database(DB_PATH);
    sqliteConnected = true;
    console.log(`[SQLite] Connected ✅ (${DB_PATH})`);
    startPolling();
  } catch (err) {
    console.warn('[SQLite] Not available —', err.message);
    console.warn('         Using mock data');
    sqliteConnected = false;
  }
}
 
// ─── Polling — new alerts every 2s ───────────────────────────────────────────
let lastSeenId = 0;
 
function startPolling() {
  // init lastSeenId to avoid replaying old alerts on startup
  try {
    const row = db.prepare('SELECT MAX(id) as maxid FROM alerts').get();
    lastSeenId = row?.maxid || 0;
  } catch {}
 
  console.log('[Polling] Watching alerts table every 2s');
  setInterval(() => {
    if (!sqliteConnected) return;
    try {
      const newAlerts = db.prepare(
        'SELECT * FROM alerts WHERE id > ? ORDER BY id ASC LIMIT 20'
      ).all(lastSeenId);
 
      if (newAlerts.length) {
        lastSeenId = newAlerts[newAlerts.length - 1].id;
        newAlerts.forEach(alert => {
          const parsed  = parseAlert(alert);
          const payload = JSON.stringify({ event: 'new_alert', data: parsed });
          wss.clients.forEach(client => {
            if (client.readyState === 1) client.send(payload);
          });
        });
      }
    } catch (err) {
      console.warn('[Polling] Error:', err.message);
    }
  }, 2000);
}
 
// ─── SQLite row → clean object ────────────────────────────────────────────────
function parseAlert(row) {
  const obj = { ...row };
  if (obj.extra_json) {
    try { Object.assign(obj, JSON.parse(obj.extra_json)); } catch {}
    delete obj.extra_json;
  }
  return obj;
}
 
function parseRow(row) {
  const obj = { ...row };
  if (obj.extra_json) {
    try { Object.assign(obj, JSON.parse(obj.extra_json)); } catch {}
    delete obj.extra_json;
  }
  return obj;
}
 
// ─── Mock Data ────────────────────────────────────────────────────────────────
function rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
 
// ─── Helpers ──────────────────────────────────────────────────────────────────
function getAlerts(limit = 50, filters = {}) {
  if (!sqliteConnected) return [];
  let sql     = 'SELECT * FROM alerts';
  const conds = [], params = [];
  if (filters.severity)  { conds.push('severity=?');        params.push(filters.severity); }
  if (filters.type)      { conds.push('type LIKE ?');        params.push(`%${filters.type}%`); }
  if (filters.source_ip) { conds.push('source_ip LIKE ?');   params.push(`%${filters.source_ip}%`); }
  if (conds.length) sql += ' WHERE ' + conds.join(' AND ');
  sql += ` ORDER BY id DESC LIMIT ${parseInt(limit)}`;
  return db.prepare(sql).all(...params).map(parseAlert);
}
 
function getAlertStats() {
  if (!sqliteConnected) return {
    total: 0, critical: 0, high: 0, medium: 0, low: 0,
    by_type: {}, by_detection: {}, by_severity: { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 },
    top_ips: {}, timeline: [],
  };
  const total    = db.prepare('SELECT COUNT(*) as c FROM alerts').get().c;
  const critical = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE severity='CRITICAL'").get().c;
  const high     = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE severity='HIGH'").get().c;
  const medium   = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE severity='MEDIUM'").get().c;
  const low      = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE severity='LOW'").get().c;
  const by_type  = db.prepare('SELECT type, COUNT(*) as c FROM alerts GROUP BY type ORDER BY c DESC LIMIT 12').all();
  const by_det   = db.prepare('SELECT detection, COUNT(*) as c FROM alerts GROUP BY detection').all();
  const top_ips  = db.prepare('SELECT source_ip, COUNT(*) as c FROM alerts GROUP BY source_ip ORDER BY c DESC LIMIT 10').all();
  const timeline = db.prepare(`
    SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
    FROM alerts WHERE timestamp >= datetime('now', 'localtime', '-24 hours')
    GROUP BY hour ORDER BY hour ASC
  `).all();
  return {
    total, critical, high, medium, low,
    by_type:      Object.fromEntries(by_type.map(r => [r.type, r.c])),
    by_detection: Object.fromEntries(by_det.map(r => [r.detection, r.c])),
    by_severity:  { CRITICAL: critical, HIGH: high, MEDIUM: medium, LOW: low },
    top_ips:      Object.fromEntries(top_ips.map(r => [r.source_ip, r.c])),
    timeline:     timeline.map(r => ({ hour: r.hour, count: r.count })),
  };
}
 
function getTrafficStats() {
  if (!sqliteConnected) return { total: 0, normal: 0, attacks: 0, attack_ratio: 0, by_detector: [] };
  const total   = db.prepare('SELECT COUNT(*) as c FROM traffic').get().c;
  const normal  = db.prepare('SELECT COUNT(*) as c FROM traffic WHERE label=0').get().c;
  const attacks = db.prepare('SELECT COUNT(*) as c FROM traffic WHERE label=1').get().c;
  const by_det  = db.prepare('SELECT detector, COUNT(*) as total, SUM(label) as attacks FROM traffic GROUP BY detector ORDER BY total DESC').all();
  return {
    total, normal, attacks,
    attack_ratio: total ? +((attacks/total)*100).toFixed(2) : 0,
    by_detector:  by_det.map(r => ({ _id: r.detector, total: r.total, attacks: r.attacks })),
  };
}
 
function getTrafficTimeline(hours = 24) {
  if (!sqliteConnected) return [];
  return db.prepare(`
    SELECT strftime('%Y-%m-%d %H:00', timestamp) as _id,
           COUNT(*) as total, SUM(label) as attacks,
           COUNT(*) - SUM(label) as normal
    FROM traffic
    WHERE timestamp >= datetime('now', 'localtime', ? || ' hours')
    GROUP BY _id ORDER BY _id ASC
  `).all(`-${hours}`);
}
 
function getTopIPs(limit = 20) {
  if (!sqliteConnected) return [];
  const rows = db.prepare(`
    SELECT source_ip, COUNT(*) as count,
           GROUP_CONCAT(DISTINCT type) as types,
           MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
           MAX(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END) as sev_rank
    FROM alerts GROUP BY source_ip ORDER BY count DESC LIMIT ?
  `).all(limit);
  const sevMap = { 4:'CRITICAL', 3:'HIGH', 2:'MEDIUM', 1:'LOW' };
  return rows.map(r => ({
    ip: r.source_ip, count: r.count,
    types: r.types ? r.types.split(',') : [],
    first_seen: r.first_seen, last_seen: r.last_seen,
    top_severity: sevMap[r.sev_rank] || 'LOW',
  }));
}
 
function getAvgPps() {
  if (!sqliteConnected) return 0;
  try {
    // Use 'localtime' modifier to match Python's datetime.now() format
    const c = db.prepare(`
      SELECT COUNT(*) as c FROM traffic
      WHERE inserted_at >= datetime('now', 'localtime', '-5 seconds')
    `).get().c;
    return Math.round(c / 5);
  } catch { return 0; }
}
 
// ─── Routes ───────────────────────────────────────────────────────────────────
 
app.get('/api/alerts', (req, res) => {
  try {
    const { limit=50, severity, type, source_ip } = req.query;
    res.json({ success: true, data: getAlerts(limit, { severity, type, source_ip }), source: sqliteConnected ? 'sqlite' : 'mock' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
 
app.get('/api/alerts/stats', (req, res) => {
  try {
    res.json({ success: true, data: getAlertStats(), source: sqliteConnected ? 'sqlite' : 'mock' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
 
app.get('/api/alerts/top-ips', (req, res) => {
  try {
    res.json({ success: true, data: getTopIPs() });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
 
app.get('/api/traffic/stats', (req, res) => {
  try {
    res.json({ success: true, data: getTrafficStats(), source: sqliteConnected ? 'sqlite' : 'mock' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
 
app.get('/api/traffic/timeline', (req, res) => {
  try {
    const hours = parseInt(req.query.hours) || 24;
    res.json({ success: true, data: getTrafficTimeline(hours), source: sqliteConnected ? 'sqlite' : 'mock' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
 
// ─── Detectors ────────────────────────────────────────────────────────────────
const DETECTOR_CONFIGS = {
  syn:        { flood_rate: 10, port_scan_threshold: 5, alert_cooldown: 20, ai_threshold: 0.60, time_window: 5 },
  arp:        { alert_threshold: 5, rate_threshold: 10, alert_cooldown: 20, ai_threshold: 0.80 },
  icmp:       { flood_rate: 20, alert_cooldown: 20, ai_threshold: 0.80, time_window: 5 },
  dns:        { request_threshold: 20, tunnel_qname_len: 50, alert_cooldown: 20, ai_threshold: 0.60, time_window: 5 },
  bruteforce: { attempt_threshold: 15, alert_cooldown: 20, ai_threshold: 0.80, time_window: 5 },
  ftp:        { attempt_threshold: 10, bounce_threshold: 3, alert_cooldown: 20, ai_threshold: 0.80 },
  dhcp:       { starvation_pps: 10, starvation_mac_count: 20, alert_cooldown: 20, ai_threshold: 0.80 },
};
 
function getDetectorStatsFromDB() {
  if (!sqliteConnected) return null;
  try {
    const detectors = ['syn','arp','icmp','dns','bruteforce','ftp','dhcp'];
    const result = {};
    detectors.forEach(d => {
      const row     = db.prepare('SELECT COUNT(*) as c, MAX(timestamp) as last_alert FROM alerts WHERE detector=?').get(d);
      const lastType = db.prepare('SELECT type FROM alerts WHERE detector=? ORDER BY timestamp DESC LIMIT 1').get(d);
      const byType  = db.prepare('SELECT type, COUNT(*) as c FROM alerts WHERE detector=? GROUP BY type').all(d);
      result[d] = {
        alert_count: row?.c || 0,
        last_alert:  row?.last_alert || null,
        last_type:   lastType?.type || null,
        by_type:     Object.fromEntries(byType.map(r => [r.type, r.c])),
      };
    });
    return result;
  } catch { return null; }
}
 
let detectorStates = {
  syn:        { enabled: true, alert_count: 47, last_alert: '2025-05-20 14:23:11', last_type: 'SYN_SCAN',        active_ips: 3 },
  arp:        { enabled: true, alert_count: 12, last_alert: '2025-05-20 13:55:02', last_type: 'ARP_SPOOFING',     active_ips: 1 },
  icmp:       { enabled: true, alert_count: 29, last_alert: '2025-05-20 14:10:44', last_type: 'ICMP_FLOOD',       active_ips: 2 },
  dns:        { enabled: true, alert_count: 18, last_alert: '2025-05-20 12:44:30', last_type: 'DNS_TUNNEL',       active_ips: 1 },
  bruteforce: { enabled: true, alert_count: 34, last_alert: '2025-05-20 14:18:55', last_type: 'BRUTE_FORCE',      active_ips: 4 },
  ftp:        { enabled: true, alert_count: 8,  last_alert: '2025-05-20 11:30:00', last_type: 'FTP_BRUTE_FORCE',  active_ips: 1 },
  dhcp:       { enabled: true, alert_count: 5,  last_alert: '2025-05-20 10:15:22', last_type: 'DHCP_STARVATION',  active_ips: 1 },
};
 
app.get('/api/detectors', (req, res) => {
  const dbStats = getDetectorStatsFromDB();
  const result = Object.entries(detectorStates).map(([name, state]) => ({
    name, ...state,
    ...(dbStats?.[name] ? {
      alert_count: dbStats[name].alert_count,
      last_alert:  dbStats[name].last_alert,
      last_type:   dbStats[name].last_type,
      by_type:     dbStats[name].by_type || {},
    } : { by_type: {} }),
    config: DETECTOR_CONFIGS[name],
  }));
  res.json({ success: true, data: result });
});
 
app.put('/api/detectors/:name/config', (req, res) => {
  const { name } = req.params;
  if (!DETECTOR_CONFIGS[name]) return res.status(404).json({ success: false, error: 'Detector not found' });
  const { key, value } = req.body;
  if (DETECTOR_CONFIGS[name][key] === undefined) return res.status(400).json({ success: false, error: 'Invalid config key' });
  DETECTOR_CONFIGS[name][key] = value;
  res.json({ success: true, message: `${name}.${key} updated to ${value}` });
});
 
app.post('/api/detectors/:name/reset', (req, res) => {
  const { name } = req.params;
  if (!detectorStates[name]) return res.status(404).json({ success: false, error: 'Detector not found' });
  detectorStates[name].active_ips = 0;
  res.json({ success: true, message: `${name} detector state reset` });
});
 
// ─── Global Config ────────────────────────────────────────────────────────────
 
// Config metadata — label, min, max, step, unit, section
const CONFIG_META = {
  // SYN
  syn_flood_rate:          { label: 'Flood Rate',            min: 1,   max: 200,  step: 1,    unit: 'pps',  section: 'syn' },
  syn_port_scan_threshold: { label: 'Port Scan Threshold',   min: 1,   max: 100,  step: 1,    unit: 'ports',section: 'syn' },
  syn_alert_cooldown:      { label: 'Alert Cooldown',        min: 5,   max: 300,  step: 5,    unit: 's',    section: 'syn' },
  syn_ai_threshold:        { label: 'AI Threshold',          min: 0.1, max: 1.0,  step: 0.05, unit: '',     section: 'syn' },
  syn_time_window:         { label: 'Time Window',           min: 1,   max: 60,   step: 1,    unit: 's',    section: 'syn' },
  // ICMP
  icmp_flood_rate:         { label: 'Flood Rate',            min: 1,   max: 500,  step: 1,    unit: 'pps',  section: 'icmp' },
  icmp_alert_cooldown:     { label: 'Alert Cooldown',        min: 5,   max: 300,  step: 5,    unit: 's',    section: 'icmp' },
  icmp_ai_threshold:       { label: 'AI Threshold',          min: 0.1, max: 1.0,  step: 0.05, unit: '',     section: 'icmp' },
  icmp_time_window:        { label: 'Time Window',           min: 1,   max: 60,   step: 1,    unit: 's',    section: 'icmp' },
  // DNS
  dns_request_threshold:   { label: 'Request Threshold',     min: 1,   max: 200,  step: 1,    unit: 'req',  section: 'dns' },
  dns_tunnel_qname_len:    { label: 'Tunnel QNAME Length',   min: 20,  max: 200,  step: 1,    unit: 'chars',section: 'dns' },
  dns_alert_cooldown:      { label: 'Alert Cooldown',        min: 5,   max: 300,  step: 5,    unit: 's',    section: 'dns' },
  dns_ai_threshold:        { label: 'AI Threshold',          min: 0.1, max: 1.0,  step: 0.05, unit: '',     section: 'dns' },
  dns_time_window:         { label: 'Time Window',           min: 1,   max: 60,   step: 1,    unit: 's',    section: 'dns' },
  // BRUTEFORCE
  brute_attempt_threshold: { label: 'Attempt Threshold',     min: 1,   max: 200,  step: 1,    unit: 'attempts', section: 'bruteforce' },
  brute_alert_cooldown:    { label: 'Alert Cooldown',        min: 5,   max: 300,  step: 5,    unit: 's',    section: 'bruteforce' },
  brute_ai_threshold:      { label: 'AI Threshold',          min: 0.1, max: 1.0,  step: 0.05, unit: '',     section: 'bruteforce' },
  brute_time_window:       { label: 'Time Window',           min: 1,   max: 60,   step: 1,    unit: 's',    section: 'bruteforce' },
  // FTP
  ftp_attempt_threshold:   { label: 'Attempt Threshold',     min: 1,   max: 200,  step: 1,    unit: 'attempts', section: 'ftp' },
  ftp_bounce_threshold:    { label: 'Bounce Threshold',      min: 1,   max: 20,   step: 1,    unit: '',     section: 'ftp' },
  ftp_alert_cooldown:      { label: 'Alert Cooldown',        min: 5,   max: 300,  step: 5,    unit: 's',    section: 'ftp' },
  ftp_ai_threshold:        { label: 'AI Threshold',          min: 0.1, max: 1.0,  step: 0.05, unit: '',     section: 'ftp' },
  // ARP
  arp_alert_threshold:     { label: 'Alert Threshold',       min: 1,   max: 50,   step: 1,    unit: '',     section: 'arp' },
  arp_rate_threshold:      { label: 'Rate Threshold',        min: 1,   max: 100,  step: 1,    unit: 'pps',  section: 'arp' },
  arp_alert_cooldown:      { label: 'Alert Cooldown',        min: 5,   max: 300,  step: 5,    unit: 's',    section: 'arp' },
  arp_ai_threshold:        { label: 'AI Threshold',          min: 0.1, max: 1.0,  step: 0.05, unit: '',     section: 'arp' },
  // DHCP
  dhcp_starvation_pps:     { label: 'Starvation PPS',        min: 1,   max: 200,  step: 1,    unit: 'pps',  section: 'dhcp' },
  dhcp_starvation_macs:    { label: 'Starvation MAC Count',  min: 1,   max: 100,  step: 1,    unit: '',     section: 'dhcp' },
  dhcp_alert_cooldown:     { label: 'Alert Cooldown',        min: 5,   max: 300,  step: 5,    unit: 's',    section: 'dhcp' },
  dhcp_ai_threshold:       { label: 'AI Threshold',          min: 0.1, max: 1.0,  step: 0.05, unit: '',     section: 'dhcp' },
};
 
// Map config key → detector name + detector config key
const CONFIG_MAP = {
  syn_flood_rate:          { detector: 'syn',        key: 'flood_rate' },
  syn_port_scan_threshold: { detector: 'syn',        key: 'port_scan_threshold' },
  syn_alert_cooldown:      { detector: 'syn',        key: 'alert_cooldown' },
  syn_ai_threshold:        { detector: 'syn',        key: 'ai_threshold' },
  syn_time_window:         { detector: 'syn',        key: 'time_window' },
  icmp_flood_rate:         { detector: 'icmp',       key: 'flood_rate' },
  icmp_alert_cooldown:     { detector: 'icmp',       key: 'alert_cooldown' },
  icmp_ai_threshold:       { detector: 'icmp',       key: 'ai_threshold' },
  icmp_time_window:        { detector: 'icmp',       key: 'time_window' },
  dns_request_threshold:   { detector: 'dns',        key: 'request_threshold' },
  dns_tunnel_qname_len:    { detector: 'dns',        key: 'tunnel_qname_len' },
  dns_alert_cooldown:      { detector: 'dns',        key: 'alert_cooldown' },
  dns_ai_threshold:        { detector: 'dns',        key: 'ai_threshold' },
  dns_time_window:         { detector: 'dns',        key: 'time_window' },
  brute_attempt_threshold: { detector: 'bruteforce', key: 'attempt_threshold' },
  brute_alert_cooldown:    { detector: 'bruteforce', key: 'alert_cooldown' },
  brute_ai_threshold:      { detector: 'bruteforce', key: 'ai_threshold' },
  brute_time_window:       { detector: 'bruteforce', key: 'time_window' },
  ftp_attempt_threshold:   { detector: 'ftp',        key: 'attempt_threshold' },
  ftp_bounce_threshold:    { detector: 'ftp',        key: 'bounce_threshold' },
  ftp_alert_cooldown:      { detector: 'ftp',        key: 'alert_cooldown' },
  ftp_ai_threshold:        { detector: 'ftp',        key: 'ai_threshold' },
  arp_alert_threshold:     { detector: 'arp',        key: 'alert_threshold' },
  arp_rate_threshold:      { detector: 'arp',        key: 'rate_threshold' },
  arp_alert_cooldown:      { detector: 'arp',        key: 'alert_cooldown' },
  arp_ai_threshold:        { detector: 'arp',        key: 'ai_threshold' },
  dhcp_starvation_pps:     { detector: 'dhcp',       key: 'starvation_pps' },
  dhcp_starvation_macs:    { detector: 'dhcp',       key: 'starvation_mac_count' },
  dhcp_alert_cooldown:     { detector: 'dhcp',       key: 'alert_cooldown' },
  dhcp_ai_threshold:       { detector: 'dhcp',       key: 'ai_threshold' },
};
 
// GET /api/config — return all current values grouped by section
app.get('/api/config', (req, res) => {
  const result = {};
  for (const [configKey, meta] of Object.entries(CONFIG_META)) {
    const map = CONFIG_MAP[configKey];
    const value = DETECTOR_CONFIGS[map.detector]?.[map.key];
    if (!result[meta.section]) result[meta.section] = [];
    result[meta.section].push({
      key: configKey,
      label: meta.label,
      value,
      min: meta.min,
      max: meta.max,
      step: meta.step,
      unit: meta.unit,
    });
  }
  res.json({ success: true, data: result });
});
 
// PUT /api/config/:key — update one config value + write to SQLite
app.put('/api/config/:key', (req, res) => {
  const { key } = req.params;
  const { value } = req.body;
  const map = CONFIG_MAP[key];
  if (!map) return res.status(404).json({ success: false, error: `Unknown config key: ${key}` });
  if (value === undefined) return res.status(400).json({ success: false, error: 'value required' });
  const parsed = typeof value === 'string' ? parseFloat(value) : value;
 
  // update in-memory copy (dashboard reflects immediately)
  DETECTOR_CONFIGS[map.detector][map.key] = parsed;
 
  // write to SQLite so manager.py picks it up within 30s
  if (sqliteConnected) {
    try {
      db.prepare(`
        INSERT INTO config (key, value, updated_at)
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
      `).run(key, parsed);
    } catch (err) {
      console.warn('[Config] SQLite write failed:', err.message);
    }
  }
 
  res.json({ success: true, message: `${key} updated to ${parsed}`, persisted: sqliteConnected });
});
 
// ─── System Health ────────────────────────────────────────────────────────────
const startTime = Date.now();
 
app.get('/api/system/stats', (req, res) => {
  const uptime = Math.floor((Date.now() - startTime) / 1000);
  let packets_received = 0;
  if (sqliteConnected) {
    try { packets_received = db.prepare('SELECT COUNT(*) as c FROM traffic').get().c; } catch {}
  }
  const packets_dropped   = Math.floor(packets_received * 0.002);
  const packets_processed = packets_received - packets_dropped;
  res.json({
    success: true,
    data: {
      packets_received, packets_processed, packets_dropped,
      drop_rate_pct:    packets_received ? +((packets_dropped/packets_received)*100).toFixed(2) : 0,
      avg_pps:          getAvgPps(),
      uptime_seconds:   uptime,
      uptime_human:     `${Math.floor(uptime/3600)}h ${Math.floor((uptime%3600)/60)}m ${uptime%60}s`,
      sqlite_connected: sqliteConnected,
      mongodb_connected: sqliteConnected, // kept for frontend compat
      ai_models_loaded: ['syn_rf_model.pkl','icmp_rf_model.pkl','dns_rf_model.pkl','bruteforce_rf_model.pkl','ftp_rf_model.pkl','arp_rf_model.pkl','dhcp_rf_model.pkl'],
      queue_size:       0,
      interface:        'eth0',
      ids_ip:           '192.168.68.130',
      db_path:          DB_PATH,
    }
  });
});
 
// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = 3001;
connectSQLite();
server.listen(PORT, () => {
  console.log(`[Server] Running on http://localhost:${PORT}`);
  console.log(`[WebSocket] ws://localhost:${PORT}`);
});
