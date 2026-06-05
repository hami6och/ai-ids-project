import { useState, useEffect, useCallback, useRef } from 'react';
import { API_BASE, WS_URL } from '../lib/constants.js';

async function apiFetch(path) {
  const res = await fetch(`${API_BASE}${path}`);
  const json = await res.json();
  if (!json.success) throw new Error(json.error || 'API error');
  return json.data;
}

export function useAlerts(filters = {}, limit = 100) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAlerts = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit, ...filters });
      Object.keys(params).forEach(k => !params.get(k) && params.delete(k));
      const data = await apiFetch(`/api/alerts?${params}`);
      setAlerts(data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [JSON.stringify(filters), limit]);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);
  return { alerts, loading, refetch: fetchAlerts };
}

export function useStats() {
  const [stats, setStats]     = useState(null);
  const [traffic, setTraffic] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    const fetch_ = async () => {
      try {
        const [alertData, trafficData, timelineData] = await Promise.all([
          apiFetch('/api/alerts/stats'),
          apiFetch('/api/traffic/stats'),
          apiFetch('/api/traffic/timeline?hours=24'),
        ]);
        if (alive) {
          setStats(alertData);
          setTraffic({ ...trafficData, timeline: timelineData });
        }
      } catch (e) { console.error(e); }
      finally { if (alive) setLoading(false); }
    };
    fetch_();
    const iv = setInterval(fetch_, 15000);
    return () => { alive = false; clearInterval(iv); };
  }, []);

  return { stats, traffic, loading };
}

export function useDetectors() {
  const [detectors, setDetectors] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchDetectors = useCallback(async () => {
    try {
      const data = await apiFetch('/api/detectors');
      setDetectors(data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchDetectors(); }, [fetchDetectors]);

  const updateConfig = async (name, key, value) => {
    await fetch(`${API_BASE}/api/detectors/${name}/config`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, value }),
    });
    fetchDetectors();
  };

  const resetDetector = async (name) => {
    await fetch(`${API_BASE}/api/detectors/${name}/reset`, { method: 'POST' });
    fetchDetectors();
  };

  return { detectors, loading, updateConfig, resetDetector };
}

export function useTopIPs() {
  const [ips, setIPs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch('/api/alerts/top-ips')
      .then(data => setIPs(data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return { ips, loading };
}

export function useSystemStats() {
  const [sys, setSys] = useState(null);

  useEffect(() => {
    let alive = true;
    const fetch_ = async () => {
      try {
        const data = await apiFetch('/api/system/stats');
        if (alive) setSys(data);
      } catch (e) { console.error(e); }
    };
    fetch_();
    const iv = setInterval(fetch_, 2000);
    return () => { alive = false; clearInterval(iv); };
  }, []);

  return sys;
}

export function useLiveAlerts(onAlert) {
  const wsRef = useRef(null);
  const cbRef = useRef(onAlert);
  cbRef.current = onAlert;

  useEffect(() => {
    let reconnectTimeout;

    const connect = () => {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.event === 'new_alert') cbRef.current(msg.data);
        } catch {}
      };

      ws.onclose = () => {
        reconnectTimeout = setTimeout(connect, 3000);
      };
    };

    connect();
    return () => {
      clearTimeout(reconnectTimeout);
      wsRef.current?.close();
    };
  }, []);
}
