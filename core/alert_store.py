"""
core/alert_store.py — Alert & Traffic Storage (SQLite)
=======================================================
THREE tables :
 
    alerts   → label=1 seulement
    traffic  → label=0 + label=1
    config   → thresholds live (écrit par dashboard, lu par manager.py)
"""
 
import sqlite3
import json
import os
import threading
from datetime import datetime
from config import SQLITE_DB_PATH
 
 
class AlertStore:
 
    def __init__(self):
        self._db_path = SQLITE_DB_PATH
        self._lock    = threading.Lock()
        self._enabled = False
        self._connect()
 
    def _connect(self):
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            conn = sqlite3.connect(self._db_path)
            self._create_tables(conn)
            conn.close()
            self._enabled = True
            print(f"   SQLite     : connected ✅ ({self._db_path})")
        except Exception as e:
            print(f"   SQLite     : unavailable — {e}")
            self._enabled = False
 
    def _get_conn(self):
        return sqlite3.connect(self._db_path, check_same_thread=False)
 
    def _create_tables(self, conn):
        cursor = conn.cursor()
 
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT,
                type          TEXT,
                source_ip     TEXT,
                target_ip     TEXT,
                severity      TEXT,
                detection     TEXT,
                detector      TEXT,
                label         INTEGER DEFAULT 1,
                ai_confidence REAL,
                extra_json    TEXT,
                inserted_at   TEXT
            )
        """)
 
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT,
                detector    TEXT,
                source_ip   TEXT,
                target_ip   TEXT,
                label       INTEGER DEFAULT 0,
                pps         REAL,
                duration    REAL,
                extra_json  TEXT,
                inserted_at TEXT
            )
        """)
 
        # ← NEW : config table for live threshold updates
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key        TEXT PRIMARY KEY,
                value      REAL NOT NULL,
                updated_at TEXT
            )
        """)
 
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type       ON alerts(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip  ON alerts(source_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_detector   ON alerts(detector)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_source_ip ON traffic(source_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_detector  ON traffic(detector)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_label     ON traffic(label)")
 
        conn.commit()
 
    # =========================
    # ALERTS
    # =========================
    def insert(self, alert: dict):
        if not self._enabled:
            return
        try:
            known = {"timestamp", "type", "source_ip", "target_ip",
                     "severity", "detection", "detector", "label", "ai_confidence"}
            extra = {k: v for k, v in alert.items() if k not in known}
            with self._lock:
                conn = self._get_conn()
                conn.execute("""
                    INSERT INTO alerts
                    (timestamp, type, source_ip, target_ip, severity,
                     detection, detector, label, ai_confidence, extra_json, inserted_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.get("timestamp", str(datetime.now())),
                    alert.get("type", ""),
                    alert.get("source_ip", ""),
                    alert.get("target_ip", ""),
                    alert.get("severity", ""),
                    alert.get("detection", "RULE"),
                    alert.get("detector", ""),
                    alert.get("label", 1),
                    alert.get("ai_confidence", 0.0),
                    json.dumps(extra, default=str),
                    str(datetime.now())
                ))
                conn.commit()
                conn.close()
 
            # auto-insert label=1 in traffic so charts show real attack ratio
            self.insert_traffic({
                "timestamp" : alert.get("timestamp", str(datetime.now())),
                "detector"  : alert.get("detector", ""),
                "source_ip" : alert.get("source_ip", ""),
                "target_ip" : alert.get("target_ip", ""),
                "label"     : 1,
                "pps"       : alert.get("pps", 0.0),
                "duration"  : alert.get("duration", 0.0),
            })
        except Exception:
            pass
 
    # =========================
    # TRAFFIC
    # =========================
    def insert_traffic(self, doc: dict):
        if not self._enabled:
            return
        try:
            known = {"timestamp", "detector", "source_ip", "target_ip",
                     "label", "pps", "duration"}
            extra = {k: v for k, v in doc.items() if k not in known}
            with self._lock:
                conn = self._get_conn()
                conn.execute("""
                    INSERT INTO traffic
                    (timestamp, detector, source_ip, target_ip,
                     label, pps, duration, extra_json, inserted_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    doc.get("timestamp", str(datetime.now())),
                    doc.get("detector", ""),
                    doc.get("source_ip", ""),
                    doc.get("target_ip", ""),
                    doc.get("label", 0),
                    doc.get("pps", 0.0),
                    doc.get("duration", 0.0),
                    json.dumps(extra, default=str),
                    str(datetime.now())
                ))
                conn.commit()
                conn.close()
        except Exception:
            pass
 
    # =========================
    # CONFIG — live thresholds
    # =========================
    def write_config(self, key: str, value: float):
        """Dashboard writes here when user changes a threshold."""
        if not self._enabled:
            return
        try:
            with self._lock:
                conn = self._get_conn()
                conn.execute("""
                    INSERT INTO config (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE
                    SET value=excluded.value, updated_at=excluded.updated_at
                """, (key, value, str(datetime.now())))
                conn.commit()
                conn.close()
        except Exception:
            pass
 
    def read_config(self) -> dict:
        """manager.py reads this every 30s to apply changes to detectors."""
        if not self._enabled:
            return {}
        try:
            with self._lock:
                conn = self._get_conn()
                rows = conn.execute("SELECT key, value FROM config").fetchall()
                conn.close()
            return {r[0]: r[1] for r in rows}
        except Exception:
            return {}
 
    # =========================
    # DASHBOARD QUERIES — alerts
    # =========================
    def get_recent_alerts(self, limit: int = 50, severity: str = None) -> list:
        if not self._enabled:
            return []
        try:
            with self._lock:
                conn = self._get_conn()
                if severity:
                    rows = conn.execute(
                        "SELECT * FROM alerts WHERE severity=? ORDER BY timestamp DESC LIMIT ?",
                        (severity, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
                    ).fetchall()
                cols = [d[0] for d in conn.execute("SELECT * FROM alerts LIMIT 0").description]
                conn.close()
            result = []
            for row in rows:
                d = dict(zip(cols, row))
                if d.get("extra_json"):
                    d.update(json.loads(d.pop("extra_json")))
                result.append(d)
            return result
        except Exception:
            return []
 
    def get_alert_stats(self) -> dict:
        if not self._enabled:
            return {}
        try:
            with self._lock:
                conn = self._get_conn()
                total    = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                critical = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
                high     = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0]
                medium   = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'").fetchone()[0]
                low      = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='LOW'").fetchone()[0]
                by_type  = conn.execute(
                    "SELECT type, COUNT(*) as c FROM alerts GROUP BY type ORDER BY c DESC LIMIT 10"
                ).fetchall()
                by_det   = conn.execute(
                    "SELECT detection, COUNT(*) as c FROM alerts GROUP BY detection"
                ).fetchall()
                top_ips  = conn.execute(
                    "SELECT source_ip, COUNT(*) as c FROM alerts GROUP BY source_ip ORDER BY c DESC LIMIT 10"
                ).fetchall()
                conn.close()
            return {
                "total"       : total,
                "critical"    : critical,
                "high"        : high,
                "medium"      : medium,
                "low"         : low,
                "by_type"     : {r[0]: r[1] for r in by_type},
                "by_detection": {r[0]: r[1] for r in by_det},
                "top_ips"     : {r[0]: r[1] for r in top_ips},
            }
        except Exception:
            return {}
 
    # =========================
    # DASHBOARD QUERIES — traffic
    # =========================
    def get_traffic_stats(self) -> dict:
        if not self._enabled:
            return {}
        try:
            with self._lock:
                conn = self._get_conn()
                total   = conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
                normal  = conn.execute("SELECT COUNT(*) FROM traffic WHERE label=0").fetchone()[0]
                attacks = conn.execute("SELECT COUNT(*) FROM traffic WHERE label=1").fetchone()[0]
                by_det  = conn.execute(
                    "SELECT detector, COUNT(*) as c FROM traffic GROUP BY detector ORDER BY c DESC"
                ).fetchall()
                conn.close()
            return {
                "total"       : total,
                "normal"      : normal,
                "attacks"     : attacks,
                "attack_ratio": round(attacks / max(total, 1) * 100, 2),
                "by_detector" : {r[0]: r[1] for r in by_det},
            }
        except Exception:
            return {}
 
    def get_traffic_timeline(self, hours: int = 24) -> list:
        if not self._enabled:
            return []
        try:
            with self._lock:
                conn = self._get_conn()
                rows = conn.execute("""
                    SELECT
                        strftime('%Y-%m-%d %H:00', timestamp) as hour,
                        COUNT(*) as total,
                        SUM(label) as attacks,
                        COUNT(*) - SUM(label) as normal
                    FROM traffic
                    WHERE timestamp >= datetime('now', ? || ' hours')
                    GROUP BY hour
                    ORDER BY hour DESC
                """, (f"-{hours}",)).fetchall()
                conn.close()
            return [
                {"hour": r[0], "total": r[1], "attacks": r[2], "normal": r[3]}
                for r in rows
            ]
        except Exception:
            return []
 
    def get_ip_history(self, ip: str, limit: int = 100) -> list:
        if not self._enabled:
            return []
        try:
            with self._lock:
                conn = self._get_conn()
                rows = conn.execute(
                    "SELECT * FROM traffic WHERE source_ip=? ORDER BY timestamp DESC LIMIT ?",
                    (ip, limit)
                ).fetchall()
                cols = [d[0] for d in conn.execute("SELECT * FROM traffic LIMIT 0").description]
                conn.close()
            result = []
            for row in rows:
                d = dict(zip(cols, row))
                if d.get("extra_json"):
                    d.update(json.loads(d.pop("extra_json")))
                result.append(d)
            return result
        except Exception:
            return []
 
    # =========================
    # UTILS
    # =========================
    @property
    def is_connected(self) -> bool:
        return self._enabled
 
    def get_stats(self) -> dict:
        return {
            "alerts" : self.get_alert_stats(),
            "traffic": self.get_traffic_stats(),
        }
 
 
# =========================
# SINGLETON
# =========================
alert_store = AlertStore.__new__(AlertStore)
alert_store._db_path = None
alert_store._lock    = threading.Lock()
alert_store._enabled = False

