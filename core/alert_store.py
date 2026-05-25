"""
core/alert_store.py — Alert & Traffic Storage
===============================================
Writes to TWO MongoDB collections :

    ai_ids.alerts   → label=1 only (every alert fired)
                       used for : alert feed, alert stats, severity counts

    ai_ids.traffic  → label=0 + label=1 (every packet processed)
                       used for : traffic charts, normal vs attack ratio,
                                  per-IP history, live traffic visualization

If MongoDB is unavailable, falls back gracefully — IDS keeps running,
everything still goes to JSONL files.

Usage in detectors :
    # on every packet processed (normal or attack)
    self.alert_store.insert_traffic(traffic_doc)

    # only when an alert fires
    self.alert_store.insert(alert_doc)
"""

from datetime import datetime
from config import (
    MONGODB_ENABLED, MONGODB_URI,
    MONGODB_DB, MONGODB_COLLECTION
)

TRAFFIC_COLLECTION = "traffic"


class AlertStore:
    """
    Thin abstraction over MongoDB.
    Two collections : alerts (label=1) and traffic (all packets).
    Injected into every detector instance by manager.py.
    Falls back gracefully if MongoDB is not available.
    """

    def __init__(self):
        self._alerts_col  = None
        self._traffic_col = None
        self._enabled     = False
        self._connect()

    def _connect(self):
        if not MONGODB_ENABLED:
            print("   MongoDB    : disabled (MONGODB_ENABLED=False in config.py)")
            return
        try:
            from pymongo import MongoClient, DESCENDING
            client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
            client.server_info()
            db = client[MONGODB_DB]

            # alerts collection — label=1 only
            self._alerts_col = db[MONGODB_COLLECTION]
            self._alerts_col.create_index("timestamp")
            self._alerts_col.create_index("type")
            self._alerts_col.create_index("severity")
            self._alerts_col.create_index("source_ip")
            self._alerts_col.create_index([("timestamp", DESCENDING)])

            # traffic collection — all packets
            self._traffic_col = db[TRAFFIC_COLLECTION]
            self._traffic_col.create_index("timestamp")
            self._traffic_col.create_index("source_ip")
            self._traffic_col.create_index("detector")
            self._traffic_col.create_index("label")
            self._traffic_col.create_index([("timestamp", DESCENDING)])

            self._enabled = True
            print(f"   MongoDB    : connected ✅ ({MONGODB_URI}/{MONGODB_DB})")
            print(f"                collections: {MONGODB_COLLECTION} (alerts) | {TRAFFIC_COLLECTION} (traffic)")

        except Exception as e:
            print(f"   MongoDB    : unavailable — {e}")
            print(f"                (data stored in JSONL only)")
            self._enabled = False

    # =========================
    # ALERTS — label=1 only
    # =========================
    def insert(self, alert: dict):
        """
        Insert one alert into alerts collection.
        Called by every detector when an alert fires.
        """
        if not self._enabled or self._alerts_col is None:
            return
        try:
            doc = {**alert, "inserted_at": str(datetime.now())}
            self._alerts_col.insert_one(doc)
        except Exception:
            pass

    # =========================
    # TRAFFIC — every packet
    # =========================
    def insert_traffic(self, traffic_doc: dict):
        """
        Insert one traffic record into traffic collection.
        Called by every detector on every packet processed (normal or attack).
        label=0 → normal traffic
        label=1 → attack traffic (also in alerts collection)
        """
        if not self._enabled or self._traffic_col is None:
            return
        try:
            doc = {**traffic_doc, "inserted_at": str(datetime.now())}
            self._traffic_col.insert_one(doc)
        except Exception:
            pass

    # =========================
    # DASHBOARD QUERIES — alerts
    # =========================
    def get_recent_alerts(self, limit: int = 50, severity: str = None) -> list:
        """Return most recent alerts — dashboard alert feed."""
        if not self._enabled:
            return []
        try:
            query  = {"severity": severity} if severity else {}
            cursor = self._alerts_col.find(
                query, {"_id": 0}
            ).sort("timestamp", -1).limit(limit)
            return list(cursor)
        except Exception:
            return []

    def get_alert_stats(self) -> dict:
        """Alert statistics for dashboard overview panel."""
        if not self._enabled:
            return {}
        try:
            total    = self._alerts_col.count_documents({})
            critical = self._alerts_col.count_documents({"severity": "CRITICAL"})
            high     = self._alerts_col.count_documents({"severity": "HIGH"})
            medium   = self._alerts_col.count_documents({"severity": "MEDIUM"})
            low      = self._alerts_col.count_documents({"severity": "LOW"})
            by_type  = self._alerts_col.aggregate([
                {"$group": {"_id": "$type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ])
            by_detection = self._alerts_col.aggregate([
                {"$group": {"_id": "$detection", "count": {"$sum": 1}}}
            ])
            top_ips = self._alerts_col.aggregate([
                {"$group": {"_id": "$source_ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ])
            return {
                "total"       : total,
                "critical"    : critical,
                "high"        : high,
                "medium"      : medium,
                "low"         : low,
                "by_type"     : {r["_id"]: r["count"] for r in by_type},
                "by_detection": {r["_id"]: r["count"] for r in by_detection},
                "top_ips"     : {r["_id"]: r["count"] for r in top_ips},
            }
        except Exception:
            return {}

    # =========================
    # DASHBOARD QUERIES — traffic
    # =========================
    def get_traffic_stats(self) -> dict:
        """Traffic statistics — normal vs attack ratio."""
        if not self._enabled:
            return {}
        try:
            total   = self._traffic_col.count_documents({})
            normal  = self._traffic_col.count_documents({"label": 0})
            attacks = self._traffic_col.count_documents({"label": 1})
            by_detector = self._traffic_col.aggregate([
                {"$group": {"_id": "$detector", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ])
            return {
                "total"       : total,
                "normal"      : normal,
                "attacks"     : attacks,
                "attack_ratio": round(attacks / max(total, 1) * 100, 2),
                "by_detector" : {r["_id"]: r["count"] for r in by_detector},
            }
        except Exception:
            return {}

    def get_recent_traffic(self, limit: int = 100, detector: str = None,
                           label: int = None) -> list:
        """Return recent traffic records — dashboard live traffic view."""
        if not self._enabled:
            return []
        try:
            query = {}
            if detector is not None:
                query["detector"] = detector
            if label is not None:
                query["label"] = label
            cursor = self._traffic_col.find(
                query, {"_id": 0}
            ).sort("timestamp", -1).limit(limit)
            return list(cursor)
        except Exception:
            return []

    def get_ip_history(self, ip: str, limit: int = 100) -> list:
        """Return all traffic records for a specific IP — per-IP drill down."""
        if not self._enabled:
            return []
        try:
            cursor = self._traffic_col.find(
                {"source_ip": ip}, {"_id": 0}
            ).sort("timestamp", -1).limit(limit)
            return list(cursor)
        except Exception:
            return []

    def get_traffic_timeline(self, hours: int = 24) -> list:
        """Traffic per hour over last N hours — timeline chart."""
        if not self._enabled:
            return []
        try:
            from datetime import timedelta
            pipeline = [
                {"$addFields": {
                    "hour": {"$dateToString": {
                        "format": "%Y-%m-%d %H:00",
                        "date": {"$toDate": "$timestamp"}
                    }}
                }},
                {"$group": {
                    "_id"    : "$hour",
                    "total"  : {"$sum": 1},
                    "attacks": {"$sum": "$label"},
                    "normal" : {"$sum": {"$subtract": [1, "$label"]}}
                }},
                {"$sort": {"_id": -1}},
                {"$limit": hours}
            ]
            return list(self._traffic_col.aggregate(pipeline))
        except Exception:
            return []

    # =========================
    # UTILS
    # =========================
    @property
    def is_connected(self) -> bool:
        return self._enabled

    def get_stats(self) -> dict:
        """Combined stats — backward compatible."""
        return {
            "alerts" : self.get_alert_stats(),
            "traffic": self.get_traffic_stats(),
        }


# =========================
# SINGLETON — initialized by manager.py
# =========================
alert_store = AlertStore.__new__(AlertStore)
alert_store._alerts_col  = None
alert_store._traffic_col = None
alert_store._enabled     = False