"""
core/alert_store.py — Alert Storage
=====================================
Writes alerts to MongoDB for the dashboard AND to JSONL for ML training.
If MongoDB is unavailable, falls back gracefully — IDS keeps running.

Usage in detectors :
    # injected by manager.py into every detector instance
    self.alert_store.insert(alert)

Dashboard API (Node.js) connects to the same MongoDB instance and queries :
    db.alerts.find().sort({timestamp:-1}).limit(50)
    db.alerts.watch()   ← live change stream for WebSocket feed
"""

from datetime import datetime
from config import (
    MONGODB_ENABLED, MONGODB_URI,
    MONGODB_DB, MONGODB_COLLECTION
)


class AlertStore:
    """
    Thin abstraction over MongoDB alerts collection.
    Injected into every detector instance by manager.py.
    Falls back gracefully if MongoDB is not available.
    """

    def __init__(self):
        self._collection = None
        self._enabled    = False
        self._connect()

    def _connect(self):
        if not MONGODB_ENABLED:
            print("   MongoDB    : disabled (MONGODB_ENABLED=False in config.py)")
            return
        try:
            from pymongo import MongoClient
            client           = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
            client.server_info()                        # test connection
            db               = client[MONGODB_DB]
            self._collection = db[MONGODB_COLLECTION]

            # indexes for fast dashboard queries
            self._collection.create_index("timestamp")
            self._collection.create_index("type")
            self._collection.create_index("severity")
            self._collection.create_index("source_ip")

            self._enabled = True
            print(f"   MongoDB    : connected ✅ ({MONGODB_URI}/{MONGODB_DB})")

        except Exception as e:
            print(f"   MongoDB    : unavailable — {e}")
            print(f"               (alerts stored in JSONL only)")
            self._enabled = False

    def insert(self, alert: dict):
        """
        Insert one alert into MongoDB.
        Called by every detector when an alert fires.
        Safe to call even if MongoDB is down — silently skips.
        """
        if not self._enabled or self._collection is None:
            return
        try:
            doc = {**alert, "inserted_at": str(datetime.now())}
            self._collection.insert_one(doc)
        except Exception:
            pass    # never crash the IDS for a DB write failure

    def get_recent(self, limit: int = 50) -> list:
        """Return most recent alerts — used by dashboard REST endpoint."""
        if not self._enabled:
            return []
        try:
            cursor = self._collection.find(
                {},
                {"_id": 0}
            ).sort("timestamp", -1).limit(limit)
            return list(cursor)
        except Exception:
            return []

    def get_stats(self) -> dict:
        """
        Return alert statistics for dashboard overview panel.
        """
        if not self._enabled:
            return {}
        try:
            total     = self._collection.count_documents({})
            critical  = self._collection.count_documents({"severity": "CRITICAL"})
            high      = self._collection.count_documents({"severity": "HIGH"})
            by_type   = self._collection.aggregate([
                {"$group": {"_id": "$type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ])
            return {
                "total"    : total,
                "critical" : critical,
                "high"     : high,
                "by_type"  : {r["_id"]: r["count"] for r in by_type}
            }
        except Exception:
            return {}

    @property
    def is_connected(self) -> bool:
        return self._enabled


# =========================
# SINGLETON — injected into detectors by manager.py
# =========================
alert_store = AlertStore.__new__(AlertStore)
alert_store._collection = None
alert_store._enabled    = False