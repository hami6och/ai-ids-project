"""
core/threat_feed.py — Threat Intelligence Feed
================================================
Queries AbuseIPDB to enrich alerts with global threat intelligence.
Runs asynchronously so it never slows down packet processing.

How it works :
    After any alert fires, manager.py calls threat_feed.check(ip).
    The result is cached for 1 hour so repeated alerts on the same IP
    don't hammer the API.
    Private/local IPs are skipped automatically.

Setup :
    1. Register free at https://www.abuseipdb.com
    2. Get your API key from Account > API
    3. Set ABUSEIPDB_API_KEY in config.py
    4. Set THREAT_FEED_ENABLED = True in config.py

API limits :
    Free tier : 1000 queries/day
    With caching : one query per unique IP per hour
    In practice : well within limits for a lab IDS

Usage in manager.py :
    from core.threat_feed import threat_feed
    threat_feed.check_async(src_ip)
"""

import time
import threading
import ipaddress
from datetime import datetime

# =========================
# CACHE CONFIG
# =========================
CACHE_TTL = 3600    # cache results for 1 hour
MIN_SCORE = 25      # only print enrichment if score >= this (skip clean IPs)


def is_private(ip: str) -> bool:
    """Skip private/local IPs — AbuseIPDB only knows public IPs."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


class ThreatFeed:
    """
    AbuseIPDB client with caching and async lookup.
    Singleton — import and use threat_feed directly.
    """

    def __init__(self):
        self._api_key   = None
        self._enabled   = False
        self._cache     = {}        # ip → (timestamp, result_dict)
        self._lock      = threading.Lock()
        self._logger    = None

    def configure(self, api_key: str, enabled: bool = True):
        """Call this from manager.py at startup."""
        self._api_key = api_key
        self._enabled = enabled and bool(api_key)
        if self._enabled:
            print(f"🌍 Threat feed : AbuseIPDB enabled")
        else:
            print(f"🌍 Threat feed : disabled (set ABUSEIPDB_API_KEY in config.py)")

    def set_logger(self, logger):
        self._logger = logger

    def check_async(self, ip: str, alert_type: str = "", severity: str = ""):
        """
        Non-blocking check — runs in background thread.
        Call this right after an alert fires.
        """
        if not self._enabled or is_private(ip):
            return
        thread = threading.Thread(
            target=self._check_and_print,
            args=(ip, alert_type, severity),
            daemon=True
        )
        thread.start()

    def _check_and_print(self, ip: str, alert_type: str, severity: str):
        result = self._query(ip)
        if not result:
            return

        score   = result.get("abuseConfidenceScore", 0)
        reports = result.get("totalReports", 0)
        country = result.get("countryCode", "??")
        domain  = result.get("domain", "unknown")

        if score < MIN_SCORE:
            return   # clean IP — don't clutter terminal

        # enrich print
        print(f"   🌍 [THREAT FEED] {ip} — score: {score}% | "
              f"reports: {reports} | country: {country} | domain: {domain}")

        if self._logger:
            self._logger.log({
                "timestamp"  : str(datetime.now()),
                "type"       : "THREAT_FEED_HIT",
                "ip"         : ip,
                "alert_type" : alert_type,
                "score"      : score,
                "reports"    : reports,
                "country"    : country,
                "domain"     : domain,
            })

    def _query(self, ip: str) -> dict | None:
        """Query AbuseIPDB with caching."""
        now = time.time()

        # check cache
        with self._lock:
            if ip in self._cache:
                ts, result = self._cache[ip]
                if now - ts < CACHE_TTL:
                    return result

        # query API
        try:
            import urllib.request
            import json

            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(url)
            req.add_header("Key", self._api_key)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=5) as resp:
                data  = json.loads(resp.read().decode())
                result = data.get("data", {})

            with self._lock:
                self._cache[ip] = (now, result)

            return result

        except Exception:
            # never crash the IDS for a threat feed failure
            return None

    def get_cache_stats(self) -> dict:
        """Return cache stats for dashboard."""
        now = time.time()
        with self._lock:
            total  = len(self._cache)
            fresh  = sum(1 for ts, _ in self._cache.values() if now - ts < CACHE_TTL)
        return {"cached_ips": total, "fresh_entries": fresh}


# =========================
# SINGLETON
# =========================
threat_feed = ThreatFeed()