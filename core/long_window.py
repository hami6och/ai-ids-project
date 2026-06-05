"""
core/long_window.py — Long-Term Attack Tracker
================================================
Tracks per-IP activity over a long window (default 600s = 10 min)
to catch slow/patient attackers who stay below short-window thresholds.

Each detector that has a slow-attack variant imports a tracker instance
and calls tracker.add() on every relevant packet.

Usage :
    from core.long_window import lw_syn, lw_brute, lw_dns

    # in detect(), on every packet:
    lw_syn.add(ip_src, value=dport, now=now)

    # check after short-window misses:
    if lw_syn.should_alert(ip_src, now):
        # slow attack detected
"""

import time
from collections import defaultdict, deque
from datetime import datetime


class LongWindowTracker:
    """
    Tracks a set of values per source IP over a long time window.
    Fires when unique value count exceeds threshold.

    value_type examples :
        "port"    → unique destination ports (SYN scan)
        "attempt" → connection attempts (brute force)
        "request" → DNS requests (DNS flood)
    """

    def __init__(self,
                 window_sec: int   = 600,
                 threshold: int    = 15,
                 cooldown: int     = 600,
                 value_type: str   = "event",
                 alert_name: str   = "SLOW_ATTACK"):

        self.window_sec = window_sec
        self.threshold  = threshold
        self.cooldown   = cooldown
        self.value_type = value_type
        self.alert_name = alert_name

        # ip → deque of (timestamp, value)
        self._data       = defaultdict(deque)
        self._last_alert = {}    # ip → last alert timestamp

    def add(self, ip: str, value, now: float = None):
        """Record one event for this IP."""
        now = now or time.time()
        self._data[ip].append((now, value))
        # evict old entries
        dq = self._data[ip]
        while dq and now - dq[0][0] > self.window_sec:
            dq.popleft()

    def should_alert(self, ip: str, now: float = None) -> bool:
        """
        Returns True if this IP has crossed the long-window threshold
        and cooldown has elapsed since last alert.
        """
        now    = now or time.time()
        dq     = self._data.get(ip)
        if not dq:
            return False

        unique = len({v for _, v in dq})
        if unique < self.threshold:
            return False

        last = self._last_alert.get(ip, 0)
        if now - last < self.cooldown:
            return False

        self._last_alert[ip] = now
        return True

    def get_summary(self, ip: str) -> dict:
        """Return summary of long-window activity for alert context."""
        dq = self._data.get(ip, deque())
        if not dq:
            return {}

        values    = [v for _, v in dq]
        times     = [t for t, _ in dq]
        unique    = len(set(values))
        timespan  = round(times[-1] - times[0], 1) if len(times) > 1 else 0

        return {
            "long_window_sec"     : self.window_sec,
            "long_window_events"  : len(dq),
            f"unique_{self.value_type}s" : unique,
            "timespan_sec"        : timespan,
            "alert_name"          : self.alert_name,
        }

    def clear(self, ip: str):
        """Clear state for an IP after alert fires."""
        self._data.pop(ip, None)


# =========================
# TRACKER INSTANCES
# One per detector that needs long-window detection
# =========================

# SYN slow scan — unique destination ports over 10 minutes
lw_syn   = LongWindowTracker(
    window_sec = 600,
    threshold  = 10,     # 10 unique ports in 10 min → slow scan
    cooldown   = 600,
    value_type = "port",
    alert_name = "SLOW_SYN_SCAN"
)

# Brute force — connection attempts over 10 minutes
lw_brute = LongWindowTracker(
    window_sec = 600,
    threshold  = 20,     # 20 attempts in 10 min → slow brute force
    cooldown   = 600,
    value_type = "attempt",
    alert_name = "SLOW_BRUTE_FORCE"
)

# DNS flood — requests over 5 minutes
lw_dns   = LongWindowTracker(
    window_sec = 300,
    threshold  = 40,     # 40 requests in 5 min → slow DNS flood
    cooldown   = 300,
    value_type = "request",
    alert_name = "SLOW_DNS_FLOOD"
)