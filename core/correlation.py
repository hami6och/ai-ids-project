"""
core/correlation.py — Cross-Detector Correlation Engine
=========================================================
Watches alerts from all detectors and fires a combined campaign
alert when the same source IP triggers multiple detectors within
a time window.

How it works :
    Every detector calls correlator.add_alert() when it fires.
    The correlator tracks alerts per source IP in a sliding window.
    When one IP hits >= CORRELATION_THRESHOLD detectors, a
    ATTACK_CAMPAIGN alert is generated with full context.

Usage in detectors :
    from core.correlation import correlator

    # after building and logging your alert
    correlator.add_alert(src_ip, alert_type, severity, dst_ip)

Usage in manager.py :
    from core.correlation import correlator
    # correlator is a singleton — no setup needed
"""

import time
from collections import defaultdict, deque
from datetime import datetime

# =========================
# CONFIG
# =========================
from config import CORRELATION_WINDOW, CORRELATION_THRESHOLD, CAMPAIGN_COOLDOWN

# =========================
# CAMPAIGN SEVERITY LOGIC
# more detectors hit = higher severity
# =========================
def campaign_severity(detector_count: int, alert_types: list) -> str:
    # CRITICAL signals regardless of count
    critical_types = {"SYN_FLOOD", "ICMP_FLOOD", "DHCP_ROGUE_SERVER", "ARP_SPOOFING"}
    if any(t in critical_types for t in alert_types):
        if detector_count >= 3:
            return "CRITICAL"
        return "HIGH"

    if detector_count >= 4: return "CRITICAL"
    if detector_count >= 3: return "HIGH"
    if detector_count >= 2: return "MEDIUM"
    return "LOW"


class CorrelationEngine:
    """
    Singleton correlation engine.
    Tracks per-IP alert history and fires campaign alerts.
    """

    def __init__(self):
        # ip → deque of (timestamp, alert_type, severity, dst_ip)
        self._history      = defaultdict(deque)
        self._last_campaign= {}    # ip → last campaign alert timestamp
        self._campaign_log = None  # set by manager.py to the campaign logger

    def set_logger(self, logger):
        """Inject the campaign logger from manager.py."""
        self._campaign_log = logger

    def add_alert(self, src_ip: str, alert_type: str,
                  severity: str, dst_ip: str = "N/A"):
        """
        Call this every time any detector fires an alert.
        Thread-safe enough for single-threaded Scapy usage.
        """
        now = time.time()

        # store this alert in history
        self._history[src_ip].append((now, alert_type, severity, dst_ip))

        # evict old entries outside the window
        dq = self._history[src_ip]
        while dq and now - dq[0][0] > CORRELATION_WINDOW:
            dq.popleft()

        # check if this IP has hit enough distinct detector types
        recent_types = list({entry[1] for entry in dq})   # unique alert types

        if len(recent_types) >= CORRELATION_THRESHOLD:
            self._maybe_fire_campaign(src_ip, recent_types, dq, now)
        else:
            # enrich single alert with threat feed even before campaign fires
            try:
                from core.threat_feed import threat_feed
                threat_feed.check_async(src_ip)
            except Exception:
                pass

    def _maybe_fire_campaign(self, src_ip: str, alert_types: list,
                              dq: deque, now: float):
        """Fire a campaign alert if cooldown has elapsed."""
        last = self._last_campaign.get(src_ip, 0)
        if now - last < CAMPAIGN_COOLDOWN:
            return

        self._last_campaign[src_ip] = now

        # build campaign context
        timespan  = round(now - dq[0][0], 1)
        dst_ips   = list({entry[3] for entry in dq if entry[3] != "N/A"})
        severity  = campaign_severity(len(alert_types), alert_types)

        campaign = {
            "timestamp"      : str(datetime.now()),
            "type"           : "ATTACK_CAMPAIGN",
            "source_ip"      : src_ip,
            "target_ips"     : dst_ips,
            "severity"       : severity,
            "detector_count" : len(alert_types),
            "alert_types"    : alert_types,
            "timespan_sec"   : timespan,
            "detection"      : "CORRELATION"
        }

        # print to terminal
        types_str = " + ".join(alert_types)
        print(f"\n{'='*60}")
        print(f"🔴 [CORRELATION] [ATTACK_CAMPAIGN] [{severity}] {src_ip}")
        print(f"   Detectors hit : {types_str}")
        print(f"   Timespan      : {timespan}s")
        print(f"   Targets       : {dst_ips}")
        print(f"{'='*60}\n")

        # log to JSONL
        if self._campaign_log:
            self._campaign_log.log(campaign)

        # enrich with threat intelligence
        try:
            from core.threat_feed import threat_feed
            threat_feed.check_async(src_ip, "ATTACK_CAMPAIGN", severity)
        except Exception:
            pass

    def get_history(self, src_ip: str) -> list:
        """Return recent alert history for an IP — useful for dashboard."""
        return list(self._history.get(src_ip, []))

    def active_attackers(self) -> dict:
        """
        Return all IPs with alerts in the current window.
        Useful for dashboard threat summary.
        Format : {ip: [alert_types]}
        """
        now = time.time()
        result = {}
        for ip, dq in self._history.items():
            recent = [e for e in dq if now - e[0] <= CORRELATION_WINDOW]
            if recent:
                result[ip] = list({e[1] for e in recent})
        return result


# =========================
# SINGLETON
# Import this in detectors and manager.py
# =========================
correlator = CorrelationEngine()