"""
core/distributed.py — Distributed Attack Detector
===================================================
Tracks traffic aggregated by DESTINATION IP across ALL source IPs.
Fires when many different sources hit the same target simultaneously
— the signature of botnet/distributed attacks.

Each detector calls tracker.add(dst_ip, src_ip, attack_type) on
every relevant packet. The tracker checks if the number of unique
source IPs hitting one destination exceeds the threshold.

Usage in detectors :
    from core.distributed import tracker

    # inside detect() on every relevant packet
    tracker.add(ip_dst, ip_src, "SYN")

Usage in manager.py :
    # tracker is a singleton — no setup needed
    # set logger once at startup:
    from core.distributed import tracker
    tracker.set_logger(Logger("data/distributed.jsonl"))
"""

import time
from collections import defaultdict, deque
from datetime import datetime

# =========================
# CONFIG
# =========================
from config import (
    DIST_WINDOW, DIST_COOLDOWN,
    DIST_SYN_THRESHOLD, DIST_ICMP_THRESHOLD,
    DIST_DNS_THRESHOLD, DIST_BRUTE_THRESHOLD
)
THRESHOLDS = {
    "SYN"    : DIST_SYN_THRESHOLD,
    "ICMP"   : DIST_ICMP_THRESHOLD,
    "DNS"    : DIST_DNS_THRESHOLD,
    "BRUTE"  : DIST_BRUTE_THRESHOLD,
    "DEFAULT": DIST_SYN_THRESHOLD,
}


def dist_severity(src_count: int) -> str:
    if src_count >= 50: return "CRITICAL"
    if src_count >= 20: return "HIGH"
    if src_count >= 10: return "MEDIUM"
    return "LOW"


class DistributedTracker:
    """
    Singleton tracker — aggregates traffic by destination IP.
    Thread-safe enough for single-worker architecture.
    """

    def __init__(self):
        # dst_ip → attack_type → deque of (timestamp, src_ip)
        self._data         = defaultdict(lambda: defaultdict(deque))
        self._last_alert   = {}    # dst_ip → last alert timestamp
        self._logger       = None

    def set_logger(self, logger):
        self._logger = logger

    def add(self, dst_ip: str, src_ip: str, attack_type: str):
        """
        Record one packet from src_ip targeting dst_ip.
        Call this on every relevant packet in each detector.
        Checks for distributed attack after each addition.
        """
        now = time.time()
        dq  = self._data[dst_ip][attack_type]
        dq.append((now, src_ip))

        # evict old entries outside the window
        while dq and now - dq[0][0] > DIST_WINDOW:
            dq.popleft()

        # count unique source IPs in window
        unique_sources = len({src for _, src in dq})
        threshold      = THRESHOLDS.get(attack_type, THRESHOLDS["DEFAULT"])

        if unique_sources >= threshold:
            self._maybe_alert(dst_ip, attack_type, unique_sources, dq, now)

    def _maybe_alert(self, dst_ip: str, attack_type: str,
                     src_count: int, dq: deque, now: float):
        """Fire distributed alert if cooldown has elapsed."""
        key      = f"{dst_ip}_{attack_type}"
        last     = self._last_alert.get(key, 0)
        if now - last < DIST_COOLDOWN:
            return

        self._last_alert[key] = now

        sources   = list({src for _, src in dq})[:10]  # top 10 for display
        severity  = dist_severity(src_count)
        alert_name = f"DISTRIBUTED_{attack_type}_FLOOD"

        alert = {
            "timestamp"    : str(datetime.now()),
            "type"         : alert_name,
            "target_ip"    : dst_ip,
            "source_count" : src_count,
            "sample_sources": sources,
            "severity"     : severity,
            "window_sec"   : DIST_WINDOW,
            "detection"    : "DISTRIBUTED"
        }

        print(f"\n{'='*60}")
        print(f"🌐 [DISTRIBUTED] [{alert_name}] [{severity}] → {dst_ip}")
        print(f"   Source IPs    : {src_count} unique sources in {DIST_WINDOW}s")
        print(f"   Sample sources: {sources[:5]}")
        print(f"{'='*60}\n")

        if self._logger:
            self._logger.log(alert)

    def get_status(self) -> dict:
        """
        Return current distributed attack status per destination.
        Used by dashboard threat map.
        """
        now    = time.time()
        result = {}
        for dst_ip, type_data in self._data.items():
            for attack_type, dq in type_data.items():
                recent  = [(t, s) for t, s in dq if now - t <= DIST_WINDOW]
                if recent:
                    sources = len({s for _, s in recent})
                    if sources >= 3:   # only report if somewhat notable
                        result[f"{dst_ip}_{attack_type}"] = {
                            "dst_ip"      : dst_ip,
                            "attack_type" : attack_type,
                            "src_count"   : sources,
                        }
        return result


# =========================
# SINGLETON
# =========================
tracker = DistributedTracker()