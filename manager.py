"""
manager.py — AI-IDS Main Entry Point
======================================
Producer/Consumer architecture :
    sniff thread  →  enqueue(packet)   ultra fast, never blocks
    worker thread →  route(packet)     all detection logic runs here

Class-based detector instances — each detector is fully encapsulated.
AlertStore bridges IDS → MongoDB for dashboard consumption.
"""

import signal
import sys
from scapy.all import sniff, conf, IPSession

from detectors.syn        import SYNDetector
from detectors.arp        import ARPDetector
from detectors.icmp       import ICMPDetector
from detectors.dns        import DNSDetector
from detectors.bruteforce import BruteForceDetector
from detectors.ftp        import FTPDetector
from detectors.dhcp       import DHCPDetector

from ai.predict           import preload_all
from core.persistence     import save_all
from core.correlation     import correlator
from core.logger          import Logger
from core.worker          import enqueue, start_worker, stop_worker, get_stats
from core.distributed     import tracker as dist_tracker
from core.threat_feed     import threat_feed
from core.alert_store     import AlertStore
from config               import THREAT_FEED_ENABLED, ABUSEIPDB_API_KEY, IFACE

# =========================
# ALERT STORE
# Shared MongoDB connection — injected into all detectors
# =========================
_alert_store = AlertStore()

# =========================
# DETECTOR INSTANCES
# All detectors get the same alert_store reference
# =========================
_detectors = [
    SYNDetector(alert_store=_alert_store),
    ARPDetector(alert_store=_alert_store),
    ICMPDetector(alert_store=_alert_store),
    DNSDetector(alert_store=_alert_store),
    BruteForceDetector(alert_store=_alert_store),
    FTPDetector(alert_store=_alert_store),
    DHCPDetector(alert_store=_alert_store),
]

# =========================
# PACKET ROUTER
# Dispatches every packet to all detectors.
# Each detector ignores packets it doesn't care about.
# =========================
def route(packet):
    for detector in _detectors:
        detector.detect(packet)

# =========================
# DASHBOARD API HELPERS
# Your teammate's Node.js API can call these via a local socket or REST.
# =========================
def get_detectors() -> list:
    """Return all detector instances — dashboard uses this for status panel."""
    return _detectors

def get_all_status() -> list:
    """Return status dict for every detector."""
    return [d.get_status() for d in _detectors]

# =========================
# GRACEFUL SHUTDOWN
# =========================
def shutdown(signum=None, frame=None):
    print("\n⏹️  Shutting down AI-IDS...")
    stop_worker(_worker_thread)
    save_all()
    s = get_stats()
    print(f"\n📊 Session stats:")
    print(f"   Packets received  : {s['packets_received']}")
    print(f"   Packets processed : {s['packets_processed']}")
    print(f"   Packets dropped   : {s['packets_dropped']}")
    print(f"   Drop rate         : {s['drop_rate_pct']}%")
    print(f"   Avg pps           : {s['pps_avg']}")
    print(f"   Uptime            : {s['uptime_seconds']}s")
    print("\n✅ AI-IDS stopped cleanly.")
    sys.exit(0)

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface

    print(f"🚀 AI-IDS MANAGER RUNNING on [{iface}]")
    print(f"   Detectors : SYN | ARP | ICMP | DNS | BRUTEFORCE | FTP | DHCP")
    print(f"   IPv6      : supported (rule-based only, no AI for IPv6)")
    print(f"   Mode      : producer/consumer queue (no packet drops)")

    # load AI models into memory before sniffing
    preload_all()

    # set campaign logger for cross-detector correlation
    campaign_logger = Logger("data/campaigns.jsonl")
    correlator.set_logger(campaign_logger)

    # set distributed attack logger
    dist_logger = Logger("data/distributed.jsonl")
    dist_tracker.set_logger(dist_logger)

    # configure threat feed enrichment
    threat_feed.configure(ABUSEIPDB_API_KEY, THREAT_FEED_ENABLED)
    threat_feed.set_logger(Logger("data/threat_feed.jsonl"))

    # register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # start worker thread — reads from queue, calls route()
    _worker_thread = start_worker(route)
    print(f"   Worker    : started ✅\n")

    # start sniffing — main thread only enqueues packets, never processes them
    sniff(
        iface=iface,
        prn=enqueue,
        session=IPSession,
        store=0
    )