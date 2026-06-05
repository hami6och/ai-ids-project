"""
manager.py — AI-IDS Main Entry Point
======================================
Producer/Consumer architecture :
    sniff thread  →  enqueue(packet)   ultra fast, never blocks
    worker thread →  route(packet)     all detection logic runs here
 
Class-based detector instances — each detector is fully encapsulated.
AlertStore bridges IDS → SQLite for dashboard consumption.
"""
 
import signal
import sys
import threading
import time
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
# =========================
_alert_store = AlertStore()
 
# =========================
# DETECTOR INSTANCES
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
 
# Map config key (SQLite) → detector index + attribute name
_CONFIG_MAP = {
    # SYN
    'syn_flood_rate':          (0, 'flood_rate'),
    'syn_port_scan_threshold': (0, 'port_scan_threshold'),
    'syn_alert_cooldown':      (0, 'alert_cooldown'),
    'syn_ai_threshold':        (0, 'ai_threshold'),
    'syn_time_window':         (0, 'time_window'),
    # ARP
    'arp_alert_threshold':     (1, 'alert_threshold'),
    'arp_rate_threshold':      (1, 'rate_threshold'),
    'arp_alert_cooldown':      (1, 'alert_cooldown'),
    'arp_ai_threshold':        (1, 'ai_threshold'),
    # ICMP
    'icmp_flood_rate':         (2, 'flood_rate'),
    'icmp_alert_cooldown':     (2, 'alert_cooldown'),
    'icmp_ai_threshold':       (2, 'ai_threshold'),
    'icmp_time_window':        (2, 'time_window'),
    # DNS
    'dns_request_threshold':   (3, 'request_threshold'),
    'dns_tunnel_qname_len':    (3, 'tunnel_qname_len'),
    'dns_alert_cooldown':      (3, 'alert_cooldown'),
    'dns_ai_threshold':        (3, 'ai_threshold'),
    'dns_time_window':         (3, 'time_window'),
    # BRUTEFORCE
    'brute_attempt_threshold': (4, 'attempt_threshold'),
    'brute_alert_cooldown':    (4, 'alert_cooldown'),
    'brute_ai_threshold':      (4, 'ai_threshold'),
    'brute_time_window':       (4, 'time_window'),
    # FTP
    'ftp_attempt_threshold':   (5, 'attempt_threshold'),
    'ftp_bounce_threshold':    (5, 'bounce_threshold'),
    'ftp_alert_cooldown':      (5, 'alert_cooldown'),
    'ftp_ai_threshold':        (5, 'ai_threshold'),
    # DHCP
    'dhcp_starvation_pps':     (6, 'starvation_pps'),
    'dhcp_starvation_macs':    (6, 'starvation_mac_count'),
    'dhcp_alert_cooldown':     (6, 'alert_cooldown'),
    'dhcp_ai_threshold':       (6, 'ai_threshold'),
}
 
# =========================
# CONFIG WATCHER
# Reads SQLite config table every 30s and applies changes to detectors
# =========================
_last_config = {}
 
def _apply_config():
    """Read config table and update detector attributes if values changed."""
    current = _alert_store.read_config()
    for key, value in current.items():
        if key not in _CONFIG_MAP:
            continue
        if _last_config.get(key) == value:
            continue  # no change
        detector_idx, attr = _CONFIG_MAP[key]
        detector = _detectors[detector_idx]
        if hasattr(detector, attr):
            old = getattr(detector, attr)
            setattr(detector, attr, value)
            print(f"   [Config] {key}: {old} → {value}")
            _last_config[key] = value
 
def _config_watcher():
    """Background thread — polls SQLite config table every 30s."""
    while True:
        time.sleep(30)
        try:
            _apply_config()
        except Exception as e:
            print(f"   [Config] Error: {e}")
 
# =========================
# PACKET ROUTER
# =========================
def route(packet):
    for detector in _detectors:
        detector.detect(packet)
 
# =========================
# DASHBOARD API HELPERS
# =========================
def get_detectors() -> list:
    return _detectors
 
def get_all_status() -> list:
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
 
    preload_all()
 
    campaign_logger = Logger("data/campaigns.jsonl")
    correlator.set_logger(campaign_logger)
 
    dist_logger = Logger("data/distributed.jsonl")
    dist_tracker.set_logger(dist_logger)
 
    threat_feed.configure(ABUSEIPDB_API_KEY, THREAT_FEED_ENABLED)
    threat_feed.set_logger(Logger("data/threat_feed.jsonl"))
 
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)
 
    # apply any saved config from previous session immediately
    _apply_config()
 
    # start config watcher thread
    watcher = threading.Thread(target=_config_watcher, daemon=True)
    watcher.start()
    print(f"   Config    : watcher started (polls every 30s) ✅")
 
    _worker_thread = start_worker(route)
    print(f"   Worker    : started ✅\n")
 
    sniff(
        iface=iface,
        prn=enqueue,
        session=IPSession,
        store=0
    )
