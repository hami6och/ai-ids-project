"""
manager.py — AI-IDS Main Entry Point
======================================
Producer/Consumer architecture :
    sniff thread  →  enqueue(packet)   ultra fast, never blocks
    worker thread →  route(packet)     all detection logic runs here

This separation prevents packet drops under heavy attack traffic.
"""

import signal
import sys
import atexit
from scapy.all import sniff, conf

from detectors        import syn, arp, icmp, dns, bruteforce, ftp, dhcp
from ai.predict       import preload_all
from core.persistence import save_all
from core.correlation import correlator
from core.logger      import Logger
from core.worker      import enqueue, start_worker, stop_worker, get_stats
from core.distributed import tracker as dist_tracker

# =========================
# CONFIG
# =========================
IFACE = None    # None = auto-detect from system

# =========================
# PACKET ROUTER
# Called by worker thread for every packet.
# Dispatches to all detectors — each ignores packets it doesn't care about.
# =========================
def route(packet):
    syn.detect(packet)
    arp.detect_arp(packet)
    icmp.detect(packet)
    dns.detect(packet)
    bruteforce.detect(packet)
    ftp.detect(packet)
    dhcp.detect(packet)

# =========================
# GRACEFUL SHUTDOWN
# Drains the queue, saves state, then exits.
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
    print(f"   Mode      : producer/consumer queue (no packet drops)")

    # load AI models into memory before sniffing
    preload_all()

    # set campaign logger for cross-detector correlation
    campaign_logger = Logger("data/campaigns.jsonl")
    correlator.set_logger(campaign_logger)

    # set distributed attack logger
    dist_logger = Logger("data/distributed.jsonl")
    dist_tracker.set_logger(dist_logger)

    # register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # start worker thread — reads from queue, calls route()
    _worker_thread = start_worker(route)
    print(f"   Worker    : started ✅\n")

    # start sniffing — main thread only enqueues packets, never processes them
    sniff(
        iface=iface,
        prn=enqueue,   # ultra fast — just puts packet in queue
        store=0
    )