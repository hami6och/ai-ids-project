from scapy.all import sniff, IP, ICMP, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger   import Logger
from core.window   import clean_old, prune_stale
from core.alerting import build_alert, severity_icmp

# =========================
# CONFIG
# =========================
TIME_WINDOW     = 5
ICMP_FLOOD_RATE = 20
ALERT_COOLDOWN  = 20
PRUNE_INTERVAL  = 60
WHITELIST       = {"127.0.0.1"}
IFACE           = None

# =========================
# STORAGE
# =========================
traffic_data = defaultdict(deque)   # ip → [(timestamp, size)]
alerted_ips  = {}
last_prune   = time.time()

# =========================
# LOGGER
# =========================
logger = Logger("data/icmp_dataset.jsonl")

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(ip):
    data = traffic_data[ip]
    if not data:
        return None

    times = [ts for ts, _  in data]
    sizes = [sz for _,  sz in data]

    duration = max(times) - min(times) if len(times) > 1 else 0

    return {
        "total_packets"  : len(data),
        "duration"       : round(duration, 3),
        "pps"            : round(len(data) / max(duration, 1), 3),
        "avg_packet_size": round(sum(sizes) / len(sizes), 2),
        "max_packet_size": max(sizes)
    }

# =========================
# DETECTION ENGINE
# =========================
def detect(packet):
    global last_prune

    if not packet.haslayer(IP) or not packet.haslayer(ICMP):
        return
    if packet[ICMP].type != 8:
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    now    = time.time()

    if ip_src in WHITELIST:
        return

    traffic_data[ip_src].append((now, len(packet)))
    clean_old(traffic_data[ip_src], now, TIME_WINDOW, ts_index=0)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(traffic_data, alerted_ips)
        last_prune = now

    features = extract_features(ip_src)
    if not features:
        return

    pps             = features["pps"]
    total_packets   = features["total_packets"]
    duration        = features["duration"]
    avg_packet_size = features["avg_packet_size"]
    max_packet_size = features["max_packet_size"]

    logger.log({
        "timestamp"      : str(datetime.now()),
        "source_ip"      : ip_src,
        "target_ip"      : ip_dst,
        "total_packets"  : total_packets,
        "duration"       : duration,
        "pps"            : pps,
        "avg_packet_size": avg_packet_size,
        "max_packet_size": max_packet_size,
        "label"          : 0
    })

    last_alert = alerted_ips.get(ip_src, 0)
    if now - last_alert < ALERT_COOLDOWN:
        return

    if pps > ICMP_FLOOD_RATE:
        alert = build_alert(
            alert_type = "ICMP_FLOOD",
            source_ip  = ip_src,
            target_ip  = ip_dst,
            severity   = severity_icmp(pps, ICMP_FLOOD_RATE),
            features   = features
        )
        print(f"🚨 ALERT [ICMP_FLOOD] [{alert['severity']}] {ip_src} → {ip_dst} | pps: {pps:.2f}")
        logger.log(alert)
        alerted_ips[ip_src] = now
        traffic_data[ip_src].clear()

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 ICMP FLOOD DETECTION RUNNING on [{iface}]...")
    sniff(
        iface=iface,
        filter="icmp",
        prn=detect,
        store=0
    )