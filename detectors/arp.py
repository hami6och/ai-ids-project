import time
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, ARP, conf

from core.logger   import Logger
from core.window   import clean_old, prune_stale
from core.alerting import build_alert, severity_arp

# ===============================
# CONFIG
# ===============================
RATE_WINDOW     = 10
RATE_THRESHOLD  = 5
ALERT_THRESHOLD = 4
ALERT_COOLDOWN  = 20
PRUNE_INTERVAL  = 60
WHITELIST       = {"127.0.0.1"}
IFACE           = None

# ===============================
# STORAGE
# ===============================
arp_table    = {}
packet_times = defaultdict(deque)   # ip → deque[timestamp]
mac_history  = defaultdict(set)
alerted_ips  = {}
last_prune   = time.time()

# ===============================
# LOGGER
# ===============================
logger = Logger("data/arp_dataset.jsonl")

# ===============================
# FEATURE EXTRACTION
# ===============================
def extract_features(ip, packet):
    dq = packet_times[ip]
    if not dq:
        return None

    duration = dq[-1] - dq[0]

    return {
        "packet_rate"   : round(len(dq) / max(duration, 1), 3),
        "unique_macs"   : len(mac_history[ip]),
        "mac_changed"   : int(bool(
                            arp_table.get(ip) and
                            arp_table.get(ip) != packet[ARP].hwsrc
                          )),
        "known_mac"     : arp_table.get(ip),
        "is_gratuitous" : int(packet[ARP].psrc == packet[ARP].pdst),
        "hwdst"         : packet[ARP].hwdst,
        "is_broadcast"  : int(packet[ARP].hwdst == "ff:ff:ff:ff:ff:ff"),
    }

# ===============================
# DETECTION ENGINE
# ===============================
def detect_arp(packet):
    global last_prune

    if not (packet.haslayer(ARP) and packet[ARP].op == 2):
        return

    ip  = packet[ARP].psrc
    mac = packet[ARP].hwsrc
    now = time.time()

    if ip in WHITELIST:
        return

    packet_times[ip].append(now)
    mac_history[ip].add(mac)
    clean_old(packet_times[ip], now, RATE_WINDOW, ts_index=None)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(packet_times, mac_history, alerted_ips)
        last_prune = now

    features = extract_features(ip, packet)
    if not features:
        return

    mac_changed   = features["mac_changed"]
    known_mac     = features["known_mac"]
    rate          = features["packet_rate"]
    unique_macs   = features["unique_macs"]
    is_gratuitous = features["is_gratuitous"]
    hwdst         = features["hwdst"]
    is_broadcast  = features["is_broadcast"]

    score = 0
    if mac_changed:           score += 3
    if unique_macs > 2:       score += 2
    if rate > RATE_THRESHOLD: score += 1
    if is_gratuitous:         score += 2
    if is_broadcast:          score += 2

    logger.log({
        "timestamp"    : str(datetime.now()),
        "ip"           : ip,
        "mac"          : mac,
        "known_mac"    : known_mac,
        "mac_changed"  : mac_changed,
        "packet_rate"  : rate,
        "unique_macs"  : unique_macs,
        "is_gratuitous": is_gratuitous,
        "hwdst"        : hwdst,
        "is_broadcast" : is_broadcast,
        "score"        : score,
        "label"        : 0
    })

    last_alert = alerted_ips.get(ip, 0)
    if now - last_alert < ALERT_COOLDOWN:
        arp_table[ip] = mac
        return

    if score >= ALERT_THRESHOLD:
        alert = build_alert(
            alert_type = "ARP_SPOOFING",
            source_ip  = ip,
            target_ip  = "N/A",
            severity   = severity_arp(score),
            features   = features,
            extra      = {"source_mac": mac, "score": score}
        )
        print(f"🚨 ALERT [ARP_SPOOFING] [{alert['severity']}] {ip} | score: {score}")
        logger.log(alert)
        alerted_ips[ip] = now

    arp_table[ip] = mac

# ===============================
# START
# ===============================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 ARP SPOOFING DETECTION RUNNING on [{iface}]...")
    sniff(
        iface=iface,
        filter="arp",
        prn=detect_arp,
        store=0
    )