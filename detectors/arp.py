import time
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, ARP, conf

from core.logger      import Logger
from core.window      import clean_old, prune_stale
from ai.predict       import predict as ai_predict
from core.alerting    import build_alert, severity_arp
from core.persistence import state_arp
from config import (
    ARP_RATE_WINDOW as RATE_WINDOW,
    ARP_RATE_THRESHOLD as RATE_THRESHOLD,
    ARP_NETWORK_RATE_THRESH as NETWORK_RATE_THRESHOLD,
    ARP_ALERT_THRESHOLD as ALERT_THRESHOLD,
    ARP_ALERT_COOLDOWN as ALERT_COOLDOWN,
    ARP_PRUNE_INTERVAL as PRUNE_INTERVAL,
    WHITELIST,
    IFACE
)
from core.correlation import correlator

# ===============================
# CONFIG
# ===============================
ALERT_THRESHOLD          = 8

# ===============================
# STORAGE
# ===============================
arp_table          = {}
packet_times       = defaultdict(deque)
mac_history        = defaultdict(set)
alerted_ips        = {}
last_prune         = time.time()
network_arp_counts = defaultdict(int)

# ===============================
# LOGGER + PERSISTENCE
# ===============================
logger = Logger("data/arp_dataset.jsonl")
state_arp.register(arp_table, alerted_ips, mac_history)
state_arp.restore()

# ===============================
# FEATURE EXTRACTION
# ===============================
def extract_features(ip, packet, now):
    dq = packet_times[ip]
    if not dq:
        return None

    duration         = dq[-1] - dq[0]
    per_ip_rate      = round(len(dq) / max(duration, 1), 3)
    window_key       = int(now / RATE_WINDOW)
    network_arp_rate = round(
        (network_arp_counts[window_key] + network_arp_counts.get(window_key - 1, 0))
        / RATE_WINDOW, 3
    )

    return {
        "packet_rate"      : per_ip_rate,
        "network_arp_rate" : network_arp_rate,
        "unique_macs"      : len(mac_history[ip]),
        "mac_changed"      : int(bool(
                               arp_table.get(ip) and
                               arp_table.get(ip) != packet[ARP].hwsrc
                             )),
        "known_mac"        : arp_table.get(ip),
        "is_gratuitous"    : int(packet[ARP].psrc == packet[ARP].pdst),
        "hwdst"            : packet[ARP].hwdst,
        "is_broadcast"     : int(packet[ARP].hwdst == "ff:ff:ff:ff:ff:ff"),
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
    state_arp.maybe_save(now)

    window_key = int(now / RATE_WINDOW)
    network_arp_counts[window_key] += 1
    stale_keys = [k for k in network_arp_counts if k < window_key - 2]
    for k in stale_keys:
        del network_arp_counts[k]

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(packet_times, mac_history, alerted_ips)
        last_prune = now

    features = extract_features(ip, packet, now)
    if not features:
        return

    ai_result = ai_predict("arp", features)
    ai_alert  = ai_result["is_attack"]
    ai_conf   = ai_result["confidence"]

    mac_changed      = features["mac_changed"]
    known_mac        = features["known_mac"]
    rate             = features["packet_rate"]
    network_arp_rate = features["network_arp_rate"]
    unique_macs      = features["unique_macs"]
    is_gratuitous    = features["is_gratuitous"]
    hwdst            = features["hwdst"]
    is_broadcast     = features["is_broadcast"]

    score = 0
    if mac_changed:                               score += 3
    if unique_macs > 2:                           score += 2
    if rate > RATE_THRESHOLD:                     score += 1
    if network_arp_rate > NETWORK_RATE_THRESHOLD: score += 2
    if is_gratuitous:                             score += 2
    if is_broadcast:                              score += 2

    logger.log({
        "timestamp"        : str(datetime.now()),
        "ip"               : ip,
        "mac"              : mac,
        "known_mac"        : known_mac,
        "mac_changed"      : mac_changed,
        "packet_rate"      : rate,
        "network_arp_rate" : network_arp_rate,
        "unique_macs"      : unique_macs,
        "is_gratuitous"    : is_gratuitous,
        "hwdst"            : hwdst,
        "is_broadcast"     : is_broadcast,
        "score"            : score,
        "label"            : 0
    })

    last_alert = alerted_ips.get(ip, 0)
    if now - last_alert < ALERT_COOLDOWN:
        arp_table[ip] = mac
        return

    if score >= ALERT_THRESHOLD or ai_alert:
        severity  = severity_arp(score)
        detection = "RULE+AI" if (score >= ALERT_THRESHOLD and ai_alert) else \
                    "AI_ONLY" if ai_alert else "RULE"
        alert = build_alert(
            alert_type = "ARP_SPOOFING",
            source_ip  = ip,
            target_ip  = "N/A",
            severity   = severity,
            features   = features,
            extra      = {"source_mac": mac, "score": score,
                          "ai_confidence": ai_conf, "detection": detection}
        )
        icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
        print(f"{icon} [{detection}] [ARP_SPOOFING] [{severity}] {ip} | score: {score} | net_rate: {network_arp_rate:.1f}/s | AI: {int(ai_conf*100)}%")
        logger.log(alert)
        correlator.add_alert(ip, "ARP_SPOOFING", alert["severity"])
        alerted_ips[ip] = now

    arp_table[ip] = mac

# ===============================
# START
# ===============================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 ARP SPOOFING DETECTION RUNNING on [{iface}]...")
    sniff(iface=iface, filter="arp", prn=detect_arp, store=0)