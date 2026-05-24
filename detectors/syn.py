from scapy.all import sniff, IP, TCP, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger   import Logger
from core.window   import clean_old, prune_stale
from ai.predict  import predict as ai_predict
from core.alerting import build_alert, severity_syn_flood, severity_syn_scan
from core.persistence import state_syn
from core.correlation import correlator
from core.distributed import tracker as dist_tracker

# =========================
# CONFIG
# =========================
TIME_WINDOW         = 5
PORT_SCAN_THRESHOLD = 5
SYN_FLOOD_RATE      = 10
ALERT_COOLDOWN      = 20
PRUNE_INTERVAL      = 60
WHITELIST           = {"127.0.0.1"}
IFACE               = None

# =========================
# STORAGE
# =========================
traffic_data = defaultdict(deque)   # ip → [(port, timestamp)]
alerted_ips  = {}
last_prune   = time.time()

# =========================
# LOGGER
# =========================
logger = Logger("data/syn_dataset.jsonl")
state_syn.register(traffic_data, alerted_ips)
state_syn.restore()

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(ip):
    data = traffic_data[ip]
    if not data:
        return None

    ports = [p for p, _ in data]
    times = [t for _, t in data]

    duration = max(times) - min(times) if len(times) > 1 else 0

    port_counts = defaultdict(int)
    for port in ports:
        port_counts[port] += 1

    return {
        "unique_ports"  : len(set(ports)),
        "total_packets" : len(ports),
        "duration"      : round(duration, 3),
        "pps"           : round(len(ports) / max(duration, 1), 3),
        "port_counts"   : dict(port_counts)
    }

# =========================
# DETECTION ENGINE
# =========================
def detect(packet):
    global last_prune

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    flags = packet[TCP].flags
    if not (flags & 0x02 and not flags & 0x10):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    dport  = packet[TCP].dport
    now    = time.time()

    if ip_src in WHITELIST:
        return

    traffic_data[ip_src].append((dport, now))
    clean_old(traffic_data[ip_src], now, TIME_WINDOW, ts_index=1)
    dist_tracker.add(ip_dst, ip_src, "SYN")
    state_syn.maybe_save(now)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(traffic_data, alerted_ips)
        last_prune = now

    features = extract_features(ip_src)
    if not features:
        return

    unique_ports  = features["unique_ports"]
    total_packets = features["total_packets"]
    pps           = features["pps"]
    port_counts   = features["port_counts"]

    # =========================
    # AI PREDICTION
    # minimum 8 packets required — SYN scan needs enough ports
    # to distinguish from normal browsing (3-4 connections)
    # =========================
    if total_packets >= 8:
        ai_result = ai_predict("syn", features)
        ai_alert  = ai_result["is_attack"]
        ai_conf   = ai_result["confidence"]
    else:
        ai_alert = False
        ai_conf  = 0.0

    logger.log({
        "timestamp"    : str(datetime.now()),
        "source_ip"    : ip_src,
        "target_ip"    : ip_dst,
        "dport"        : dport,
        "unique_ports" : unique_ports,
        "total_packets": total_packets,
        "pps"          : pps,
        "label"        : 0
    })

    last_alert = alerted_ips.get(ip_src, 0)
    if now - last_alert < ALERT_COOLDOWN:
        return

    # SYN FLOOD
    # fires if rule threshold crossed OR AI is confident
    for port, count in port_counts.items():
        rate = count / TIME_WINDOW
        if rate > SYN_FLOOD_RATE or (ai_alert and count == max(port_counts.values())):
            alert = build_alert(
                alert_type = "SYN_FLOOD",
                source_ip  = ip_src,
                target_ip  = ip_dst,
                severity   = severity_syn_flood(rate),
                features   = features,
                extra      = {"port": port, "rate": round(rate, 2),
                              "ai_confidence": ai_conf,
                              "detection": "RULE+AI" if ai_alert else "RULE"}
            )
            detection = alert.get("detection", "RULE")
            icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
            print(f"{icon} [{detection}] [SYN_FLOOD] [{alert['severity']}] {ip_src} → {ip_dst}:{port} | rate: {rate:.2f} pps")
            logger.log(alert)
            correlator.add_alert(ip_src, "SYN_FLOOD", alert["severity"], ip_dst)
            alerted_ips[ip_src] = now
            traffic_data[ip_src].clear()
            return

    # SYN SCAN
    if unique_ports >= PORT_SCAN_THRESHOLD or ai_alert:
        alert = build_alert(
            alert_type = "SYN_SCAN",
            source_ip  = ip_src,
            target_ip  = ip_dst,
            severity   = severity_syn_scan(unique_ports),
            features   = features,
            extra      = {"ai_confidence": ai_conf,
                          "detection": "RULE+AI" if ai_alert else
                                       "AI_ONLY" if ai_alert else "RULE"}
        )
        detection = alert.get("detection", "RULE")
        icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
        print(f"{icon} [{detection}] [SYN_SCAN] [{alert['severity']}] {ip_src} → {ip_dst} | ports: {unique_ports}")
        logger.log(alert)
        correlator.add_alert(ip_src, "SYN_SCAN", alert["severity"], ip_dst)
        alerted_ips[ip_src] = now
        traffic_data[ip_src].clear()

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 SYN FLOOD/SCAN DETECTION RUNNING on [{iface}]...")
    sniff(
        iface=iface,
        filter="tcp[tcpflags] & tcp-syn != 0",
        prn=detect,
        store=0
    )