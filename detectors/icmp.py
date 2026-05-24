from scapy.all import sniff, IP, IPv6, ICMP, ICMPv6EchoRequest, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger   import Logger
from core.window   import clean_old, prune_stale
from ai.predict  import predict as ai_predict
from core.alerting import build_alert, severity_icmp
from core.persistence import state_icmp
from core.correlation import correlator
from core.distributed import tracker as dist_tracker

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
state_icmp.register(traffic_data, alerted_ips)
state_icmp.restore()

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

    # support both ICMPv4 (echo request type=8) and ICMPv6 echo request
    is_ipv4 = packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type == 8
    is_ipv6 = packet.haslayer(IPv6) and packet.haslayer(ICMPv6EchoRequest)
    if not (is_ipv4 or is_ipv6):
        return

    ip_src = (packet[IPv6].src if packet.haslayer(IPv6) else packet[IP].src)
    ip_dst = (packet[IPv6].dst if packet.haslayer(IPv6) else packet[IP].dst)
    now    = time.time()

    if ip_src in WHITELIST:
        return

    traffic_data[ip_src].append((now, len(packet)))
    clean_old(traffic_data[ip_src], now, TIME_WINDOW, ts_index=0)
    dist_tracker.add(ip_dst, ip_src, "ICMP")
    state_icmp.maybe_save(now)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(traffic_data, alerted_ips)
        last_prune = now

    features = extract_features(ip_src)
    if not features:
        return

    # extract features first — then use them for AI check
    pps             = features["pps"]
    total_packets   = features["total_packets"]
    duration        = features["duration"]
    avg_packet_size = features["avg_packet_size"]
    max_packet_size = features["max_packet_size"]

    # =========================
    # AI PREDICTION
    # minimum 10 packets required — prevents AI from firing
    # on normal pings which have too few packets for a confident prediction
    # =========================
    if total_packets >= 10:
        ai_result = ai_predict("icmp", features)
        ai_alert  = ai_result["is_attack"]
        ai_conf   = ai_result["confidence"]
    else:
        ai_alert = False
        ai_conf  = 0.0

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

    if pps > ICMP_FLOOD_RATE or ai_alert:
        alert = build_alert(
            alert_type = "ICMP_FLOOD",
            source_ip  = ip_src,
            target_ip  = ip_dst,
            severity   = severity_icmp(pps, ICMP_FLOOD_RATE),
            features   = features,
            extra      = {"ai_confidence": ai_conf,
                          "detection": "RULE+AI" if (pps > ICMP_FLOOD_RATE and ai_alert)
                                       else "AI_ONLY" if ai_alert else "RULE"}
        )
        detection = alert.get("detection", "RULE")
        icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
        print(f"{icon} [{detection}] [ICMP_FLOOD] [{alert['severity']}] {ip_src} → {ip_dst} | pps: {pps:.2f}")
        logger.log(alert)
        correlator.add_alert(ip_src, "ICMP_FLOOD", alert["severity"], ip_dst)
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