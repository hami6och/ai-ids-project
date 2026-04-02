from scapy.all import sniff, IP, UDP, DNS, DNSQR, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger   import Logger
from core.window   import clean_old, prune_stale
from core.alerting import build_alert, severity_dns

# =========================
# CONFIG
# =========================
TIME_WINDOW       = 5
REQUEST_THRESHOLD = 20
ALERT_COOLDOWN    = 20
PRUNE_INTERVAL    = 60
WHITELIST         = {"127.0.0.1"}
IFACE             = None

QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"
}

# =========================
# STORAGE
# =========================
dns_requests = defaultdict(deque)   # ip → [(timestamp, qname, qtype_str)]
alerted_ips  = {}
last_prune   = time.time()

# =========================
# LOGGER
# =========================
logger = Logger("data/dns_logs.jsonl")

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(ip):
    data = dns_requests[ip]
    if not data:
        return None

    times  = [t  for t,  _, _  in data]
    qnames = [q  for _,  q, _  in data]
    qtypes = [qt for _,  _, qt in data]

    duration     = max(times) - min(times) if len(times) > 1 else 0
    intervals    = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
    avg_interval = sum(intervals) / len(intervals) if intervals else 0

    unique_domains         = len(set(qnames))
    domain_diversity_ratio = unique_domains / len(qnames)

    domain_counts = defaultdict(int)
    for q in qnames:
        domain_counts[q] += 1
    top_domain       = max(domain_counts, key=domain_counts.get)
    top_domain_ratio = domain_counts[top_domain] / len(qnames)

    type_counts   = defaultdict(int)
    for qt in qtypes:
        type_counts[qt] += 1

    avg_qname_len = sum(len(q) for q in qnames) / len(qnames)

    return {
        "total_requests"        : len(data),
        "duration"              : round(duration, 3),
        "pps"                   : round(len(data) / max(duration, 1), 3),
        "avg_interval"          : round(avg_interval, 4),
        "unique_domains"        : unique_domains,
        "domain_diversity_ratio": round(domain_diversity_ratio, 3),
        "top_domain"            : top_domain,
        "top_domain_ratio"      : round(top_domain_ratio, 3),
        "unique_qtypes"         : len(set(qtypes)),
        "type_counts"           : dict(type_counts),
        "avg_qname_len"         : round(avg_qname_len, 2),
    }

# =========================
# DETECTION ENGINE
# =========================
def detect(packet):
    global last_prune

    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return
    if not packet.haslayer(DNS):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    now    = time.time()

    if ip_src in WHITELIST:
        return
    if packet[DNS].qr != 0:
        return

    if packet.haslayer(DNSQR):
        qname     = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        qtype_str = QTYPE_MAP.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))
    else:
        qname     = "unknown"
        qtype_str = "unknown"

    dns_requests[ip_src].append((now, qname, qtype_str))
    clean_old(dns_requests[ip_src], now, TIME_WINDOW, ts_index=0)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(dns_requests, alerted_ips)
        last_prune = now

    features = extract_features(ip_src)
    if not features:
        return

    logger.log({
        "timestamp" : str(datetime.now()),
        "source_ip" : ip_src,
        "target_ip" : ip_dst,
        "qname"     : qname,
        "qtype"     : qtype_str,
        "label"     : 0,
        **features
    })

    last_alert = alerted_ips.get(ip_src, 0)
    if now - last_alert < ALERT_COOLDOWN:
        return

    alert_type = None
    if features["avg_qname_len"] > 50:
        alert_type = "DNS_TUNNEL"
    elif features["total_requests"] >= REQUEST_THRESHOLD:
        alert_type = "DNS_FLOOD"

    if alert_type:
        alert = build_alert(
            alert_type = alert_type,
            source_ip  = ip_src,
            target_ip  = ip_dst,
            severity   = severity_dns(features["total_requests"], features["pps"]),
            features   = features
        )
        print(f"🚨 ALERT [{alert['severity']}] [{alert_type}] {ip_src} → {ip_dst} "
              f"| {features['total_requests']} req | pps: {features['pps']} "
              f"| avg_len: {features['avg_qname_len']}")
        logger.log(alert)
        alerted_ips[ip_src] = now

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 DNS FLOOD/TUNNEL DETECTION RUNNING on [{iface}]...")
    sniff(
        iface=iface,
        filter="udp port 53",
        prn=detect,
        store=0
    )