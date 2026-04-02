from scapy.all import sniff, IP, TCP, conf
from collections import defaultdict, deque
import time
import json
import atexit
from datetime import datetime

# =========================
# CONFIG
# =========================
TIME_WINDOW         = 5
PORT_SCAN_THRESHOLD = 5
SYN_FLOOD_RATE      = 10
ALERT_COOLDOWN      = 20
PRUNE_INTERVAL      = 60
WHITELIST           = {"127.0.0.1"}
LOG_FILE            = "data/syn_dataset.jsonl"
IFACE               = None    # None = auto-detect

# =========================
# STORAGE
# =========================
traffic_data = defaultdict(deque)   # ip → [(port, timestamp)]
alerted_ips  = {}
last_prune   = time.time()

# =========================
# JSONL LOGGER
# =========================
log_file = open(LOG_FILE, "a")
atexit.register(log_file.close)

def log_event(data):
    log_file.write(json.dumps(data) + "\n")
    log_file.flush()

# =========================
# CLEAN OLD DATA (popleft O(1))
# =========================
def clean_old(ip, now):
    dq = traffic_data[ip]
    while dq and now - dq[0][1] > TIME_WINDOW:
        dq.popleft()

# =========================
# PRUNE STALE IPs
# =========================
def prune_stale(now):
    stale = [ip for ip, dq in traffic_data.items() if not dq]
    for ip in stale:
        del traffic_data[ip]
        alerted_ips.pop(ip, None)

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
# SEVERITY
# =========================
def compute_severity_flood(rate):
    if rate > SYN_FLOOD_RATE * 4: return "CRITICAL"
    if rate > SYN_FLOOD_RATE * 2: return "HIGH"
    return "MEDIUM"

def compute_severity_scan(unique_ports):
    if unique_ports > 50:  return "CRITICAL"
    if unique_ports > 20:  return "HIGH"
    if unique_ports > 10:  return "MEDIUM"
    return "LOW"

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
    clean_old(ip_src, now)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(now)
        last_prune = now

    features = extract_features(ip_src)
    if not features:
        return

    unique_ports  = features["unique_ports"]
    total_packets = features["total_packets"]
    duration      = features["duration"]
    pps           = features["pps"]
    port_counts   = features["port_counts"]

    # =========================
    # LOG EVERY PACKET
    # =========================
    log_event({
        "timestamp"    : str(datetime.now()),
        "source_ip"    : ip_src,
        "target_ip"    : ip_dst,
        "dport"        : dport,
        "unique_ports" : unique_ports,
        "total_packets": total_packets,
        "duration"     : duration,
        "pps"          : pps,
        "label"        : 0    # default normal — attacker sets to 1
    })

    # =========================
    # ANTI-SPAM
    # =========================
    last_alert = alerted_ips.get(ip_src, 0)
    if now - last_alert < ALERT_COOLDOWN:
        return

    # =========================
    # SYN FLOOD DETECTION
    # =========================
    for port, count in port_counts.items():
        rate = count / TIME_WINDOW
        if rate > SYN_FLOOD_RATE:
            severity = compute_severity_flood(rate)
            alert = {
                "timestamp"    : str(datetime.now()),
                "type"         : "SYN_FLOOD",
                "source_ip"    : ip_src,
                "target_ip"    : ip_dst,
                "port"         : port,
                "rate"         : round(rate, 2),
                "total_packets": total_packets,
                "severity"     : severity,
                "label"        : 1
            }
            print(f"🚨 ALERT [SYN_FLOOD] [{severity}] {ip_src} → {ip_dst}:{port} | rate: {rate:.2f} pps")
            log_event(alert)
            alerted_ips[ip_src] = now
            traffic_data[ip_src].clear()
            return

    # =========================
    # SYN SCAN DETECTION
    # =========================
    if unique_ports >= PORT_SCAN_THRESHOLD:
        severity = compute_severity_scan(unique_ports)
        alert = {
            "timestamp"    : str(datetime.now()),
            "type"         : "SYN_SCAN",
            "source_ip"    : ip_src,
            "target_ip"    : ip_dst,
            "unique_ports" : unique_ports,
            "total_packets": total_packets,
            "duration"     : duration,
            "pps"          : pps,
            "severity"     : severity,
            "label"        : 1
        }
        print(f"🚨 ALERT [SYN_SCAN] [{severity}] {ip_src} → {ip_dst} | ports: {unique_ports}")
        log_event(alert)
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
