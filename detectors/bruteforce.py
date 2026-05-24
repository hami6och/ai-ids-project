from scapy.all import sniff, IP, IPv6, TCP, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger   import Logger
from core.window   import clean_old, prune_stale
from ai.predict  import predict as ai_predict
from core.alerting import build_alert, severity_bruteforce
from core.persistence import state_bruteforce
from config import (
    MULTI_SOURCE_WINDOW, MULTI_SOURCE_THRESHOLD, MULTI_SOURCE_COOLDOWN,
    BRUTE_TIME_WINDOW as TIME_WINDOW,
    BRUTE_ATTEMPT_THRESHOLD as ATTEMPT_THRESHOLD,
    BRUTE_ALERT_COOLDOWN as ALERT_COOLDOWN,
    BRUTE_PRUNE_INTERVAL as PRUNE_INTERVAL,
    BRUTE_TARGET_PORTS as TARGET_PORTS,
    BRUTE_AI_MIN_ATTEMPTS,
    WHITELIST,
    IFACE
)
from core.correlation import correlator
from core.long_window  import lw_brute
from core.distributed import tracker as dist_tracker

# =========================
# CONFIG
# =========================

# =========================
# STORAGE
# =========================
attempts    = defaultdict(deque)   # ip → [(port, timestamp, flags)]
# per-destination-port tracking — catches MAC-rotating brute force
# key = (dst_ip, dst_port), value = deque of (timestamp, src_ip)
dst_port_sources = defaultdict(deque)
dst_port_alerted = {}    # (dst_ip, dst_port) → last alert timestamp
alerted_ips = {}
last_prune  = time.time()

# =========================
# LOGGER
# =========================
logger = Logger("data/bruteforce_logs.jsonl")
state_bruteforce.register(attempts, alerted_ips)
state_bruteforce.restore()

# =========================
# PRIVATE IP CHECK
# =========================
def is_private(ip):
    if ip.startswith(("192.168.", "10.")):
        return True
    parts = ip.split(".")
    if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
        return True
    return False

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(ip):
    data = attempts[ip]
    if not data:
        return None

    ports = [p for p, _, _ in data]
    times = [t for _, t, _ in data]
    flags = [f for _, _, f in data]

    duration     = max(times) - min(times) if len(times) > 1 else 0
    intervals    = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
    avg_interval = sum(intervals) / len(intervals) if intervals else 0

    port_counts      = defaultdict(int)
    for p in ports:
        port_counts[p] += 1
    max_port         = max(port_counts.values())
    port_focus_ratio = max_port / len(ports)

    syn_count = sum(1 for f in flags if "S" in f and "A" not in f)
    syn_ratio = syn_count / len(flags)

    # interval regularity — machine tools send at fixed intervals
    interval_std = round(
        (sum((i - avg_interval)**2 for i in intervals) / max(len(intervals), 1)) ** 0.5, 4
    ) if intervals else 0.0

    return {
        "total_attempts"  : len(data),
        "unique_ports"    : len(set(ports)),
        "duration"        : round(duration, 3),
        "pps"             : round(len(data) / max(duration, 1), 3),
        "avg_interval"    : round(avg_interval, 4),
        "interval_std"    : interval_std,
        "port_focus_ratio": round(port_focus_ratio, 3),
        "syn_ratio"       : round(syn_ratio, 3),
        "port_counts"     : dict(port_counts)
    }

# =========================
# DETECTION ENGINE
# =========================
def detect(packet):
    global last_prune

    if not (packet.haslayer(IP) or packet.haslayer(IPv6)) or not packet.haslayer(TCP):
        return

    src_ip = (packet[IPv6].src if packet.haslayer(IPv6) else packet[IP].src)
    dst_ip = (packet[IPv6].dst if packet.haslayer(IPv6) else packet[IP].dst)
    dport  = packet[TCP].dport
    flags  = str(packet[TCP].flags)
    now    = time.time()

    if src_ip in WHITELIST:
        return
    if src_ip == dst_ip:
        return
    if not is_private(dst_ip):
        return
    if dport not in TARGET_PORTS:
        return

    attempts[src_ip].append((dport, now, flags))
    clean_old(attempts[src_ip], now, TIME_WINDOW, ts_index=1)

    # track per-destination-port sources for MAC-spoof detection
    dst_key = (dst_ip, dport)
    dst_port_sources[dst_key].append((now, src_ip))
    # evict old entries
    dq_dst = dst_port_sources[dst_key]
    while dq_dst and now - dq_dst[0][0] > MULTI_SOURCE_WINDOW:
        dq_dst.popleft()
    dist_tracker.add(dst_ip, src_ip, "BRUTE")
    lw_brute.add(src_ip, value=(dport, now), now=now)
    state_bruteforce.maybe_save(now)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(attempts, alerted_ips)
        last_prune = now

    features = extract_features(src_ip)
    if not features:
        return

    # =========================
    # AI PREDICTION
    # minimum 8 attempts required before AI runs
    # fewer attempts may just be normal connection behavior
    # =========================
    if features.get("total_attempts", 0) >= BRUTE_AI_MIN_ATTEMPTS:
        ai_result = ai_predict("bruteforce", features)
        ai_alert  = ai_result["is_attack"]
        ai_conf   = ai_result["confidence"]
    else:
        ai_alert = False
        ai_conf  = 0.0

    total_attempts   = features["total_attempts"]
    unique_ports     = features["unique_ports"]
    port_focus_ratio = features["port_focus_ratio"]

    logger.log({
        "timestamp" : str(datetime.now()),
        "source_ip" : src_ip,
        "target_ip" : dst_ip,
        "dport"     : dport,
        "flags"     : flags,
        "label"     : 0,
        **features
    })

    # MULTI-SOURCE BRUTE FORCE — MAC spoofing evasion detection
    dst_key         = (dst_ip, dport)
    dq_dst          = dst_port_sources.get(dst_key, deque())
    unique_sources  = len({src for _, src in dq_dst})
    last_dst_alert  = dst_port_alerted.get(dst_key, 0)

    if unique_sources >= MULTI_SOURCE_THRESHOLD and        now - last_dst_alert > MULTI_SOURCE_COOLDOWN:

        sample_sources = list({src for _, src in dq_dst})[:5]
        alert = build_alert(
            alert_type = "MULTI_SOURCE_BRUTE",
            source_ip  = src_ip,
            target_ip  = dst_ip,
            severity   = "HIGH",
            features   = features,
            extra      = {
                "target_port"    : dport,
                "unique_sources" : unique_sources,
                "sample_sources" : sample_sources,
                "window_sec"     : MULTI_SOURCE_WINDOW,
                "detection"      : "RULE"
            }
        )
        print(f"🚨 [RULE] [MULTI_SOURCE_BRUTE] [HIGH] {unique_sources} sources → "
              f"{dst_ip}:{dport} | sample: {sample_sources[:3]}")
        logger.log(alert)
        correlator.add_alert(src_ip, "MULTI_SOURCE_BRUTE", "HIGH", dst_ip)
        dst_port_alerted[dst_key] = now

    # SLOW BRUTE FORCE — long window check
    if lw_brute.should_alert(src_ip, now):
        summary = lw_brute.get_summary(src_ip)
        alert = build_alert(
            alert_type = "SLOW_BRUTE_FORCE",
            source_ip  = src_ip,
            target_ip  = dst_ip,
            severity   = "MEDIUM",
            features   = features,
            extra      = {**summary, "detection": "RULE"}
        )
        print(f"🐢 [SLOW] [SLOW_BRUTE_FORCE] [MEDIUM] {src_ip} → {dst_ip} | "
              f"attempts: {summary.get('unique_attempts', 0)} in {summary.get('timespan_sec', 0)}s")
        logger.log(alert)
        correlator.add_alert(src_ip, "SLOW_BRUTE_FORCE", "MEDIUM", dst_ip)
        alerted_ips[src_ip] = now
        lw_brute.clear(src_ip)

    last_alert = alerted_ips.get(src_ip, 0)
    if now - last_alert < ALERT_COOLDOWN:
        return

    alert_type = None
    if total_attempts >= ATTEMPT_THRESHOLD and unique_ports <= 2 and features["syn_ratio"] > 0.6:
        alert_type = "BRUTE_FORCE"
    elif total_attempts >= 20 and port_focus_ratio < 0.4:
        alert_type = "CREDENTIAL_STUFFING"

    if not alert_type and ai_alert:
        alert_type = "BRUTE_FORCE_AI"

    if alert_type:
        alert = build_alert(
            alert_type = alert_type,
            source_ip  = src_ip,
            target_ip  = dst_ip,
            severity   = severity_bruteforce(total_attempts),
            features   = features,
            extra      = {"ai_confidence": ai_conf,
                          "detection": "RULE+AI" if ai_alert else
                                       "AI_ONLY" if "AI" in alert_type else "RULE"}
        )
        detection = alert.get("detection", "RULE")
        icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
        print(f"{icon} [{detection}] [{alert['severity']}] [{alert_type}] {src_ip} → {dst_ip} | attempts: {total_attempts} | ports: {unique_ports} | focus: {port_focus_ratio}")
        logger.log(alert)
        correlator.add_alert(src_ip, alert_type, alert["severity"], dst_ip)
        alerted_ips[src_ip] = now

# =========================
# START
# =========================
if __name__ == "__main__":
    port_filter = " or ".join(f"dst port {p}" for p in TARGET_PORTS)
    bpf_filter  = f"tcp and ({port_filter})"
    iface       = IFACE or conf.iface
    print(f"🚀 BRUTE FORCE DETECTOR RUNNING on [{iface}]")
    print(f"   Filter: {bpf_filter}")
    sniff(
        iface=iface,
        filter=bpf_filter,
        prn=detect,
        store=0
    )