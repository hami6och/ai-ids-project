from scapy.all import sniff, Ether, IP, UDP, BOOTP, DHCP, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger   import Logger
from core.window   import clean_old, prune_stale
from ai.predict  import predict as ai_predict
from core.alerting import build_alert, severity_dhcp
from core.persistence import state_dhcp
from core.correlation import correlator

# =========================
# CONFIG
# =========================
TIME_WINDOW            = 10
ALERT_COOLDOWN         = 20
PRUNE_INTERVAL         = 60
IFACE                  = None

# Starvation thresholds
STARVATION_PPS         = 10     # DISCOVER packets/sec
STARVATION_MAC_COUNT   = 20     # unique MACs in window

# Rogue server — known legitimate DHCP server IPs on your network
# IMPORTANT : set this to your actual DHCP server IP before deploying
LEGITIMATE_DHCP_SERVERS = {
    "192.168.1.1", "192.168.1.254",
    "10.0.0.1",
    "192.168.68.1", "192.168.68.2", "192.168.68.254"   # your lab DHCP servers
}

# Anomaly detection thresholds
REPEATED_DECLINE_THRESHOLD  = 5   # DHCP DECLINEs from same MAC = conflict attack
RAPID_RELEASE_THRESHOLD     = 8   # rapid RELEASE+DISCOVER cycles = starvation variant
OFFER_RATIO_THRESHOLD       = 0.3 # unexpected OFFERs ratio = rogue server signal

# =========================
# STORAGE
# =========================
# per-MAC tracking
mac_requests   = defaultdict(deque)    # mac → [(timestamp, msg_type)]
mac_declines   = defaultdict(deque)    # mac → [timestamp]  DHCP DECLINE msgs
mac_releases   = defaultdict(deque)    # mac → [timestamp]  DHCP RELEASE msgs

# per-IP tracking (for rogue server detection)
server_offers  = defaultdict(deque)    # server_ip → [timestamp]
server_seen    = {}                    # server_ip → first_seen timestamp

# network-wide tracking
all_macs_seen  = defaultdict(set)      # window_key → set of MACs
alerted_macs   = {}                    # mac → last alert timestamp
alerted_ips    = {}                    # ip → last alert timestamp
last_prune     = time.time()

# DHCP message type codes
DHCP_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM"
}

# =========================
# LOGGER
# =========================
logger = Logger("data/dhcp_dataset.jsonl")
state_dhcp.register(mac_requests, mac_declines, mac_releases, server_seen, alerted_macs, alerted_ips)
state_dhcp.restore()

# =========================
# DHCP MESSAGE TYPE EXTRACTOR
# =========================
def get_dhcp_type(packet) -> int:
    """Extract DHCP message type from packet options."""
    if not packet.haslayer(DHCP):
        return 0
    for opt in packet[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            return opt[1]
    return 0

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(mac: str, src_ip: str, msg_type: int, now: float) -> dict:
    req_data  = mac_requests[mac]
    dec_data  = mac_declines[mac]
    rel_data  = mac_releases[mac]

    if not req_data:
        return None

    times    = [t for t, _ in req_data]
    types    = [tp for _, tp in req_data]
    duration = max(times) - min(times) if len(times) > 1 else 0

    type_counts = defaultdict(int)
    for tp in types:
        type_counts[DHCP_TYPES.get(tp, str(tp))] += 1

    # discover ratio — high ratio = starvation
    discover_count = type_counts.get("DISCOVER", 0)
    discover_ratio = discover_count / len(types) if types else 0

    # decline ratio — high ratio = conflict injection attack
    decline_count  = len(dec_data)

    # release count — rapid release/discover cycling
    release_count  = len(rel_data)

    # intervals between messages
    intervals    = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
    avg_interval = sum(intervals) / len(intervals) if intervals else 0

    return {
        "total_messages"  : len(req_data),
        "duration"        : round(duration, 3),
        "pps"             : round(len(req_data) / max(duration, 1), 3),
        "avg_interval"    : round(avg_interval, 4),
        "discover_count"  : discover_count,
        "discover_ratio"  : round(discover_ratio, 3),
        "decline_count"   : decline_count,
        "release_count"   : release_count,
        "type_counts"     : dict(type_counts),
    }

# =========================
# NETWORK-WIDE MAC COUNT
# How many unique MACs are requesting in this window?
# Starvation floods with spoofed MACs so this count spikes
# =========================
def get_network_mac_count(now: float) -> int:
    """Count unique MACs seen across the entire network in TIME_WINDOW."""
    window_key = int(now / TIME_WINDOW)
    return len(all_macs_seen.get(window_key, set()))

# =========================
# CLEAN OLD DATA
# =========================
def clean_all(mac: str, now: float):
    clean_old(mac_requests[mac],  now, TIME_WINDOW, ts_index=0)
    clean_old(mac_declines[mac],  now, TIME_WINDOW, ts_index=None)
    clean_old(mac_releases[mac],  now, TIME_WINDOW, ts_index=None)

# =========================
# PRUNE
# =========================
def prune_all(now: float):
    prune_stale(mac_requests,  mac_declines, mac_releases, alerted_macs)
    prune_stale(server_offers, alerted_ips)

    # clean old window keys from all_macs_seen
    current_window = int(now / TIME_WINDOW)
    stale_keys = [k for k in all_macs_seen if k < current_window - 1]
    for k in stale_keys:
        del all_macs_seen[k]

# =========================
# DETECTION ENGINE
# =========================
def detect(packet):
    global last_prune

    if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
        return

    now      = time.time()
    msg_type = get_dhcp_type(packet)
    if msg_type == 0:
        return

    # extract MAC from Ethernet layer (more reliable than BOOTP chaddr)
    src_mac  = packet[Ether].src if packet.haslayer(Ether) else "unknown"
    src_ip   = packet[IP].src   if packet.haslayer(IP)    else "0.0.0.0"
    type_str = DHCP_TYPES.get(msg_type, str(msg_type))

    # =========================
    # STORE
    # =========================
    mac_requests[src_mac].append((now, msg_type))

    if msg_type == 4:   # DECLINE
        mac_declines[src_mac].append(now)
    if msg_type == 7:   # RELEASE
        mac_releases[src_mac].append(now)

    # track MAC in network-wide window
    window_key = int(now / TIME_WINDOW)
    all_macs_seen[window_key].add(src_mac)

    # track OFFER senders for rogue server detection
    if msg_type == 2:   # OFFER
        server_offers[src_ip].append(now)
        if src_ip not in server_seen:
            server_seen[src_ip] = now
        clean_old(server_offers[src_ip], now, TIME_WINDOW, ts_index=None)

    clean_all(src_mac, now)
    state_dhcp.maybe_save(now)

    if now - last_prune > PRUNE_INTERVAL:
        prune_all(now)
        last_prune = now

    features = extract_features(src_mac, src_ip, msg_type, now)
    if not features:
        return

    # =========================
    # AI PREDICTION
    # runs alongside rule-based, either can trigger alert
    # =========================
    ai_result = ai_predict("dhcp", features)
    ai_alert  = ai_result["is_attack"]
    ai_conf   = ai_result["confidence"]

    network_mac_count = get_network_mac_count(now)

    # =========================
    # LOG EVERY PACKET
    # =========================
    logger.log({
        "timestamp"        : str(datetime.now()),
        "src_mac"          : src_mac,
        "src_ip"           : src_ip,
        "msg_type"         : type_str,
        "network_mac_count": network_mac_count,
        "label"            : 0,
        **features
    })

    # =========================
    # DETECTION LOGIC
    # =========================

    # ── AI CHECK — fires if any rule or AI flags it ─────────
    if ai_alert and now - alerted_macs.get(src_mac, 0) > ALERT_COOLDOWN:
        alert = build_alert(
            alert_type = "DHCP_AI",
            source_ip  = src_ip,
            target_ip  = "255.255.255.255",
            severity   = "MEDIUM",
            features   = features,
            extra      = {"src_mac": src_mac, "ai_confidence": ai_conf,
                          "detection": "AI_ONLY"}
        )
        print(f"🤖 AI ALERT [DHCP_AI] {src_mac} | confidence: {ai_conf:.0%}")
        logger.log(alert)
        alerted_macs[src_mac] = now

    # ── Rule 1 : DHCP STARVATION ──────────────────────────
    # Classic starvation : flood of DISCOVERs with spoofed MACs
    # We check BOTH per-MAC rate AND network-wide unique MAC count
    # because starvation uses different source MACs each time
    last_alert_mac = alerted_macs.get(src_mac, 0)

    pps            = features["pps"]
    discover_ratio = features["discover_ratio"]
    total          = features["total_messages"]

    starvation_per_mac     = (pps > STARVATION_PPS and discover_ratio > 0.8)
    starvation_network     = (network_mac_count > STARVATION_MAC_COUNT)

    if (starvation_per_mac or starvation_network) and \
       now - last_alert_mac > ALERT_COOLDOWN:

        severity = severity_dhcp("DHCP_STARVATION", pps, network_mac_count)
        alert    = build_alert(
            alert_type = "DHCP_STARVATION",
            source_ip  = src_ip,
            target_ip  = "255.255.255.255",
            severity   = severity,
            features   = features,
            extra      = {
                "src_mac"          : src_mac,
                "network_mac_count": network_mac_count,
                "trigger"          : "per_mac" if starvation_per_mac else "network_wide"
            }
        )
        detection = alert.get("detection", "RULE")
        icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
        print(f"{icon} [{detection}] [{severity}] [DHCP_STARVATION] {src_mac} | pps: {pps:.2f} | network MACs: {network_mac_count}")
        logger.log(alert)
        correlator.add_alert(src_ip, "DHCP_STARVATION", alert["severity"])
        alerted_macs[src_mac] = now

    # ── Rule 2 : DHCP ROGUE SERVER ────────────────────────
    # Any IP sending DHCP OFFERs that is NOT in our known server list
    # is a rogue server — this is always CRITICAL
    if msg_type == 2 and src_ip not in LEGITIMATE_DHCP_SERVERS:
        last_alert_ip = alerted_ips.get(src_ip, 0)
        if now - last_alert_ip > ALERT_COOLDOWN:
            offer_count = len(server_offers[src_ip])
            alert = build_alert(
                alert_type = "DHCP_ROGUE_SERVER",
                source_ip  = src_ip,
                target_ip  = "255.255.255.255",
                severity   = "CRITICAL",
                features   = features,
                extra      = {
                    "src_mac"    : src_mac,
                    "offer_count": offer_count,
                    "first_seen" : str(datetime.fromtimestamp(server_seen.get(src_ip, now)))
                }
            )
            detection = alert.get("detection", "RULE")
            icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
            print(f"{icon} [{detection}] [CRITICAL] [DHCP_ROGUE_SERVER] Unknown server {src_ip} ({src_mac}) sending OFFERs | offers: {offer_count}")
            logger.log(alert)
            correlator.add_alert(src_ip, "DHCP_ROGUE_SERVER", "CRITICAL")
            alerted_ips[src_ip] = now

    # ── Rule 3 : DHCP DECLINE FLOOD (conflict injection) ──
    # Attacker sends repeated DECLINEs to exhaust IP pool
    # by making the server think IPs are already in use
    decline_count = features["decline_count"]
    if decline_count >= REPEATED_DECLINE_THRESHOLD and \
       now - last_alert_mac > ALERT_COOLDOWN:

        alert = build_alert(
            alert_type = "DHCP_DECLINE_FLOOD",
            source_ip  = src_ip,
            target_ip  = "255.255.255.255",
            severity   = severity_dhcp("DHCP_DECLINE_FLOOD", pps, network_mac_count),
            features   = features,
            extra      = {"src_mac": src_mac, "decline_count": decline_count}
        )
        detection = alert.get("detection", "RULE")
        icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
        print(f"{icon} [{detection}] [{alert['severity']}] [DHCP_DECLINE_FLOOD] {src_mac} | declines: {decline_count}")
        logger.log(alert)
        alerted_macs[src_mac] = now

    # ── Rule 4 : RAPID RELEASE/DISCOVER CYCLING ───────────
    # Starvation variant — attacker rapidly releases then re-requests
    # to cycle through IP allocations and exhaust the pool more subtly
    release_count = features["release_count"]
    discover_count = features["discover_count"]
    if release_count >= RAPID_RELEASE_THRESHOLD and \
       discover_count >= RAPID_RELEASE_THRESHOLD and \
       now - last_alert_mac > ALERT_COOLDOWN:

        alert = build_alert(
            alert_type = "DHCP_RAPID_CYCLING",
            source_ip  = src_ip,
            target_ip  = "255.255.255.255",
            severity   = severity_dhcp("DHCP_RAPID_CYCLING", pps, network_mac_count),
            features   = features,
            extra      = {
                "src_mac"      : src_mac,
                "release_count": release_count,
                "discover_count": discover_count
            }
        )
        detection = alert.get("detection", "RULE")
        icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
        print(f"{icon} [{detection}] [{alert['severity']}] [DHCP_RAPID_CYCLING] {src_mac} | releases: {release_count} discovers: {discover_count}")
        logger.log(alert)
        alerted_macs[src_mac] = now

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 DHCP DETECTOR RUNNING on [{iface}]")
    print(f"   Legitimate servers : {LEGITIMATE_DHCP_SERVERS}")
    print(f"   Detects : STARVATION | ROGUE_SERVER | DECLINE_FLOOD | RAPID_CYCLING")
    sniff(
        iface=iface,
        filter="udp and (port 67 or port 68)",
        prn=detect,
        store=0
    )