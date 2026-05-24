from scapy.all import sniff, IP, TCP, Raw, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger   import Logger
from core.window   import clean_old, prune_stale
from ai.predict  import predict as ai_predict
from core.alerting import build_alert, severity_ftp
from core.persistence import state_ftp
from core.correlation import correlator

# =========================
# CONFIG
# =========================
TIME_WINDOW        = 10
ATTEMPT_THRESHOLD  = 10     # brute force threshold
ALERT_COOLDOWN     = 20
PRUNE_INTERVAL     = 60
WHITELIST          = {"127.0.0.1"}
IFACE              = None

# FTP bounce — PORT command pointing to a third-party IP
# is the core signal of an FTP bounce attack
BOUNCE_THRESHOLD   = 3      # nb of suspicious PORT commands to alert

# =========================
# STORAGE
# =========================
# brute force tracking — same pattern as bruteforce.py
attempts     = defaultdict(deque)   # ip → [(timestamp, flags)]

# bounce tracking — PORT commands per session
bounce_cmds  = defaultdict(deque)   # ip → [(timestamp, port_target_ip)]

alerted_ips  = {}
last_prune   = time.time()

# =========================
# LOGGER
# =========================
logger = Logger("data/ftp_dataset.jsonl")
state_ftp.register(attempts, bounce_cmds, alerted_ips)
state_ftp.restore()

# =========================
# PRIVATE IP CHECK
# =========================
def is_private(ip: str) -> bool:
    if ip.startswith(("192.168.", "10.")):
        return True
    parts = ip.split(".")
    if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
        return True
    return False

# =========================
# PORT COMMAND PARSER
# Extracts target IP from FTP PORT command payload
# PORT command format : PORT h1,h2,h3,h4,p1,p2
# where h1-h4 are IP octets and p1,p2 encode the port
# =========================
def parse_port_command(payload: str):
    """
    Returns (target_ip, target_port) or None if not a PORT command.

    Example payload : "PORT 192,168,1,50,0,21\r\n"
    Extracts ip     : "192.168.1.50"
    Extracts port   : 0*256 + 21 = 21
    """
    payload = payload.strip().upper()
    if not payload.startswith("PORT"):
        return None
    try:
        parts  = payload.split()[1].split(",")
        ip     = ".".join(parts[:4])
        port   = int(parts[4]) * 256 + int(parts[5])
        return ip, port
    except Exception:
        return None

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features_bruteforce(ip: str) -> dict:
    data = attempts[ip]
    if not data:
        return None

    times = [t for t, _ in data]
    flags = [f for _, f in data]

    duration     = max(times) - min(times) if len(times) > 1 else 0
    intervals    = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
    avg_interval = sum(intervals) / len(intervals) if intervals else 0

    syn_count = sum(1 for f in flags if "S" in f and "A" not in f)
    syn_ratio = syn_count / len(flags) if flags else 0

    return {
        "total_attempts" : len(data),
        "duration"       : round(duration, 3),
        "pps"            : round(len(data) / max(duration, 1), 3),
        "avg_interval"   : round(avg_interval, 4),
        "syn_ratio"      : round(syn_ratio, 3),
    }

def extract_features_bounce(ip: str) -> dict:
    data = bounce_cmds[ip]
    if not data:
        return None

    times      = [t  for t, _ in data]
    targets    = [tg for _, tg in data]
    duration   = max(times) - min(times) if len(times) > 1 else 0

    # third-party targets = IPs that are NOT the connecting client
    # and NOT private to the same subnet
    third_party = [t for t in targets if t != ip]

    return {
        "total_port_cmds"      : len(data),
        "third_party_targets"  : len(third_party),
        "unique_targets"       : len(set(targets)),
        "duration"             : round(duration, 3),
        "pps"                  : round(len(data) / max(duration, 1), 3),
    }

# =========================
# CLEAN OLD DATA
# =========================
def clean_all(ip: str, now: float):
    clean_old(attempts[ip],    now, TIME_WINDOW, ts_index=0)
    clean_old(bounce_cmds[ip], now, TIME_WINDOW, ts_index=0)

# =========================
# DETECTION ENGINE
# =========================
def detect(packet):
    global last_prune

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dport  = packet[TCP].dport
    sport  = packet[TCP].sport
    flags  = str(packet[TCP].flags)
    now    = time.time()

    if src_ip in WHITELIST:
        return
    if src_ip == dst_ip:
        return

    # =========================
    # PATH 1 — FTP BRUTE FORCE
    # connection attempts to port 21
    # =========================
    if dport == 21 and is_private(dst_ip):
        attempts[src_ip].append((now, flags))
        clean_old(attempts[src_ip], now, TIME_WINDOW, ts_index=0)
        state_ftp.maybe_save(now)

        if now - last_prune > PRUNE_INTERVAL:
            prune_stale(attempts, bounce_cmds, alerted_ips)
            last_prune = now

        features = extract_features_bruteforce(src_ip)
        if not features:
            return

        # AI prediction for brute force path
        # minimum 8 attempts before AI runs
        if features.get("total_attempts", 0) >= 8:
            ai_result = ai_predict("ftp", features)
            ai_alert  = ai_result["is_attack"]
            ai_conf   = ai_result["confidence"]
        else:
            ai_alert = False
            ai_conf  = 0.0

        logger.log({
            "timestamp"  : str(datetime.now()),
            "source_ip"  : src_ip,
            "target_ip"  : dst_ip,
            "attack_path": "brute_force",
            "label"      : 0,
            **features
        })

        last_alert = alerted_ips.get(src_ip, 0)
        if now - last_alert < ALERT_COOLDOWN:
            return

        total   = features["total_attempts"]
        syn_r   = features["syn_ratio"]
        pps     = features["pps"]

        if (total >= ATTEMPT_THRESHOLD and syn_r > 0.6) or ai_alert:
            alert = build_alert(
                alert_type = "FTP_BRUTE_FORCE",
                source_ip  = src_ip,
                target_ip  = dst_ip,
                severity   = severity_ftp("FTP_BRUTE_FORCE", pps, total),
                features   = features
            )
            
            detection = alert.get("detection", "RULE")
            icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
            print(f"{icon} [{detection}] [{alert['severity']}] [FTP_BRUTE_FORCE] {src_ip} → {dst_ip} | attempts: {total} | syn_ratio: {syn_r}")

            logger.log(alert)
            correlator.add_alert(src_ip, "FTP_BRUTE_FORCE", alert["severity"], dst_ip)
            alerted_ips[src_ip] = now

    # =========================
    # PATH 2 — FTP BOUNCE ATTACK
    # PORT commands sent to FTP server (sport=21 means
    # the FTP server is responding — we catch the client
    # sending PORT on an established FTP connection dport=21)
    # =========================
    if dport == 21 and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
        except Exception:
            return

        result = parse_port_command(payload)
        if not result:
            return

        target_ip, target_port = result

        # Bounce signal — PORT command pointing to a DIFFERENT machine
        # In a legitimate FTP transfer the PORT IP matches the client IP
        # In a bounce attack it points to a third party
        if target_ip != src_ip:
            bounce_cmds[src_ip].append((now, target_ip))
            clean_old(bounce_cmds[src_ip], now, TIME_WINDOW, ts_index=0)
            state_ftp.maybe_save(now)

            features = extract_features_bounce(src_ip)
            if not features:
                return

            # AI prediction for bounce path
            # minimum 3 PORT commands before AI runs
            if features.get("total_port_cmds", 0) >= 3:
                ai_result = ai_predict("ftp", features)
                ai_alert  = ai_result["is_attack"]
                ai_conf   = ai_result["confidence"]
            else:
                ai_alert = False
                ai_conf  = 0.0

            logger.log({
                "timestamp"     : str(datetime.now()),
                "source_ip"     : src_ip,
                "target_ip"     : dst_ip,
                "bounce_target" : target_ip,
                "bounce_port"   : target_port,
                "attack_path"   : "bounce",
                "label"         : 0,
                **features
            })

            last_alert = alerted_ips.get(src_ip, 0)
            if now - last_alert < ALERT_COOLDOWN:
                return

            if features["third_party_targets"] >= BOUNCE_THRESHOLD or ai_alert:
                alert = build_alert(
                    alert_type = "FTP_BOUNCE",
                    source_ip  = src_ip,
                    target_ip  = dst_ip,
                    severity   = severity_ftp("FTP_BOUNCE", features["pps"], features["total_port_cmds"]),
                    features   = features,
                    extra      = {
                        "bounce_target": target_ip,
                        "bounce_port"  : target_port
                    }
                )
                detection = alert.get("detection", "RULE")
                icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
                print(f"{icon} [{detection}] [{alert['severity']}] [FTP_BOUNCE] {src_ip} using FTP server to scan {target_ip}:{target_port} | PORT cmds: {features['total_port_cmds']}")
                logger.log(alert)
                correlator.add_alert(src_ip, "FTP_BOUNCE", alert["severity"], dst_ip)
                alerted_ips[src_ip] = now

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 FTP DETECTOR RUNNING on [{iface}]")
    print(f"   Detects: FTP_BRUTE_FORCE | FTP_BOUNCE")
    sniff(
        iface=iface,
        filter="tcp port 21",
        prn=detect,
        store=0
    )