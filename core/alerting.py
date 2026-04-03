from datetime import datetime


# =========================
# ALERT BUILDER
# =========================
def build_alert(alert_type: str, source_ip: str, target_ip: str,
                severity: str, features: dict, extra: dict = None) -> dict:
    """
    Build a standardized alert dict.
    `features` is spread in so every feature is a top-level key.
    `extra` is for detector-specific fields (e.g. port, mac, score).

    Usage:
        alert = build_alert(
            alert_type = "SYN_FLOOD",
            source_ip  = ip_src,
            target_ip  = ip_dst,
            severity   = "HIGH",
            features   = features,
            extra      = {"port": port, "rate": rate}
        )
    """
    alert = {
        "timestamp" : str(datetime.now()),
        "type"      : alert_type,
        "source_ip" : source_ip,
        "target_ip" : target_ip,
        "severity"  : severity,
        "label"     : 1,
        **features
    }
    if extra:
        alert.update(extra)
    return alert


# =========================
# SEVERITY — per detector
# =========================
def severity_syn_flood(rate: float) -> str:
    if rate > 40: return "CRITICAL"
    if rate > 20: return "HIGH"
    return "MEDIUM"

def severity_syn_scan(unique_ports: int) -> str:
    if unique_ports > 50: return "CRITICAL"
    if unique_ports > 20: return "HIGH"
    if unique_ports > 10: return "MEDIUM"
    return "LOW"

def severity_arp(score: int) -> str:
    if score >= 9: return "HIGH"
    if score >= 6: return "MEDIUM"
    return "LOW"

def severity_icmp(pps: float, flood_rate: float) -> str:
    if pps > flood_rate * 4: return "CRITICAL"
    if pps > flood_rate * 2: return "HIGH"
    if pps > flood_rate:     return "MEDIUM"
    return "LOW"

def severity_dns(total: int, pps: float) -> str:
    if total > 100 or pps > 30: return "CRITICAL"
    if total > 50  or pps > 15: return "HIGH"
    if total > 30  or pps > 8:  return "MEDIUM"
    return "LOW"

def severity_bruteforce(total_attempts: int) -> str:
    if total_attempts > 100: return "CRITICAL"
    if total_attempts > 40:  return "HIGH"
    if total_attempts > 20:  return "MEDIUM"
    return "LOW"