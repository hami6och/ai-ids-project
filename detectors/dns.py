"""
detectors/dns.py — DNS Flood & Tunnel Detector
================================================
Detects :
    DNS_FLOOD      — high query rate from one source
    DNS_TUNNEL     — long encoded subdomains
    DNS_AI         — AI-only sub-threshold detection
    SLOW_DNS_FLOOD — slow flood over long window (lw_dns)
"""

from scapy.all import sniff, IP, IPv6, UDP, DNS, DNSQR, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger      import Logger
from core.window      import clean_old, prune_stale
from ai.predict       import predict as ai_predict
from core.alerting    import build_alert, severity_dns
from core.persistence import state_dns
from core.correlation import correlator
from core.long_window import lw_dns
from core.distributed import tracker as dist_tracker
from config import (
    AI_THRESHOLD_DNS,
    DNS_TIME_WINDOW, DNS_REQUEST_THRESHOLD, DNS_TUNNEL_QNAME_LEN,
    DNS_ALERT_COOLDOWN, DNS_PRUNE_INTERVAL, DNS_AI_MIN_REQUESTS,
    WHITELIST, IFACE
)

QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"
}


class DNSDetector:
    NAME = "dns"

    def __init__(self, alert_store=None):
        # state
        self.dns_requests = defaultdict(deque)   # ip → [(ts, qname, qtype)]
        self.alerted_ips  = {}
        self.last_prune   = time.time()

        # config
        self.time_window      = DNS_TIME_WINDOW
        self.request_threshold= DNS_REQUEST_THRESHOLD
        self.tunnel_qname_len = DNS_TUNNEL_QNAME_LEN
        self.alert_cooldown   = DNS_ALERT_COOLDOWN
        self.prune_interval   = DNS_PRUNE_INTERVAL
        self.ai_min_requests  = DNS_AI_MIN_REQUESTS
        self.ai_threshold     = AI_THRESHOLD_DNS

        # sub-components
        self.logger      = Logger("data/dns_logs.jsonl")
        self.alert_store = alert_store
        self._state      = state_dns
        self._state.register(self.dns_requests, self.alerted_ips)
        self._state.restore()

        # dashboard stats
        self.alert_count     = 0
        self.last_alert_time = None
        self.last_alert_type = None

    # =========================
    # FEATURE EXTRACTION
    # =========================
    def _extract_features(self, ip: str) -> dict | None:
        data = self.dns_requests[ip]
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

        type_counts = defaultdict(int)
        for qt in qtypes:
            type_counts[qt] += 1

        avg_qname_len = sum(len(q) for q in qnames) / len(qnames)

        interval_std = round(
            (sum((i - avg_interval)**2 for i in intervals) / max(len(intervals), 1)) ** 0.5, 4
        ) if intervals else 0.0

        return {
            "total_requests"        : len(data),
            "duration"              : round(duration, 3),
            "pps"                   : round(len(data) / max(duration, 1), 3),
            "avg_interval"          : round(avg_interval, 4),
            "interval_std"          : interval_std,
            "unique_domains"        : unique_domains,
            "domain_diversity_ratio": round(domain_diversity_ratio, 3),
            "top_domain"            : top_domain,
            "top_domain_ratio"      : round(top_domain_ratio, 3),
            "type_counts"           : dict(type_counts),
            "avg_qname_len"         : round(avg_qname_len, 2),
        }

    # =========================
    # DETECTION ENGINE
    # =========================
    def detect(self, packet):
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)) or not packet.haslayer(UDP):
            return
        if not packet.haslayer(DNS):
            return

        ip_src = (packet[IPv6].src if packet.haslayer(IPv6) else packet[IP].src)
        ip_dst = (packet[IPv6].dst if packet.haslayer(IPv6) else packet[IP].dst)
        now    = time.time()

        if ip_src in WHITELIST:
            return
        if packet[DNS].qr != 0:
            return
        if ip_dst.startswith(("224.", "239.", "255.")):
            return

        if packet.haslayer(DNSQR):
            qname     = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            qtype_str = QTYPE_MAP.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))
        else:
            qname     = "unknown"
            qtype_str = "unknown"

        self.dns_requests[ip_src].append((now, qname, qtype_str))
        clean_old(self.dns_requests[ip_src], now, self.time_window, ts_index=0)
        dist_tracker.add(ip_dst, ip_src, "DNS")
        lw_dns.add(ip_src, value=qname, now=now)
        self._state.maybe_save(now)

        if now - self.last_prune > self.prune_interval:
            prune_stale(self.dns_requests, self.alerted_ips)
            self.last_prune = now

        features = self._extract_features(ip_src)
        if not features:
            return

        if features["total_requests"] >= self.ai_min_requests:
            ai_result = ai_predict("dns", features, threshold=self.ai_threshold)
            ai_alert  = ai_result["is_attack"]
            ai_conf   = ai_result["confidence"]
        else:
            ai_alert = False
            ai_conf  = 0.0

        traffic_doc = {
            "timestamp" : str(datetime.now()),
            "detector"  : self.NAME,
            "source_ip" : ip_src,
            "target_ip" : ip_dst,
            "qname"     : qname,
            "qtype"     : qtype_str,
            "label"     : 0,
            **features
        }
        self.logger.log(traffic_doc)
        if self.alert_store:
            self.alert_store.insert_traffic(traffic_doc)

        # SLOW DNS FLOOD
        if lw_dns.should_alert(ip_src, now):
            summary = lw_dns.get_summary(ip_src)
            alert = build_alert(
                alert_type = "SLOW_DNS_FLOOD",
                source_ip  = ip_src,
                target_ip  = ip_dst,
                severity   = "LOW",
                features   = features,
                extra      = {**summary, "detection": "RULE"}
            )
            print(f"🐢 [SLOW] [SLOW_DNS_FLOOD] [LOW] {ip_src} → {ip_dst} | "
                  f"requests: {summary.get('unique_requests', 0)} in {summary.get('timespan_sec', 0)}s")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(ip_src, "SLOW_DNS_FLOOD", "LOW", ip_dst)
            self._record_alert("SLOW_DNS_FLOOD")
            self.alerted_ips[ip_src] = now
            lw_dns.clear(ip_src)

        last_alert = self.alerted_ips.get(ip_src, 0)
        if now - last_alert < self.alert_cooldown:
            return

        alert_type = None
        if features["avg_qname_len"] > self.tunnel_qname_len:
            alert_type = "DNS_TUNNEL"
        elif features["total_requests"] >= self.request_threshold:
            alert_type = "DNS_FLOOD"

        if not alert_type and ai_alert:
            alert_type = "DNS_AI"

        if alert_type:
            alert = build_alert(
                alert_type = alert_type,
                source_ip  = ip_src,
                target_ip  = ip_dst,
                severity   = severity_dns(features["total_requests"], features["pps"]),
                features   = features,
                extra      = {"ai_confidence": ai_conf,
                              "detection": "RULE+AI" if ai_alert else
                                           "AI_ONLY" if alert_type == "DNS_AI" else "RULE"}
            )
            detection = alert.get("detection", "RULE")
            icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
            print(f"{icon} [{detection}] [{alert['severity']}] [{alert_type}] {ip_src} → {ip_dst} | {features['total_requests']} req | pps: {features['pps']} | avg_len: {features['avg_qname_len']} | AI: {int(ai_conf*100)}%")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(ip_src, alert_type, alert["severity"], ip_dst)
            self._record_alert(alert_type)
            self.alerted_ips[ip_src] = now

    # =========================
    # DASHBOARD API
    # =========================
    def get_status(self) -> dict:
        return {
            "name"        : self.NAME,
            "enabled"     : True,
            "alert_count" : self.alert_count,
            "last_alert"  : self.last_alert_time,
            "last_type"   : self.last_alert_type,
            "active_ips"  : len(self.dns_requests),
            "config"      : self._get_config(),
        }

    def update_config(self, key: str, value) -> bool:
        if hasattr(self, key):
            setattr(self, key, value)
            return True
        return False

    def reset(self):
        self.dns_requests.clear()
        self.alerted_ips.clear()
        self.alert_count = 0
        self.last_alert_time = None
        self.last_alert_type = None

    def _record_alert(self, alert_type: str):
        self.alert_count    += 1
        self.last_alert_time = str(datetime.now())
        self.last_alert_type = alert_type

    def _get_config(self) -> dict:
        return {
            "request_threshold": self.request_threshold,
            "tunnel_qname_len" : self.tunnel_qname_len,
            "alert_cooldown"   : self.alert_cooldown,
            "ai_threshold"     : self.ai_threshold,
            "time_window"      : self.time_window,
        }

    @staticmethod
    def run():
        detector = DNSDetector()
        iface    = IFACE or conf.iface
        print(f"🚀 DNS FLOOD/TUNNEL DETECTION RUNNING on [{iface}]...")
        sniff(iface=iface, filter="udp port 53", prn=detector.detect, store=0)


if __name__ == "__main__":
    DNSDetector.run()