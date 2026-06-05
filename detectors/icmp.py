"""
detectors/icmp.py — ICMP Flood & Redirect Detector
====================================================
Detects :
    ICMP_FLOOD    — high ICMP echo request rate
    ICMP_REDIRECT — type=5 from non-gateway source
"""

from scapy.all import sniff, IP, IPv6, ICMP, ICMPv6EchoRequest, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger      import Logger
from core.window      import clean_old, prune_stale
from ai.predict       import predict as ai_predict
from core.alerting    import build_alert, severity_icmp
from core.persistence import state_icmp
from core.correlation import correlator
from core.distributed import tracker as dist_tracker
from config import (
    AI_THRESHOLD_ICMP,
    ICMP_TIME_WINDOW, ICMP_FLOOD_RATE, ICMP_ALERT_COOLDOWN,
    ICMP_PRUNE_INTERVAL, ICMP_AI_MIN_PACKETS,
    WHITELIST, KNOWN_GATEWAYS, ICMP_REDIRECT_COOLDOWN, IFACE
)


class ICMPDetector:
    NAME = "icmp"

    def __init__(self, alert_store=None):
        # state
        self.traffic_data     = defaultdict(deque)   # ip → [(timestamp, size)]
        self.redirect_alerted = {}
        self.alerted_ips      = {}
        self.last_prune       = time.time()

        # config
        self.time_window      = ICMP_TIME_WINDOW
        self.flood_rate       = ICMP_FLOOD_RATE
        self.alert_cooldown   = ICMP_ALERT_COOLDOWN
        self.prune_interval   = ICMP_PRUNE_INTERVAL
        self.ai_min_packets   = ICMP_AI_MIN_PACKETS
        self.ai_threshold     = AI_THRESHOLD_ICMP
        self.known_gateways   = set(KNOWN_GATEWAYS)
        self.redirect_cooldown= ICMP_REDIRECT_COOLDOWN

        # sub-components
        self.logger      = Logger("data/icmp_dataset.jsonl")
        self.alert_store = alert_store
        self._state      = state_icmp
        self._state.register(self.traffic_data, self.alerted_ips)
        self._state.restore()

        # dashboard stats
        self.alert_count     = 0
        self.last_alert_time = None
        self.last_alert_type = None

    # =========================
    # FEATURE EXTRACTION
    # =========================
    def _extract_features(self, ip: str) -> dict | None:
        data = self.traffic_data[ip]
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
    def detect(self, packet):
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return
        if not packet.haslayer(ICMP) and not packet.haslayer(ICMPv6EchoRequest):
            return

        ip_src = (packet[IPv6].src if packet.haslayer(IPv6) else packet[IP].src)
        ip_dst = (packet[IPv6].dst if packet.haslayer(IPv6) else packet[IP].dst)
        now    = time.time()

        if ip_src in WHITELIST:
            return

        # ICMP REDIRECT — check before type=8 filter
        if packet.haslayer(ICMP) and packet[ICMP].type == 5:
            if ip_src not in self.known_gateways:
                last_redirect = self.redirect_alerted.get(ip_src, 0)
                if now - last_redirect > self.redirect_cooldown:
                    try:
                        redirect_gw = packet[ICMP].gw if hasattr(packet[ICMP], 'gw') else "unknown"
                    except Exception:
                        redirect_gw = "unknown"
                    alert = build_alert(
                        alert_type = "ICMP_REDIRECT",
                        source_ip  = ip_src,
                        target_ip  = ip_dst,
                        severity   = "HIGH",
                        features   = {"redirect_gateway": str(redirect_gw)},
                        extra      = {"redirect_gw": str(redirect_gw),
                                      "known_gws": list(self.known_gateways),
                                      "detection": "RULE"},
                        detector   = self.NAME          # ← AJOUTÉ
                    )
                    print(f"🚨 [RULE] [ICMP_REDIRECT] [HIGH] {ip_src} → {ip_dst} "
                          f"| redirecting via: {redirect_gw}")
                    self.logger.log(alert)
                    if self.alert_store:
                        self.alert_store.insert(alert)
                    correlator.add_alert(ip_src, "ICMP_REDIRECT", "HIGH", ip_dst)
                    self._record_alert("ICMP_REDIRECT")
                    self.redirect_alerted[ip_src] = now
            return

        # FLOOD — echo requests only
        is_ipv4 = packet.haslayer(ICMP) and packet[ICMP].type == 8
        is_ipv6 = packet.haslayer(ICMPv6EchoRequest)
        if not (is_ipv4 or is_ipv6):
            return

        self.traffic_data[ip_src].append((now, len(packet)))
        clean_old(self.traffic_data[ip_src], now, self.time_window, ts_index=0)
        dist_tracker.add(ip_dst, ip_src, "ICMP")
        self._state.maybe_save(now)

        if now - self.last_prune > self.prune_interval:
            prune_stale(self.traffic_data, self.alerted_ips)
            self.last_prune = now

        features = self._extract_features(ip_src)
        if not features:
            return

        pps           = features["pps"]
        total_packets = features["total_packets"]

        if total_packets >= self.ai_min_packets:
            ai_result = ai_predict("icmp", features, threshold=self.ai_threshold)
            ai_alert  = ai_result["is_attack"]
            ai_conf   = ai_result["confidence"]
        else:
            ai_alert = False
            ai_conf  = 0.0

        traffic_doc = {
            "timestamp"      : str(datetime.now()),
            "detector"       : self.NAME,
            "source_ip"      : ip_src,
            "target_ip"      : ip_dst,
            "total_packets"  : total_packets,
            "duration"       : features["duration"],
            "pps"            : pps,
            "avg_packet_size": features["avg_packet_size"],
            "max_packet_size": features["max_packet_size"],
            "label"          : 0
        }
        self.logger.log(traffic_doc)
        if self.alert_store:
            self.alert_store.insert_traffic(traffic_doc)

        last_alert = self.alerted_ips.get(ip_src, 0)
        if now - last_alert < self.alert_cooldown:
            return

        if pps > self.flood_rate or ai_alert:
            alert = build_alert(
                alert_type = "ICMP_FLOOD",
                source_ip  = ip_src,
                target_ip  = ip_dst,
                severity   = severity_icmp(pps, self.flood_rate),
                features   = features,
                extra      = {"ai_confidence": ai_conf,
                              "detection": "RULE+AI" if (pps > self.flood_rate and ai_alert)
                                           else "AI_ONLY" if ai_alert else "RULE"},
                detector   = self.NAME          # ← AJOUTÉ
            )
            detection = alert.get("detection", "RULE")
            icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
            print(f"{icon} [{detection}] [ICMP_FLOOD] [{alert['severity']}] {ip_src} → {ip_dst} | pps: {pps:.2f} | AI: {int(ai_conf*100)}%")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(ip_src, "ICMP_FLOOD", alert["severity"], ip_dst)
            self._record_alert("ICMP_FLOOD")
            self.alerted_ips[ip_src] = now
            self.traffic_data[ip_src].clear()

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
            "active_ips"  : len(self.traffic_data),
            "config"      : self._get_config(),
        }

    def update_config(self, key: str, value) -> bool:
        if hasattr(self, key):
            setattr(self, key, value)
            return True
        return False

    def reset(self):
        self.traffic_data.clear()
        self.alerted_ips.clear()
        self.redirect_alerted.clear()
        self.alert_count = 0
        self.last_alert_time = None
        self.last_alert_type = None

    def _record_alert(self, alert_type: str):
        self.alert_count    += 1
        self.last_alert_time = str(datetime.now())
        self.last_alert_type = alert_type

    def _get_config(self) -> dict:
        return {
            "flood_rate"    : self.flood_rate,
            "alert_cooldown": self.alert_cooldown,
            "ai_threshold"  : self.ai_threshold,
            "time_window"   : self.time_window,
        }

    @staticmethod
    def run():
        detector = ICMPDetector()
        iface    = IFACE or conf.iface
        print(f"🚀 ICMP FLOOD DETECTION RUNNING on [{iface}]...")
        sniff(iface=iface, filter="icmp", prn=detector.detect, store=0)


if __name__ == "__main__":
    ICMPDetector.run()