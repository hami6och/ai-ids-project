"""
detectors/dhcp.py — DHCP Attack Detector
==========================================
Detects :
    DHCP_STARVATION   — flood of DISCOVERs with spoofed MACs
    DHCP_ROGUE_SERVER — OFFERs from unknown server IP
    DHCP_DECLINE_FLOOD— repeated DECLINEs (conflict injection)
    DHCP_RAPID_CYCLING— rapid RELEASE+DISCOVER cycling
"""

from scapy.all import sniff, Ether, IP, UDP, BOOTP, DHCP, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger      import Logger
from core.window      import clean_old, prune_stale
from ai.predict       import predict as ai_predict
from core.alerting    import build_alert, severity_dhcp
from core.persistence import state_dhcp
from core.correlation import correlator
from config import (
    AI_THRESHOLD_DHCP,
    DHCP_TIME_WINDOW, DHCP_ALERT_COOLDOWN, DHCP_PRUNE_INTERVAL,
    DHCP_STARVATION_PPS, DHCP_STARVATION_MACS,
    DHCP_DECLINE_THRESHOLD, DHCP_RELEASE_THRESHOLD,
    DHCP_LEGITIMATE_SERVERS, IFACE
)

DHCP_TYPES = {
    1: "DISCOVER", 2: "OFFER",   3: "REQUEST",
    4: "DECLINE",  5: "ACK",     6: "NAK",
    7: "RELEASE",  8: "INFORM"
}


class DHCPDetector:
    NAME = "dhcp"

    def __init__(self, alert_store=None):
        # state
        self.mac_requests  = defaultdict(deque)   # mac → [(ts, msg_type)]
        self.mac_declines  = defaultdict(deque)   # mac → [ts]
        self.mac_releases  = defaultdict(deque)   # mac → [ts]
        self.server_offers = defaultdict(deque)   # server_ip → [ts]
        self.server_seen   = {}
        self.all_macs_seen = defaultdict(set)     # window_key → set of MACs
        self.alerted_macs  = {}
        self.alerted_ips   = {}
        self.last_prune    = time.time()

        # config
        self.time_window                = DHCP_TIME_WINDOW
        self.alert_cooldown             = DHCP_ALERT_COOLDOWN
        self.prune_interval             = DHCP_PRUNE_INTERVAL
        self.starvation_pps             = DHCP_STARVATION_PPS
        self.starvation_mac_count       = DHCP_STARVATION_MACS
        self.repeated_decline_threshold = DHCP_DECLINE_THRESHOLD
        self.rapid_release_threshold    = DHCP_RELEASE_THRESHOLD
        self.legitimate_servers         = set(DHCP_LEGITIMATE_SERVERS)
        self.ai_threshold               = AI_THRESHOLD_DHCP

        # sub-components
        self.logger      = Logger("data/dhcp_dataset.jsonl")
        self.alert_store = alert_store
        self._state      = state_dhcp
        self._state.register(
            self.mac_requests, self.mac_declines, self.mac_releases,
            self.server_seen, self.alerted_macs, self.alerted_ips
        )
        self._state.restore()

        # dashboard stats
        self.alert_count     = 0
        self.last_alert_time = None
        self.last_alert_type = None

    # =========================
    # DHCP TYPE EXTRACTOR
    # =========================
    @staticmethod
    def _get_dhcp_type(packet) -> int:
        if not packet.haslayer(DHCP):
            return 0
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                return opt[1]
        return 0

    # =========================
    # FEATURE EXTRACTION
    # =========================
    def _extract_features(self, mac: str, src_ip: str, msg_type: int, now: float) -> dict | None:
        req_data = self.mac_requests[mac]
        dec_data = self.mac_declines[mac]
        rel_data = self.mac_releases[mac]

        if not req_data:
            return None

        times    = [t for t, _ in req_data]
        types    = [tp for _, tp in req_data]
        duration = max(times) - min(times) if len(times) > 1 else 0

        type_counts = defaultdict(int)
        for tp in types:
            type_counts[DHCP_TYPES.get(tp, str(tp))] += 1

        discover_count = type_counts.get("DISCOVER", 0)
        discover_ratio = discover_count / len(types) if types else 0
        decline_count  = len(dec_data)
        release_count  = len(rel_data)

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

    def _get_network_mac_count(self, now: float) -> int:
        window_key = int(now / self.time_window)
        return len(self.all_macs_seen.get(window_key, set()))

    def _clean_all(self, mac: str, now: float):
        clean_old(self.mac_requests[mac], now, self.time_window, ts_index=0)
        clean_old(self.mac_declines[mac], now, self.time_window, ts_index=None)
        clean_old(self.mac_releases[mac], now, self.time_window, ts_index=None)

    # =========================
    # DETECTION ENGINE
    # =========================
    def detect(self, packet):
        if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
            return

        now      = time.time()
        msg_type = self._get_dhcp_type(packet)
        if msg_type == 0:
            return

        src_mac  = packet[Ether].src if packet.haslayer(Ether) else "unknown"
        src_ip   = packet[IP].src   if packet.haslayer(IP)    else "0.0.0.0"
        type_str = DHCP_TYPES.get(msg_type, str(msg_type))

        self.mac_requests[src_mac].append((now, msg_type))
        if msg_type == 4:
            self.mac_declines[src_mac].append(now)
        if msg_type == 7:
            self.mac_releases[src_mac].append(now)

        window_key = int(now / self.time_window)
        self.all_macs_seen[window_key].add(src_mac)

        if msg_type == 2:
            self.server_offers[src_ip].append(now)
            if src_ip not in self.server_seen:
                self.server_seen[src_ip] = now
            clean_old(self.server_offers[src_ip], now, self.time_window, ts_index=None)

        self._clean_all(src_mac, now)
        self._state.maybe_save(now)

        if now - self.last_prune > self.prune_interval:
            prune_stale(self.mac_requests, self.mac_declines, self.mac_releases, self.alerted_macs)
            prune_stale(self.server_offers, self.alerted_ips)
            current_window = int(now / self.time_window)
            for k in [k for k in self.all_macs_seen if k < current_window - 1]:
                del self.all_macs_seen[k]
            self.last_prune = now

        features = self._extract_features(src_mac, src_ip, msg_type, now)
        if not features:
            return

        ai_result = ai_predict("dhcp", features, threshold=self.ai_threshold)
        ai_alert  = ai_result["is_attack"]
        ai_conf   = ai_result["confidence"]

        network_mac_count = self._get_network_mac_count(now)

        traffic_doc = {
            "timestamp"        : str(datetime.now()),
            "detector"         : self.NAME,
            "source_ip"        : src_ip,
            "src_mac"          : src_mac,
            "src_ip"           : src_ip,
            "msg_type"         : type_str,
            "network_mac_count": network_mac_count,
            "label"            : 0,
            **features
        }
        self.logger.log(traffic_doc)
        if self.alert_store:
            self.alert_store.insert_traffic(traffic_doc)

        last_alert_mac = self.alerted_macs.get(src_mac, 0)
        pps            = features["pps"]
        discover_ratio = features["discover_ratio"]

        # DHCP STARVATION
        starvation_per_mac = (pps > self.starvation_pps and discover_ratio > 0.8)
        starvation_network = (network_mac_count > self.starvation_mac_count)

        if (starvation_per_mac or starvation_network) and \
           now - last_alert_mac > self.alert_cooldown:
            severity = severity_dhcp("DHCP_STARVATION", pps, network_mac_count)
            alert    = build_alert(
                alert_type = "DHCP_STARVATION",
                source_ip  = src_ip,
                target_ip  = "255.255.255.255",
                severity   = severity,
                features   = features,
                extra      = {"src_mac": src_mac, "network_mac_count": network_mac_count,
                              "trigger": "per_mac" if starvation_per_mac else "network_wide",
                              "detection": "RULE"},
                detector   = self.NAME          # ← AJOUTÉ
            )
            icon = "🚨"
            print(f"{icon} [RULE] [{severity}] [DHCP_STARVATION] {src_mac} | pps: {pps:.2f} | network MACs: {network_mac_count} | AI: {int(ai_conf*100)}%")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(src_ip, "DHCP_STARVATION", alert["severity"])
            self._record_alert("DHCP_STARVATION")
            self.alerted_macs[src_mac] = now

        # DHCP ROGUE SERVER
        if msg_type == 2 and src_ip not in self.legitimate_servers:
            last_alert_ip = self.alerted_ips.get(src_ip, 0)
            if now - last_alert_ip > self.alert_cooldown:
                offer_count = len(self.server_offers[src_ip])
                alert = build_alert(
                    alert_type = "DHCP_ROGUE_SERVER",
                    source_ip  = src_ip,
                    target_ip  = "255.255.255.255",
                    severity   = "CRITICAL",
                    features   = features,
                    extra      = {"src_mac": src_mac, "offer_count": offer_count,
                                  "first_seen": str(datetime.fromtimestamp(self.server_seen.get(src_ip, now))),
                                  "detection": "RULE"},
                    detector   = self.NAME          # ← AJOUTÉ
                )
                print(f"🚨 [RULE] [CRITICAL] [DHCP_ROGUE_SERVER] Unknown server {src_ip} ({src_mac}) sending OFFERs | offers: {offer_count} | AI: {int(ai_conf*100)}%")
                self.logger.log(alert)
                if self.alert_store:
                    self.alert_store.insert(alert)
                correlator.add_alert(src_ip, "DHCP_ROGUE_SERVER", "CRITICAL")
                self._record_alert("DHCP_ROGUE_SERVER")
                self.alerted_ips[src_ip] = now

        # DHCP DECLINE FLOOD
        decline_count = features["decline_count"]
        if decline_count >= self.repeated_decline_threshold and \
           now - last_alert_mac > self.alert_cooldown:
            alert = build_alert(
                alert_type = "DHCP_DECLINE_FLOOD",
                source_ip  = src_ip,
                target_ip  = "255.255.255.255",
                severity   = severity_dhcp("DHCP_DECLINE_FLOOD", pps, network_mac_count),
                features   = features,
                extra      = {"src_mac": src_mac, "decline_count": decline_count, "detection": "RULE"},
                detector   = self.NAME          # ← AJOUTÉ
            )
            print(f"🚨 [RULE] [{alert['severity']}] [DHCP_DECLINE_FLOOD] {src_mac} | declines: {decline_count} | AI: {int(ai_conf*100)}%")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            self._record_alert("DHCP_DECLINE_FLOOD")
            self.alerted_macs[src_mac] = now

        # DHCP RAPID CYCLING
        release_count  = features["release_count"]
        discover_count = features["discover_count"]
        if release_count >= self.rapid_release_threshold and \
           discover_count >= self.rapid_release_threshold and \
           now - last_alert_mac > self.alert_cooldown:
            alert = build_alert(
                alert_type = "DHCP_RAPID_CYCLING",
                source_ip  = src_ip,
                target_ip  = "255.255.255.255",
                severity   = severity_dhcp("DHCP_RAPID_CYCLING", pps, network_mac_count),
                features   = features,
                extra      = {"src_mac": src_mac, "release_count": release_count,
                              "discover_count": discover_count, "detection": "RULE"},
                detector   = self.NAME          # ← AJOUTÉ
            )
            print(f"🚨 [RULE] [{alert['severity']}] [DHCP_RAPID_CYCLING] {src_mac} | releases: {release_count} discovers: {discover_count} | AI: {int(ai_conf*100)}%")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            self._record_alert("DHCP_RAPID_CYCLING")
            self.alerted_macs[src_mac] = now

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
            "active_macs" : len(self.mac_requests),
            "config"      : self._get_config(),
        }

    def update_config(self, key: str, value) -> bool:
        if hasattr(self, key):
            setattr(self, key, value)
            return True
        return False

    def reset(self):
        self.mac_requests.clear()
        self.mac_declines.clear()
        self.mac_releases.clear()
        self.server_offers.clear()
        self.server_seen.clear()
        self.all_macs_seen.clear()
        self.alerted_macs.clear()
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
            "starvation_pps"            : self.starvation_pps,
            "starvation_mac_count"      : self.starvation_mac_count,
            "repeated_decline_threshold": self.repeated_decline_threshold,
            "alert_cooldown"            : self.alert_cooldown,
            "ai_threshold"              : self.ai_threshold,
        }

    @staticmethod
    def run():
        detector = DHCPDetector()
        iface    = IFACE or conf.iface
        print(f"🚀 DHCP DETECTOR RUNNING on [{iface}]")
        sniff(iface=iface, filter="udp and (port 67 or port 68)",
              prn=detector.detect, store=0)


if __name__ == "__main__":
    DHCPDetector.run()