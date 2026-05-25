"""
detectors/arp.py — ARP Spoofing Detector
==========================================
Detects :
    ARP_SPOOFING — MAC changes, gratuitous ARPs, high rate
"""

from scapy.all import sniff, ARP, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger      import Logger
from core.window      import clean_old, prune_stale
from ai.predict       import predict as ai_predict
from core.alerting    import build_alert, severity_arp
from core.persistence import state_arp
from core.correlation import correlator
from config import (
    AI_THRESHOLD_ARP,
    ARP_RATE_WINDOW, ARP_RATE_THRESHOLD, ARP_NETWORK_RATE_THRESH,
    ARP_ALERT_THRESHOLD, ARP_ALERT_COOLDOWN, ARP_PRUNE_INTERVAL,
    WHITELIST, IFACE
)


class ARPDetector:
    NAME = "arp"

    def __init__(self, alert_store=None):
        # state
        self.arp_table          = {}
        self.packet_times       = defaultdict(deque)
        self.mac_history        = defaultdict(set)
        self.alerted_ips        = {}
        self.network_arp_counts = defaultdict(int)
        self.last_prune         = time.time()

        # config
        self.rate_window         = ARP_RATE_WINDOW
        self.rate_threshold      = ARP_RATE_THRESHOLD
        self.network_rate_thresh = ARP_NETWORK_RATE_THRESH
        self.alert_threshold     = ARP_ALERT_THRESHOLD
        self.alert_cooldown      = ARP_ALERT_COOLDOWN
        self.prune_interval      = ARP_PRUNE_INTERVAL
        self.ai_threshold        = AI_THRESHOLD_ARP

        # sub-components
        self.logger      = Logger("data/arp_dataset.jsonl")
        self.alert_store = alert_store
        self._state      = state_arp
        self._state.register(self.arp_table, self.alerted_ips, self.mac_history)
        self._state.restore()

        # dashboard stats
        self.alert_count     = 0
        self.last_alert_time = None
        self.last_alert_type = None

    # =========================
    # FEATURE EXTRACTION
    # =========================
    def _extract_features(self, ip: str, packet, now: float) -> dict | None:
        dq = self.packet_times[ip]
        if not dq:
            return None

        duration         = dq[-1] - dq[0]
        per_ip_rate      = round(len(dq) / max(duration, 1), 3)
        window_key       = int(now / self.rate_window)
        network_arp_rate = round(
            (self.network_arp_counts[window_key] +
             self.network_arp_counts.get(window_key - 1, 0)) / self.rate_window, 3
        )

        return {
            "packet_rate"      : per_ip_rate,
            "network_arp_rate" : network_arp_rate,
            "unique_macs"      : len(self.mac_history[ip]),
            "mac_changed"      : int(bool(
                                   self.arp_table.get(ip) and
                                   self.arp_table.get(ip) != packet[ARP].hwsrc
                                 )),
            "known_mac"        : self.arp_table.get(ip),
            "is_gratuitous"    : int(packet[ARP].psrc == packet[ARP].pdst),
            "hwdst"            : packet[ARP].hwdst,
            "is_broadcast"     : int(packet[ARP].hwdst == "ff:ff:ff:ff:ff:ff"),
        }

    # =========================
    # DETECTION ENGINE
    # =========================
    def detect(self, packet):
        if not (packet.haslayer(ARP) and packet[ARP].op == 2):
            return

        ip  = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        now = time.time()

        if ip in WHITELIST:
            return

        self.packet_times[ip].append(now)
        self.mac_history[ip].add(mac)
        clean_old(self.packet_times[ip], now, self.rate_window, ts_index=None)
        self._state.maybe_save(now)

        window_key = int(now / self.rate_window)
        self.network_arp_counts[window_key] += 1
        stale_keys = [k for k in self.network_arp_counts if k < window_key - 2]
        for k in stale_keys:
            del self.network_arp_counts[k]

        if now - self.last_prune > self.prune_interval:
            prune_stale(self.packet_times, self.mac_history, self.alerted_ips)
            self.last_prune = now

        features = self._extract_features(ip, packet, now)
        if not features:
            return

        ai_result = ai_predict("arp", features, threshold=self.ai_threshold)
        ai_alert  = ai_result["is_attack"]
        ai_conf   = ai_result["confidence"]

        mac_changed      = features["mac_changed"]
        rate             = features["packet_rate"]
        network_arp_rate = features["network_arp_rate"]
        unique_macs      = features["unique_macs"]
        is_gratuitous    = features["is_gratuitous"]
        is_broadcast     = features["is_broadcast"]

        score = 0
        if mac_changed:                                    score += 3
        if unique_macs > 2:                                score += 2
        if rate > self.rate_threshold:                     score += 1
        if network_arp_rate > self.network_rate_thresh:    score += 2
        if is_gratuitous:                                  score += 2
        if is_broadcast:                                   score += 2

        self.logger.log({
            "timestamp"        : str(datetime.now()),
            "ip"               : ip,
            "mac"              : mac,
            "known_mac"        : features["known_mac"],
            "mac_changed"      : mac_changed,
            "packet_rate"      : rate,
            "network_arp_rate" : network_arp_rate,
            "unique_macs"      : unique_macs,
            "is_gratuitous"    : is_gratuitous,
            "hwdst"            : features["hwdst"],
            "is_broadcast"     : is_broadcast,
            "score"            : score,
            "label"            : 0
        })

        last_alert = self.alerted_ips.get(ip, 0)
        if now - last_alert < self.alert_cooldown:
            self.arp_table[ip] = mac
            return

        if score >= self.alert_threshold or ai_alert:
            severity  = severity_arp(score)
            detection = "RULE+AI" if (score >= self.alert_threshold and ai_alert) else \
                        "AI_ONLY" if ai_alert else "RULE"
            alert = build_alert(
                alert_type = "ARP_SPOOFING",
                source_ip  = ip,
                target_ip  = "N/A",
                severity   = severity,
                features   = features,
                extra      = {"source_mac": mac, "score": score,
                              "ai_confidence": ai_conf, "detection": detection}
            )
            icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
            print(f"{icon} [{detection}] [ARP_SPOOFING] [{severity}] {ip} | score: {score} | net_rate: {network_arp_rate:.1f}/s | AI: {int(ai_conf*100)}%")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(ip, "ARP_SPOOFING", alert["severity"])
            self._record_alert("ARP_SPOOFING")
            self.alerted_ips[ip] = now

        self.arp_table[ip] = mac

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
            "active_ips"  : len(self.arp_table),
            "config"      : self._get_config(),
        }

    def update_config(self, key: str, value) -> bool:
        if hasattr(self, key):
            setattr(self, key, value)
            return True
        return False

    def reset(self):
        self.arp_table.clear()
        self.packet_times.clear()
        self.mac_history.clear()
        self.alerted_ips.clear()
        self.network_arp_counts.clear()
        self.alert_count = 0
        self.last_alert_time = None
        self.last_alert_type = None

    def _record_alert(self, alert_type: str):
        self.alert_count    += 1
        self.last_alert_time = str(datetime.now())
        self.last_alert_type = alert_type

    def _get_config(self) -> dict:
        return {
            "alert_threshold"    : self.alert_threshold,
            "rate_threshold"     : self.rate_threshold,
            "alert_cooldown"     : self.alert_cooldown,
            "ai_threshold"       : self.ai_threshold,
        }

    @staticmethod
    def run():
        detector = ARPDetector()
        iface    = IFACE or conf.iface
        print(f"🚀 ARP SPOOFING DETECTION RUNNING on [{iface}]...")
        sniff(iface=iface, filter="arp", prn=detector.detect, store=0)


if __name__ == "__main__":
    ARPDetector.run()