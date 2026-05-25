"""
detectors/syn.py — SYN Flood & Port Scan Detector
===================================================
Detects :
    SYN_FLOOD       — high SYN rate to one port
    SYN_SCAN        — SYNs spread across many ports
    SLOW_SYN_SCAN   — slow scan over long window (lw_syn)
"""

from scapy.all import sniff, IP, IPv6, TCP, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger      import Logger
from core.window      import clean_old, prune_stale
from ai.predict       import predict as ai_predict
from core.alerting    import build_alert, severity_syn_flood, severity_syn_scan
from core.persistence import state_syn
from core.correlation import correlator
from core.long_window import lw_syn
from core.distributed import tracker as dist_tracker
from config import (
    AI_THRESHOLD_SYN,
    SYN_TIME_WINDOW, SYN_FLOOD_RATE, PORT_SCAN_THRESHOLD,
    SYN_ALERT_COOLDOWN, SYN_PRUNE_INTERVAL, SYN_AI_MIN_PACKETS,
    WHITELIST, IFACE
)


class SYNDetector:
    NAME = "syn"

    def __init__(self, alert_store=None):
        # state
        self.traffic_data = defaultdict(deque)   # ip → [(port, timestamp)]
        self.alerted_ips  = {}
        self.last_prune   = time.time()

        # config — live-updatable via update_config()
        self.time_window         = SYN_TIME_WINDOW
        self.flood_rate          = SYN_FLOOD_RATE
        self.port_scan_threshold = PORT_SCAN_THRESHOLD
        self.alert_cooldown      = SYN_ALERT_COOLDOWN
        self.prune_interval      = SYN_PRUNE_INTERVAL
        self.ai_min_packets      = SYN_AI_MIN_PACKETS
        self.ai_threshold        = AI_THRESHOLD_SYN

        # sub-components
        self.logger      = Logger("data/syn_dataset.jsonl")
        self.alert_store = alert_store
        self._state      = state_syn
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
    # DETECTION ENGINE
    # =========================
    def detect(self, packet):
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)) or not packet.haslayer(TCP):
            return

        flags = packet[TCP].flags
        if not (flags & 0x02 and not flags & 0x10):
            return

        ip_src = (packet[IPv6].src if packet.haslayer(IPv6) else packet[IP].src)
        ip_dst = (packet[IPv6].dst if packet.haslayer(IPv6) else packet[IP].dst)
        dport  = packet[TCP].dport
        now    = time.time()

        if ip_src in WHITELIST:
            return

        self.traffic_data[ip_src].append((dport, now))
        clean_old(self.traffic_data[ip_src], now, self.time_window, ts_index=1)
        dist_tracker.add(ip_dst, ip_src, "SYN")
        lw_syn.add(ip_src, value=dport, now=now)
        self._state.maybe_save(now)

        if now - self.last_prune > self.prune_interval:
            prune_stale(self.traffic_data, self.alerted_ips)
            self.last_prune = now

        features = self._extract_features(ip_src)
        if not features:
            return

        unique_ports  = features["unique_ports"]
        total_packets = features["total_packets"]
        pps           = features["pps"]
        port_counts   = features["port_counts"]

        if total_packets >= self.ai_min_packets:
            ai_result = ai_predict("syn", features, threshold=self.ai_threshold)
            ai_alert  = ai_result["is_attack"]
            ai_conf   = ai_result["confidence"]
        else:
            ai_alert = False
            ai_conf  = 0.0

        self.logger.log({
            "timestamp"    : str(datetime.now()),
            "source_ip"    : ip_src,
            "target_ip"    : ip_dst,
            "dport"        : dport,
            "unique_ports" : unique_ports,
            "total_packets": total_packets,
            "pps"          : pps,
            "label"        : 0
        })

        last_alert = self.alerted_ips.get(ip_src, 0)
        if now - last_alert < self.alert_cooldown:
            return

        # SYN FLOOD
        for port, count in port_counts.items():
            rate = count / self.time_window
            if rate > self.flood_rate or (ai_alert and count == max(port_counts.values())):
                alert = build_alert(
                    alert_type = "SYN_FLOOD",
                    source_ip  = ip_src,
                    target_ip  = ip_dst,
                    severity   = severity_syn_flood(rate),
                    features   = features,
                    extra      = {"port": port, "rate": round(rate, 2),
                                  "ai_confidence": ai_conf,
                                  "detection": "RULE+AI" if ai_alert else "RULE"}
                )
                detection = alert.get("detection", "RULE")
                icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
                print(f"{icon} [{detection}] [SYN_FLOOD] [{alert['severity']}] {ip_src} → {ip_dst}:{port} | rate: {rate:.2f} pps | AI: {int(ai_conf*100) if ai_conf else 0}%")
                self.logger.log(alert)
                if self.alert_store:
                    self.alert_store.insert(alert)
                correlator.add_alert(ip_src, "SYN_FLOOD", alert["severity"], ip_dst)
                self._record_alert("SYN_FLOOD")
                self.alerted_ips[ip_src] = now
                self.traffic_data[ip_src].clear()
                return

        # SLOW SYN SCAN
        if lw_syn.should_alert(ip_src, now):
            summary = lw_syn.get_summary(ip_src)
            alert = build_alert(
                alert_type = "SLOW_SYN_SCAN",
                source_ip  = ip_src,
                target_ip  = ip_dst,
                severity   = "MEDIUM",
                features   = features,
                extra      = {**summary, "detection": "RULE"}
            )
            print(f"🐢 [SLOW] [SLOW_SYN_SCAN] [MEDIUM] {ip_src} → {ip_dst} | "
                  f"ports: {summary.get('unique_ports', 0)} in {summary.get('timespan_sec', 0)}s")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(ip_src, "SLOW_SYN_SCAN", "MEDIUM", ip_dst)
            self._record_alert("SLOW_SYN_SCAN")
            self.alerted_ips[ip_src] = now
            lw_syn.clear(ip_src)

        # SYN SCAN
        if unique_ports >= self.port_scan_threshold or ai_alert:
            alert = build_alert(
                alert_type = "SYN_SCAN",
                source_ip  = ip_src,
                target_ip  = ip_dst,
                severity   = severity_syn_scan(unique_ports),
                features   = features,
                extra      = {"ai_confidence": ai_conf,
                              "detection": "RULE+AI" if (unique_ports >= self.port_scan_threshold and ai_alert)
                                           else "AI_ONLY" if ai_alert else "RULE"}
            )
            detection = alert.get("detection", "RULE")
            icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
            print(f"{icon} [{detection}] [SYN_SCAN] [{alert['severity']}] {ip_src} → {ip_dst} | ports: {unique_ports} | AI: {int(ai_conf*100) if ai_conf else 0}%")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(ip_src, "SYN_SCAN", alert["severity"], ip_dst)
            self._record_alert("SYN_SCAN")
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
        self.alert_count = 0
        self.last_alert_time = None
        self.last_alert_type = None

    def _record_alert(self, alert_type: str):
        self.alert_count    += 1
        self.last_alert_time = str(datetime.now())
        self.last_alert_type = alert_type

    def _get_config(self) -> dict:
        return {
            "flood_rate"         : self.flood_rate,
            "port_scan_threshold": self.port_scan_threshold,
            "alert_cooldown"     : self.alert_cooldown,
            "ai_threshold"       : self.ai_threshold,
            "time_window"        : self.time_window,
        }

    # =========================
    # STANDALONE START
    # =========================
    @staticmethod
    def run():
        detector = SYNDetector()
        iface    = IFACE or conf.iface
        print(f"🚀 SYN FLOOD/SCAN DETECTION RUNNING on [{iface}]...")
        sniff(iface=iface, filter="tcp[tcpflags] & tcp-syn != 0",
              prn=detector.detect, store=0)


if __name__ == "__main__":
    SYNDetector.run()