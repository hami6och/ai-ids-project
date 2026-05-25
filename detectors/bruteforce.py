"""
detectors/bruteforce.py — Brute Force Detector
================================================
Detects :
    BRUTE_FORCE         — rapid SYNs to auth port from one source
    CREDENTIAL_STUFFING — spread across multiple auth ports
    MULTI_SOURCE_BRUTE  — many IPs hitting same port (MAC-spoof evasion)
    SLOW_BRUTE_FORCE    — slow attempts over long window (lw_brute)
"""

from scapy.all import sniff, IP, IPv6, TCP, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger      import Logger
from core.window      import clean_old, prune_stale
from ai.predict       import predict as ai_predict
from core.alerting    import build_alert, severity_bruteforce
from core.persistence import state_bruteforce
from core.correlation import correlator
from core.long_window import lw_brute
from core.distributed import tracker as dist_tracker
from config import (
    AI_THRESHOLD_BRUTEFORCE,
    MULTI_SOURCE_WINDOW, MULTI_SOURCE_THRESHOLD, MULTI_SOURCE_COOLDOWN,
    BRUTE_TIME_WINDOW, BRUTE_ATTEMPT_THRESHOLD, BRUTE_ALERT_COOLDOWN,
    BRUTE_PRUNE_INTERVAL, BRUTE_TARGET_PORTS, BRUTE_AI_MIN_ATTEMPTS,
    WHITELIST, IFACE
)


class BruteForceDetector:
    NAME = "bruteforce"

    def __init__(self, alert_store=None):
        # state
        self.attempts         = defaultdict(deque)   # ip → [(port, ts, flags)]
        self.dst_port_sources = defaultdict(deque)   # (dst_ip, port) → [(ts, src_ip)]
        self.dst_port_alerted = {}
        self.alerted_ips      = {}
        self.last_prune       = time.time()

        # config
        self.time_window        = BRUTE_TIME_WINDOW
        self.attempt_threshold  = BRUTE_ATTEMPT_THRESHOLD
        self.alert_cooldown     = BRUTE_ALERT_COOLDOWN
        self.prune_interval     = BRUTE_PRUNE_INTERVAL
        self.target_ports       = set(BRUTE_TARGET_PORTS)
        self.ai_min_attempts    = BRUTE_AI_MIN_ATTEMPTS
        self.ai_threshold       = AI_THRESHOLD_BRUTEFORCE
        self.multi_src_window   = MULTI_SOURCE_WINDOW
        self.multi_src_threshold= MULTI_SOURCE_THRESHOLD
        self.multi_src_cooldown = MULTI_SOURCE_COOLDOWN

        # sub-components
        self.logger      = Logger("data/bruteforce_logs.jsonl")
        self.alert_store = alert_store
        self._state      = state_bruteforce
        self._state.register(self.attempts, self.alerted_ips)
        self._state.restore()

        # dashboard stats
        self.alert_count     = 0
        self.last_alert_time = None
        self.last_alert_type = None

    # =========================
    # PRIVATE IP CHECK
    # =========================
    @staticmethod
    def _is_private(ip: str) -> bool:
        if ip.startswith(("192.168.", "10.")):
            return True
        parts = ip.split(".")
        if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            return True
        return False

    # =========================
    # FEATURE EXTRACTION
    # =========================
    def _extract_features(self, ip: str) -> dict | None:
        data = self.attempts[ip]
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
    def detect(self, packet):
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
        if not self._is_private(dst_ip):
            return
        if dport not in self.target_ports:
            return

        self.attempts[src_ip].append((dport, now, flags))
        clean_old(self.attempts[src_ip], now, self.time_window, ts_index=1)

        dst_key = (dst_ip, dport)
        self.dst_port_sources[dst_key].append((now, src_ip))
        dq_dst = self.dst_port_sources[dst_key]
        while dq_dst and now - dq_dst[0][0] > self.multi_src_window:
            dq_dst.popleft()

        dist_tracker.add(dst_ip, src_ip, "BRUTE")
        lw_brute.add(src_ip, value=(dport, now), now=now)
        self._state.maybe_save(now)

        if now - self.last_prune > self.prune_interval:
            prune_stale(self.attempts, self.alerted_ips)
            self.last_prune = now

        features = self._extract_features(src_ip)
        if not features:
            return

        if features.get("total_attempts", 0) >= self.ai_min_attempts:
            ai_result = ai_predict("bruteforce", features, threshold=self.ai_threshold)
            ai_alert  = ai_result["is_attack"]
            ai_conf   = ai_result["confidence"]
        else:
            ai_alert = False
            ai_conf  = 0.0

        total_attempts   = features["total_attempts"]
        unique_ports     = features["unique_ports"]
        port_focus_ratio = features["port_focus_ratio"]

        traffic_doc = {
            "timestamp" : str(datetime.now()),
            "detector"  : self.NAME,
            "source_ip" : src_ip,
            "target_ip" : dst_ip,
            "dport"     : dport,
            "flags"     : flags,
            "label"     : 0,
            **features
        }
        self.logger.log(traffic_doc)
        if self.alert_store:
            self.alert_store.insert_traffic(traffic_doc)

        # MULTI-SOURCE BRUTE FORCE
        unique_sources = len({s for _, s in self.dst_port_sources.get(dst_key, deque())})
        last_dst_alert = self.dst_port_alerted.get(dst_key, 0)

        if unique_sources >= self.multi_src_threshold and \
           now - last_dst_alert > self.multi_src_cooldown:
            sample_sources = list({s for _, s in self.dst_port_sources.get(dst_key, deque())})[:5]
            alert = build_alert(
                alert_type = "MULTI_SOURCE_BRUTE",
                source_ip  = src_ip,
                target_ip  = dst_ip,
                severity   = "HIGH",
                features   = features,
                extra      = {"target_port": dport, "unique_sources": unique_sources,
                              "sample_sources": sample_sources,
                              "window_sec": self.multi_src_window, "detection": "RULE"}
            )
            print(f"🚨 [RULE] [MULTI_SOURCE_BRUTE] [HIGH] {unique_sources} sources → "
                  f"{dst_ip}:{dport} | sample: {sample_sources[:3]}")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(src_ip, "MULTI_SOURCE_BRUTE", "HIGH", dst_ip)
            self._record_alert("MULTI_SOURCE_BRUTE")
            self.dst_port_alerted[dst_key] = now

        # SLOW BRUTE FORCE
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
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(src_ip, "SLOW_BRUTE_FORCE", "MEDIUM", dst_ip)
            self._record_alert("SLOW_BRUTE_FORCE")
            self.alerted_ips[src_ip] = now
            lw_brute.clear(src_ip)

        last_alert = self.alerted_ips.get(src_ip, 0)
        if now - last_alert < self.alert_cooldown:
            return

        alert_type = None
        if total_attempts >= self.attempt_threshold and unique_ports <= 2 and features["syn_ratio"] > 0.6:
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
            print(f"{icon} [{detection}] [{alert['severity']}] [{alert_type}] {src_ip} → {dst_ip} | attempts: {total_attempts} | ports: {unique_ports} | focus: {port_focus_ratio} | AI: {int(ai_conf*100)}%")
            self.logger.log(alert)
            if self.alert_store:
                self.alert_store.insert(alert)
            correlator.add_alert(src_ip, alert_type, alert["severity"], dst_ip)
            self._record_alert(alert_type)
            self.alerted_ips[src_ip] = now

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
            "active_ips"  : len(self.attempts),
            "config"      : self._get_config(),
        }

    def update_config(self, key: str, value) -> bool:
        if hasattr(self, key):
            setattr(self, key, value)
            return True
        return False

    def reset(self):
        self.attempts.clear()
        self.dst_port_sources.clear()
        self.dst_port_alerted.clear()
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
            "attempt_threshold" : self.attempt_threshold,
            "alert_cooldown"    : self.alert_cooldown,
            "ai_threshold"      : self.ai_threshold,
            "time_window"       : self.time_window,
            "target_ports"      : list(self.target_ports),
        }

    @staticmethod
    def run():
        detector    = BruteForceDetector()
        port_filter = " or ".join(f"dst port {p}" for p in BRUTE_TARGET_PORTS)
        bpf_filter  = f"tcp and ({port_filter})"
        iface       = IFACE or conf.iface
        print(f"🚀 BRUTE FORCE DETECTOR RUNNING on [{iface}]")
        sniff(iface=iface, filter=bpf_filter, prn=detector.detect, store=0)


if __name__ == "__main__":
    BruteForceDetector.run()