"""
detectors/ftp.py — FTP Brute Force & Bounce Detector
======================================================
Detects :
    FTP_BRUTE_FORCE — rapid SYNs to port 21
    FTP_BOUNCE      — PORT commands pointing to third-party IPs
"""

from scapy.all import sniff, IP, IPv6, TCP, Raw, conf
from collections import defaultdict, deque
import time
from datetime import datetime

from core.logger      import Logger
from core.window      import clean_old, prune_stale
from ai.predict       import predict as ai_predict
from core.alerting    import build_alert, severity_ftp
from core.persistence import state_ftp
from core.correlation import correlator
from config import (
    AI_THRESHOLD_FTP,
    FTP_TIME_WINDOW, FTP_ATTEMPT_THRESHOLD, FTP_BOUNCE_THRESHOLD,
    FTP_ALERT_COOLDOWN, FTP_PRUNE_INTERVAL,
    FTP_AI_MIN_ATTEMPTS, FTP_AI_MIN_PORT_CMDS,
    WHITELIST, IFACE
)


class FTPDetector:
    NAME = "ftp"

    def __init__(self, alert_store=None):
        # state
        self.attempts    = defaultdict(deque)   # ip → [(ts, flags)]
        self.bounce_cmds = defaultdict(deque)   # ip → [(ts, target_ip)]
        self.alerted_ips = {}
        self.last_prune  = time.time()

        # config
        self.time_window      = FTP_TIME_WINDOW
        self.attempt_threshold= FTP_ATTEMPT_THRESHOLD
        self.bounce_threshold = FTP_BOUNCE_THRESHOLD
        self.alert_cooldown   = FTP_ALERT_COOLDOWN
        self.prune_interval   = FTP_PRUNE_INTERVAL
        self.ai_min_attempts  = FTP_AI_MIN_ATTEMPTS
        self.ai_min_port_cmds = FTP_AI_MIN_PORT_CMDS
        self.ai_threshold     = AI_THRESHOLD_FTP

        # sub-components
        self.logger      = Logger("data/ftp_dataset.jsonl")
        self.alert_store = alert_store
        self._state      = state_ftp
        self._state.register(self.attempts, self.bounce_cmds, self.alerted_ips)
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
    # PORT COMMAND PARSER
    # =========================
    @staticmethod
    def _parse_port_command(payload: str):
        payload = payload.strip().upper()
        if not payload.startswith("PORT"):
            return None
        try:
            parts = payload.split()[1].split(",")
            ip    = ".".join(parts[:4])
            port  = int(parts[4]) * 256 + int(parts[5])
            return ip, port
        except Exception:
            return None

    # =========================
    # FEATURE EXTRACTION
    # =========================
    def _extract_features_bruteforce(self, ip: str) -> dict | None:
        data = self.attempts[ip]
        if not data:
            return None

        times = [t for t, _ in data]
        flags = [f for _, f in data]
        duration     = max(times) - min(times) if len(times) > 1 else 0
        intervals    = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        syn_count    = sum(1 for f in flags if "S" in f and "A" not in f)
        syn_ratio    = syn_count / len(flags) if flags else 0

        interval_std = round(
            (sum((i - avg_interval)**2 for i in intervals) / max(len(intervals), 1)) ** 0.5, 4
        ) if intervals else 0.0

        return {
            "total_attempts" : len(data),
            "duration"       : round(duration, 3),
            "pps"            : round(len(data) / max(duration, 1), 3),
            "avg_interval"   : round(avg_interval, 4),
            "interval_std"   : interval_std,
            "syn_ratio"      : round(syn_ratio, 3),
        }

    def _extract_features_bounce(self, ip: str) -> dict | None:
        data = self.bounce_cmds[ip]
        if not data:
            return None

        times       = [t  for t, _ in data]
        targets     = [tg for _, tg in data]
        duration    = max(times) - min(times) if len(times) > 1 else 0
        third_party = [t for t in targets if t != ip]

        return {
            "total_port_cmds"    : len(data),
            "third_party_targets": len(third_party),
            "unique_targets"     : len(set(targets)),
            "duration"           : round(duration, 3),
            "pps"                : round(len(data) / max(duration, 1), 3),
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

        # PATH 1 — FTP BRUTE FORCE
        if dport == 21 and self._is_private(dst_ip):
            self.attempts[src_ip].append((now, flags))
            clean_old(self.attempts[src_ip], now, self.time_window, ts_index=0)
            self._state.maybe_save(now)

            if now - self.last_prune > self.prune_interval:
                prune_stale(self.attempts, self.bounce_cmds, self.alerted_ips)
                self.last_prune = now

            features = self._extract_features_bruteforce(src_ip)
            if not features:
                return

            if features.get("total_attempts", 0) >= self.ai_min_attempts:
                ai_result = ai_predict("ftp", features, threshold=self.ai_threshold)
                ai_alert  = ai_result["is_attack"]
                ai_conf   = ai_result["confidence"]
            else:
                ai_alert = False
                ai_conf  = 0.0

            traffic_doc = {
                "timestamp"  : str(datetime.now()),
                "detector"   : self.NAME,
                "source_ip"  : src_ip,
                "target_ip"  : dst_ip,
                "attack_path": "brute_force",
                "label"      : 0,
                **features
            }
            self.logger.log(traffic_doc)
            if self.alert_store:
                self.alert_store.insert_traffic(traffic_doc)

            last_alert = self.alerted_ips.get(src_ip, 0)
            if now - last_alert < self.alert_cooldown:
                return

            total = features["total_attempts"]
            syn_r = features["syn_ratio"]
            pps   = features["pps"]

            if (total >= self.attempt_threshold and syn_r > 0.6) or ai_alert:
                alert = build_alert(
                    alert_type = "FTP_BRUTE_FORCE",
                    source_ip  = src_ip,
                    target_ip  = dst_ip,
                    severity   = severity_ftp("FTP_BRUTE_FORCE", pps, total),
                    features   = features,
                    extra      = {"ai_confidence": ai_conf,
                                  "detection": "RULE+AI" if (total >= self.attempt_threshold and ai_alert)
                                               else "AI_ONLY" if ai_alert else "RULE"}
                )
                detection = alert.get("detection", "RULE")
                icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
                print(f"{icon} [{detection}] [{alert['severity']}] [FTP_BRUTE_FORCE] "
                      f"{src_ip} → {dst_ip} | attempts: {total} | syn_ratio: {syn_r} | AI: {int(ai_conf*100)}%")
                self.logger.log(alert)
                if self.alert_store:
                    self.alert_store.insert(alert)
                correlator.add_alert(src_ip, "FTP_BRUTE_FORCE", alert["severity"], dst_ip)
                self._record_alert("FTP_BRUTE_FORCE")
                self.alerted_ips[src_ip] = now

        # PATH 2 — FTP BOUNCE
        if dport == 21 and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
            except Exception:
                return

            result = self._parse_port_command(payload)
            if not result:
                return

            target_ip, target_port = result

            if target_ip != src_ip:
                self.bounce_cmds[src_ip].append((now, target_ip))
                clean_old(self.bounce_cmds[src_ip], now, self.time_window, ts_index=0)
                self._state.maybe_save(now)

                features = self._extract_features_bounce(src_ip)
                if not features:
                    return

                if features.get("total_port_cmds", 0) >= self.ai_min_port_cmds:
                    ai_result = ai_predict("ftp", features, threshold=self.ai_threshold)
                    ai_alert  = ai_result["is_attack"]
                    ai_conf   = ai_result["confidence"]
                else:
                    ai_alert = False
                    ai_conf  = 0.0

                traffic_doc = {
                    "timestamp"    : str(datetime.now()),
                    "detector"     : self.NAME,
                    "source_ip"    : src_ip,
                    "target_ip"    : dst_ip,
                    "bounce_target": target_ip,
                    "bounce_port"  : target_port,
                    "attack_path"  : "bounce",
                    "label"        : 0,
                    **features
                }
                self.logger.log(traffic_doc)
                if self.alert_store:
                    self.alert_store.insert_traffic(traffic_doc)

                last_alert = self.alerted_ips.get(src_ip, 0)
                if now - last_alert < self.alert_cooldown:
                    return

                if features["third_party_targets"] >= self.bounce_threshold or ai_alert:
                    alert = build_alert(
                        alert_type = "FTP_BOUNCE",
                        source_ip  = src_ip,
                        target_ip  = dst_ip,
                        severity   = severity_ftp("FTP_BOUNCE", features["pps"], features["total_port_cmds"]),
                        features   = features,
                        extra      = {"bounce_target": target_ip, "bounce_port": target_port,
                                      "ai_confidence": ai_conf,
                                      "detection": "RULE+AI" if (features["third_party_targets"] >= self.bounce_threshold and ai_alert)
                                                   else "AI_ONLY" if ai_alert else "RULE"}
                    )
                    detection = alert.get("detection", "RULE")
                    icon = "🔥" if detection == "RULE+AI" else "🤖" if "AI" in detection else "🚨"
                    print(f"{icon} [{detection}] [{alert['severity']}] [FTP_BOUNCE] {src_ip} using FTP server to scan {target_ip}:{target_port} | PORT cmds: {features['total_port_cmds']} | AI: {int(ai_conf*100)}%")
                    self.logger.log(alert)
                    if self.alert_store:
                        self.alert_store.insert(alert)
                    correlator.add_alert(src_ip, "FTP_BOUNCE", alert["severity"], dst_ip)
                    self._record_alert("FTP_BOUNCE")
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
        self.bounce_cmds.clear()
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
            "attempt_threshold": self.attempt_threshold,
            "bounce_threshold" : self.bounce_threshold,
            "alert_cooldown"   : self.alert_cooldown,
            "ai_threshold"     : self.ai_threshold,
            "time_window"      : self.time_window,
        }

    @staticmethod
    def run():
        detector = FTPDetector()
        iface    = IFACE or conf.iface
        print(f"🚀 FTP DETECTOR RUNNING on [{iface}]")
        sniff(iface=iface, filter="tcp port 21", prn=detector.detect, store=0)


if __name__ == "__main__":
    FTPDetector.run()