import pandas as pd
import json
import os
from pathlib import Path
from collections import Counter

# =========================
# FEATURE COLUMNS PER DETECTOR
# =========================
FEATURES = {
    "syn": [
        "pps", "duration", "total_packets",
        "unique_ports", "avg_interval"
    ],
    "icmp": [
        "pps", "duration", "total_packets",
        "avg_packet_size", "max_packet_size"
    ],
    "bruteforce": [
        "pps", "duration", "total_attempts",
        "avg_interval", "syn_ratio",
        "port_focus_ratio", "unique_ports"
    ],
    "arp": [
        "packet_rate", "network_arp_rate", "unique_macs",
        "mac_changed", "is_gratuitous", "is_broadcast"
    ],
    "dns": [
        "pps", "duration", "total_requests",
        "avg_interval", "unique_domains",
        "domain_diversity_ratio", "avg_qname_len",
        "top_domain_ratio"
    ],
    "dhcp": [
        "pps", "duration", "total_requests",
        "unique_macs", "is_offer"
    ],
    "ftp": [
        "pps", "duration", "total_attempts",
        "avg_interval", "syn_ratio",
        "port_focus_ratio", "unique_ports"
    ]
}

# =========================
# CIC COLUMN MAPS
# CIC-2017 and CIC-2018 have different column names
# =========================
CIC_COLUMN_MAP = {
    # CIC-IDS-2017 column names
    "Flow Packets/s"              : "pps",
    "Flow Duration"               : "duration",
    "Total Fwd Packets"           : "total_packets",
    "Total Backward Packets"      : "total_bwd_packets",
    "Flow IAT Mean"               : "avg_interval",
    "Average Packet Size"         : "avg_packet_size",
    "Max Packet Length"           : "max_packet_size",
    "Destination Port"            : "dport",
    "SYN Flag Count"              : "syn_count",
    "Total Length of Fwd Packets" : "total_fwd_bytes",
    "Label"                       : "label_raw"
}

CIC2018_COLUMN_MAP = {
    # CIC-IDS-2018 column names — different from 2017
    "Flow Pkts/s"                 : "pps",
    "Flow Duration"               : "duration",
    "Tot Fwd Pkts"                : "total_packets",
    "Tot Bwd Pkts"                : "total_bwd_packets",
    "Flow IAT Mean"               : "avg_interval",
    "Pkt Size Avg"                : "avg_packet_size",
    "Pkt Len Max"                 : "max_packet_size",
    "Dst Port"                    : "dport",
    "SYN Flag Cnt"                : "syn_count",
    "TotLen Fwd Pkts"             : "total_fwd_bytes",
    "Timestamp"                   : "timestamp",
    "Label"                       : "label_raw"
}

# =========================
# LABEL STANDARDIZATION
# =========================
def standardize_label(raw_label: str, dataset: str) -> int:
    label = str(raw_label).strip().upper()

    if label in {"BENIGN", "NORMAL", "0", "LEGITIMATE", "BACKGROUND"}:
        return 0

    if dataset in {"cic2017", "cic2018"}:
        attacks = {
            "DOS HULK", "DOS GOLDENEYE", "DOS SLOWLORIS",
            "DOS SLOWHTTPTEST", "DDOS", "PORTSCAN", "PORT SCAN",
            "FTP-PATATOR", "SSH-PATATOR", "BOTNET", "INFILTRATION",
            "FTP-BRUTEFORCE", "SSH-BRUTEFORCE",
            "DOSHULK", "DOSGOLDENEYE", "DOSSLOWLORIS",
            "WEB ATTACK \x96 BRUTE FORCE",
        }
        return 1 if label in attacks else -1

    if dataset == "unsw_nb15":
        if label == "1": return 1
        if label == "0": return 0
        attacks = {
            "FUZZERS", "ANALYSIS", "BACKDOORS", "DOS",
            "EXPLOITS", "GENERIC", "RECONNAISSANCE",
            "SHELLCODE", "WORMS", "BACKDOOR"
        }
        return 1 if label in attacks else -1

    if dataset == "cira_doh":
        if label in {"MALICIOUS", "1"}:  return 1
        if label in {"BENIGN", "0"}:     return 0
        return -1

    if dataset == "lab_own":
        if label in {"0", "0.0"}: return 0
        if label in {"1", "1.0"}: return 1
        return -1

    return -1

# =========================
# CLASS BALANCING
# =========================
def balance_dataset(df: pd.DataFrame, label_col="label", ratio=2) -> pd.DataFrame:
    attack = df[df[label_col] == 1]
    normal = df[df[label_col] == 0]

    n_normal_target = min(len(normal), len(attack) * ratio)

    if n_normal_target == 0:
        print("  ⚠️  No attack samples found — check your labels")
        return df

    normal_sampled = normal.sample(n=n_normal_target, random_state=42)
    balanced       = pd.concat([attack, normal_sampled])
    return balanced.sample(frac=1, random_state=42).reset_index(drop=True)

# =========================
# IP AGGREGATION
# Computes per-source-IP features from flow-level data
# This is Option D — recovers unique_ports and port_focus_ratio
# by grouping multiple flows from the same source IP within
# a time window, replicating what the detector does at runtime
# =========================
def aggregate_by_ip(df: pd.DataFrame, detector: str,
                    bucket_size: int = 30) -> pd.DataFrame:
    """
    Groups consecutive flow rows into buckets and computes
    per-bucket aggregated features including unique_ports
    and port_focus_ratio.

    CIC-IDS-2017/2018 CSV files don't include Source IP
    (stripped during CICFlowMeter export). Instead we use
    row proximity — the label column identifies attack vs
    normal flows and consecutive attack rows typically
    come from the same attacker in these datasets.

    bucket_size : number of flows per aggregation window
                  ~30 flows approximates a 5-second window
                  at typical CIC dataset capture rates
    """
    if df.empty:
        return df

    df = df.reset_index(drop=True)
    df["_bucket"] = df.index // bucket_size

    # separate attack and normal before bucketing
    # prevents majority-vote from drowning attack rows
    df_attack = df[df["label"] == 1].copy()
    df_normal = df[df["label"] == 0].copy()
    source    = df["dataset_source"].iloc[0] if not df.empty else "cic2017"

    def _agg_group(sub_df, label_val, src):
        if sub_df.empty:
            return pd.DataFrame()
        sub_df = sub_df.reset_index(drop=True)
        sub_df["_bucket"] = sub_df.index // bucket_size
        rows = []
        for bucket, group in sub_df.groupby("_bucket"):
            ports = group["dport"].dropna().tolist() if "dport" in group.columns else []
            if ports:
                port_counts      = Counter(ports)
                unique_ports     = len(port_counts)
                port_focus_ratio = round(max(port_counts.values()) / len(ports), 3)
            else:
                unique_ports     = 0
                port_focus_ratio = 0.0
            row = {
                "pps"             : group["pps"].mean()             if "pps" in group.columns else 0,
                "duration"        : group["duration"].sum()         if "duration" in group.columns else 0,
                "total_packets"   : group["total_packets"].sum()    if "total_packets" in group.columns else 0,
                "total_attempts"  : group["total_packets"].sum()    if "total_packets" in group.columns else 0,
                "avg_interval"    : group["avg_interval"].mean()    if "avg_interval" in group.columns else 0,
                "avg_packet_size" : group["avg_packet_size"].mean() if "avg_packet_size" in group.columns else 0,
                "max_packet_size" : group["max_packet_size"].max()  if "max_packet_size" in group.columns else 0,
                "unique_ports"    : unique_ports,
                "port_focus_ratio": port_focus_ratio,
                "label"           : label_val,
                "dataset_source"  : src
            }
            if "syn_count" in group.columns and "total_packets" in group.columns:
                total_syn  = group["syn_count"].sum()
                total_pkts = group["total_packets"].sum()
                row["syn_ratio"] = round(float(total_syn) / max(float(total_pkts), 1), 3)
            else:
                row["syn_ratio"] = 0.0
            rows.append(row)
        return pd.DataFrame(rows)

    attack_agg = _agg_group(df_attack, 1, source)
    normal_agg = _agg_group(df_normal, 0, source)
    result     = pd.concat([attack_agg, normal_agg], ignore_index=True)
    result     = result.replace([float("inf"), float("-inf")], float("nan")).fillna(0)

    print(f"  ✅ Aggregated {len(df)} flows → "
          f"{len(attack_agg)} attack + {len(normal_agg)} normal buckets")
    return result.reset_index(drop=True)

# =========================
# BASE CIC LOADER
# Loads raw CIC CSV, renames columns, standardizes labels
# Returns raw flow-level df ready for aggregation or direct use
# =========================
def _load_cic_raw(filepath: str, dataset_tag: str,
                  column_map: dict = None) -> pd.DataFrame:
    """
    Internal — loads any CIC CSV file (2017 or 2018),
    applies column map and label standardization.
    Returns raw flow-level DataFrame.
    """
    print(f"  Loading {dataset_tag.upper()} : {Path(filepath).name}")
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()

    cmap = column_map if column_map is not None else CIC_COLUMN_MAP
    df = df.rename(columns={k: v for k, v in cmap.items() if k in df.columns})

    # force numeric — CIC-2018 has string values in some numeric columns
    for col in ["syn_count", "total_packets", "pps", "duration",
                "avg_interval", "avg_packet_size", "max_packet_size", "dport"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    if "syn_count" in df.columns and "total_packets" in df.columns:
        df["syn_ratio"] = df["syn_count"] / df["total_packets"].replace(0, 1)

    if "total_attempts" not in df.columns and "total_packets" in df.columns:
        df["total_attempts"] = df["total_packets"]

    df["label_raw"]      = df.get("label_raw", "BENIGN")
    df["label"]          = df["label_raw"].apply(lambda x: standardize_label(x, dataset_tag))
    df["dataset_source"] = dataset_tag
    df = df[df["label"] != -1]
    df = df.replace([float("inf"), float("-inf")], float("nan"))

    return df

# =========================
# LOADER — CIC-IDS-2017 (flow level, for icmp/dns)
# =========================
def load_cic2017(filepath: str, detector: str) -> pd.DataFrame:
    df = _load_cic_raw(filepath, "cic2017")

    feature_cols = FEATURES.get(detector, [])
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    return df[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
# LOADER — CIC-IDS-2017 AGGREGATED (for syn/bruteforce/ftp)
# Uses Option D — per-IP aggregation to recover unique_ports
# =========================
def load_cic2017_aggregated(filepath: str, detector: str) -> pd.DataFrame:
    df = _load_cic_raw(filepath, "cic2017")
    df = aggregate_by_ip(df, detector)

    feature_cols = FEATURES.get(detector, [])
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    return df[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
# LOADER — CIC-IDS-2018 (flow level, for icmp)
# =========================
def load_cic2018(filepath: str, detector: str) -> pd.DataFrame:
    df = _load_cic_raw(filepath, "cic2018", column_map=CIC2018_COLUMN_MAP)

    feature_cols = FEATURES.get(detector, [])
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    return df[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
# LOADER — CIC-IDS-2018 AGGREGATED (for bruteforce/ftp)
# Uses timestamp column for time-based bucketing
# CIC-2018 has Timestamp column — better than row-index bucketing
# =========================
def load_cic2018_aggregated(filepath: str, detector: str) -> pd.DataFrame:
    df = _load_cic_raw(filepath, "cic2018", column_map=CIC2018_COLUMN_MAP)

    # separate attack and normal flows BEFORE bucketing
    # this prevents majority-vote from drowning attack rows
    # when benign traffic dominates the time window
    df_attack = df[df["label"] == 1].copy()
    df_normal = df[df["label"] == 0].copy()

    def bucket_and_aggregate(sub_df, label_val, bucket_size=30):
        if sub_df.empty:
            return pd.DataFrame()

        # use timestamp if available for accurate windowing
        if "timestamp" in sub_df.columns:
            try:
                sub_df["timestamp"] = pd.to_datetime(
                    sub_df["timestamp"], dayfirst=True, errors="coerce"
                )
                sub_df = sub_df.sort_values("timestamp")
                t0 = sub_df["timestamp"].min()
                sub_df["_bucket"] = (
                    (sub_df["timestamp"] - t0).dt.total_seconds() // 5
                ).astype(int)
            except Exception:
                sub_df["_bucket"] = sub_df.index // bucket_size
        else:
            sub_df["_bucket"] = sub_df.index // bucket_size

        rows = []
        for bucket, group in sub_df.groupby("_bucket"):
            ports = group["dport"].dropna().tolist() if "dport" in group.columns else []

            if ports:
                port_counts      = Counter(ports)
                unique_ports     = len(port_counts)
                port_focus_ratio = round(max(port_counts.values()) / len(ports), 3)
            else:
                unique_ports     = 0
                port_focus_ratio = 0.0

            row = {
                "pps"             : group["pps"].mean()             if "pps" in group.columns else 0,
                "duration"        : group["duration"].sum()         if "duration" in group.columns else 0,
                "total_packets"   : group["total_packets"].sum()    if "total_packets" in group.columns else 0,
                "total_attempts"  : group["total_packets"].sum()    if "total_packets" in group.columns else 0,
                "avg_interval"    : group["avg_interval"].mean()    if "avg_interval" in group.columns else 0,
                "avg_packet_size" : group["avg_packet_size"].mean() if "avg_packet_size" in group.columns else 0,
                "max_packet_size" : group["max_packet_size"].max()  if "max_packet_size" in group.columns else 0,
                "unique_ports"    : unique_ports,
                "port_focus_ratio": port_focus_ratio,
                "label"           : label_val,
                "dataset_source"  : "cic2018"
            }

            if "syn_count" in group.columns and "total_packets" in group.columns:
                total_syn  = group["syn_count"].sum()
                total_pkts = group["total_packets"].sum()
                row["syn_ratio"] = round(float(total_syn) / max(float(total_pkts), 1), 3)
            else:
                row["syn_ratio"] = 0.0

            rows.append(row)
        return pd.DataFrame(rows)

    attack_agg = bucket_and_aggregate(df_attack, label_val=1)
    normal_agg = bucket_and_aggregate(df_normal, label_val=0)
    result     = pd.concat([attack_agg, normal_agg], ignore_index=True)
    result     = result.replace([float("inf"), float("-inf")], float("nan")).fillna(0)

    print(f"  ✅ Aggregated {len(df)} flows → "
          f"{len(attack_agg)} attack + {len(normal_agg)} normal buckets")

    feature_cols = FEATURES.get(detector, [])
    for col in feature_cols:
        if col not in result.columns:
            result[col] = 0

    return result[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
# LOADER — UNSW-NB15
# =========================
def load_unsw_nb15(filepath: str, detector: str) -> pd.DataFrame:
    print(f"  Loading UNSW-NB15 : {Path(filepath).name}")
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()

    column_map = {
        "rate"    : "pps",
        "dur"     : "duration",
        "spkts"   : "total_packets",
        "sinpkt"  : "avg_interval",
        "smean"   : "avg_packet_size",
        "dmean"   : "max_packet_size",
    }
    df = df.rename(columns={k: v for k, v in column_map.items() if k in df.columns})

    df["label"]          = df["label"].apply(lambda x: standardize_label(str(x), "unsw_nb15"))
    df["dataset_source"] = "unsw_nb15"
    df = df[df["label"] != -1]
    df = df.replace([float("inf"), float("-inf")], float("nan"))

    feature_cols = FEATURES.get(detector, [])
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    return df[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
# LOADER — CIRA-CIC-DoH
# =========================
def load_cira_doh(filepath: str, detector: str) -> pd.DataFrame:
    print(f"  Loading CIRA-CIC-DoH : {Path(filepath).name}")
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()

    column_map = {
        "FlowSentRate"        : "pps",
        "PacketTimeMean"      : "duration",
        "ResponseTimeTimeMean": "avg_interval",
        "PacketLengthMean"    : "avg_qname_len",
        "Label"               : "label_raw"
    }
    df = df.rename(columns={k: v for k, v in column_map.items() if k in df.columns})

    df["label"]          = df["label_raw"].apply(lambda x: standardize_label(x, "cira_doh"))
    df["dataset_source"] = "cira_doh"
    df = df[df["label"] != -1]
    df = df.replace([float("inf"), float("-inf")], float("nan"))

    feature_cols = FEATURES.get(detector, [])
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    return df[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
# LOADER — KAGGLE DNS TUNNELING QUERIES
# =========================
def load_dns_kaggle(filepath: str) -> pd.DataFrame:
    print(f"  Loading Kaggle DNS : {Path(filepath).name}")
    df = pd.read_csv(filepath, header=None, names=["label", "query"])

    df["label"]          = pd.to_numeric(df["label"], errors="coerce")
    df["dataset_source"] = "kaggle_dns"
    df = df.dropna(subset=["label", "query"])
    df["label"] = df["label"].astype(int)

    df["query"]        = df["query"].str.rstrip(".")
    df["avg_qname_len"] = df["query"].str.len().astype(float)

    def base_domain(q):
        parts = str(q).split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else q

    df["base_domain"] = df["query"].apply(base_domain)

    window = 20
    unique_domains_list   = []
    domain_diversity_list = []
    top_domain_ratio_list = []
    total_requests_list   = []

    base_domains = df["base_domain"].tolist()

    for i in range(len(base_domains)):
        start       = max(0, i - window + 1)
        window_vals = base_domains[start : i + 1]
        total       = len(window_vals)
        counts      = Counter(window_vals)
        unique      = len(counts)
        top_r       = max(counts.values()) / total if total > 0 else 0
        div_r       = unique / total if total > 0 else 0

        unique_domains_list.append(float(unique))
        domain_diversity_list.append(round(div_r, 3))
        top_domain_ratio_list.append(round(top_r, 3))
        total_requests_list.append(float(total))

    df["unique_domains"]         = unique_domains_list
    df["domain_diversity_ratio"] = domain_diversity_list
    df["top_domain_ratio"]       = top_domain_ratio_list
    df["total_requests"]         = total_requests_list

    df["pps"]           = 0.0
    df["duration"]      = 0.0
    df["avg_interval"]  = 0.0
    df["unique_qtypes"] = 0

    feature_cols = FEATURES.get("dns", [])
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    print(f"  ✅ Computed features from {len(df)} query rows")
    return df[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
# LOADER — YOUR OWN JSONL LOGS
# =========================
def load_own(detector: str) -> pd.DataFrame:
    filename_map = {
        "syn"        : "data/syn_dataset.jsonl",
        "arp"        : "data/arp_dataset.jsonl",
        "icmp"       : "data/icmp_dataset.jsonl",
        "dns"        : "data/dns_logs.jsonl",
        "bruteforce" : "data/bruteforce_logs.jsonl",
        "dhcp"       : "data/dhcp_dataset.jsonl",
        "ftp"        : "data/ftp_dataset.jsonl"
    }

    filepath = filename_map.get(detector)
    if not filepath or not Path(filepath).exists():
        print(f"  ⚠️  No own data found for {detector} — skipping")
        return pd.DataFrame()

    print(f"  Loading own data : {filepath}")
    records = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    if not records:
        print(f"  ⚠️  {filepath} is empty")
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df["dataset_source"] = "lab_own"
    df["label"]          = df["label"].apply(lambda x: standardize_label(str(x), "lab_own"))
    df = df[df["label"] != -1]

    feature_cols = FEATURES.get(detector, [])
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    return df[feature_cols + ["label", "dataset_source"]].fillna(0).reset_index(drop=True)

# =========================
# MAIN LOADER
# =========================
def load_all(detector: str, own_weight: int = 0) -> pd.DataFrame:
    print(f"\n{'='*55}")
    print(f"  Loading dataset for : {detector.upper()}")
    print(f"{'='*55}")

    frames = []

    # ── SYN : aggregated 2017 + 2017 flow-level for flood ──
    if detector == "syn":
        for f in [
            "datasets/Wednesday-workingHours.pcap_ISCX.csv",
            "datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "datasets/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "datasets/Monday-WorkingHours.pcap_ISCX.csv",
        ]:
            if Path(f).exists():
                # aggregated — gives real unique_ports for scan detection
                frames.append(load_cic2017_aggregated(f, detector))

    # ── ICMP : flow-level 2017 + 2018 + UNSW ──────────────
    elif detector == "icmp":
        for f in [
            "datasets/Wednesday-workingHours.pcap_ISCX.csv",
            "datasets/Monday-WorkingHours.pcap_ISCX.csv",
        ]:
            if Path(f).exists(): frames.append(load_cic2017(f, detector))
        # CIC-IDS-2018 adds more DoS variety
        if Path("datasets/02-16-2018.csv").exists():
            frames.append(load_cic2018("datasets/02-16-2018.csv", detector))
        if Path("datasets/UNSW_NB15_training-set.csv").exists():
            frames.append(load_unsw_nb15("datasets/UNSW_NB15_training-set.csv", detector))

    # ── BRUTEFORCE : aggregated 2017 + aggregated 2018 ────
    elif detector == "bruteforce":
        for f in [
            "datasets/Tuesday-WorkingHours.pcap_ISCX.csv",
            "datasets/Monday-WorkingHours.pcap_ISCX.csv",
        ]:
            if Path(f).exists():
                frames.append(load_cic2017_aggregated(f, detector))
        # CIC-IDS-2018 has 14x more brute force samples
        if Path("datasets/02-14-2018.csv").exists():
            frames.append(load_cic2018_aggregated("datasets/02-14-2018.csv", detector))

    # ── FTP : same as bruteforce ───────────────────────────
    elif detector == "ftp":
        for f in [
            "datasets/Tuesday-WorkingHours.pcap_ISCX.csv",
            "datasets/Monday-WorkingHours.pcap_ISCX.csv",
        ]:
            if Path(f).exists():
                frames.append(load_cic2017_aggregated(f, detector))
        if Path("datasets/02-14-2018.csv").exists():
            frames.append(load_cic2018_aggregated("datasets/02-14-2018.csv", detector))

    # ── ARP : own data only ────────────────────────────────
    elif detector == "arp":
        pass

    # ── DNS : CIRA + Kaggle ────────────────────────────────
    elif detector == "dns":
        if Path("datasets/BCCC-CIRA-CIC-DoHBrw-2020.csv").exists():
            frames.append(load_cira_doh("datasets/BCCC-CIRA-CIC-DoHBrw-2020.csv", detector))
        for f in ["datasets/training.csv", "datasets/validating.csv"]:
            if Path(f).exists():
                frames.append(load_dns_kaggle(f))

    # ── DHCP : own data only ───────────────────────────────
    elif detector == "dhcp":
        pass

    # own data
    if own_weight > 0:
        own_df = load_own(detector)
        if not own_df.empty:
            for _ in range(own_weight):
                frames.append(own_df)

    if not frames:
        print(f"  ❌ No data found for {detector}")
        return pd.DataFrame()

    # align columns before concat
    feature_cols = FEATURES.get(detector, [])
    all_cols = feature_cols + ["label", "dataset_source"]
    for i, frame in enumerate(frames):
        for col in all_cols:
            if col not in frame.columns:
                frames[i][col] = 0
        frames[i] = frames[i][all_cols]

    df = pd.concat(frames, ignore_index=True)
    df = df[df["label"] != -1]
    df = df.replace([float("inf"), float("-inf")], float("nan")).dropna()

    print(f"\n  Before balancing :")
    print(f"    Total rows  : {len(df)}")
    print(f"    Normal  (0) : {(df['label']==0).sum()}")
    print(f"    Attack  (1) : {(df['label']==1).sum()}")
    print(f"    Sources     : {df['dataset_source'].value_counts().to_dict()}")

    df = balance_dataset(df)

    print(f"\n  After balancing :")
    print(f"    Total rows  : {len(df)}")
    print(f"    Normal  (0) : {(df['label']==0).sum()}")
    print(f"    Attack  (1) : {(df['label']==1).sum()}")

    return df

# =========================
# QUICK CHECK
# =========================
if __name__ == "__main__":
    detectors = ["syn", "arp", "icmp", "dns", "bruteforce", "ftp", "dhcp"]
    for det in detectors:
        df = load_all(det)
        if not df.empty:
            print(f"\n  ✅ {det} ready — shape: {df.shape}")
            print(f"     columns: {list(df.columns)}")
        else:
            print(f"\n  ❌ {det} — no data available yet")