import pandas as pd
import json
import os
from pathlib import Path

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
    "packet_rate", "network_arp_rate",  
    "unique_macs", "mac_changed",
    "is_gratuitous", "is_broadcast"
    ],
    "dns": [
        "pps", "duration", "total_requests",
        "avg_interval", "unique_domains",
        "domain_diversity_ratio", "avg_qname_len",
        "top_domain_ratio", "unique_qtypes"
    ],
    "dhcp": [
        "pps", "duration", "total_requests",
        "unique_macs", "is_offer"
    ],
    "ftp": [
        "pps", "duration", "total_attempts",
        "avg_interval", "syn_ratio"
    ]
}

# =========================
# CIC-IDS-2017 COLUMN MAP
# Verified against actual files
# =========================
CIC_COLUMN_MAP = {
    "Flow Packets/s"              : "pps",
    "Flow Duration"               : "duration",
    "Total Fwd Packets"           : "total_packets",
    "Total Backward Packets"      : "total_bwd_packets",
    "Flow IAT Mean"               : "avg_interval",
    "Average Packet Size"         : "avg_packet_size",   # one source only
    "Max Packet Length"           : "max_packet_size",   # one source only
    "Destination Port"            : "dport",
    "SYN Flag Count"              : "syn_count",
    "Total Length of Fwd Packets" : "total_fwd_bytes",
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
            "WEB ATTACK \x96 BRUTE FORCE", "WEB ATTACK \x96 XSS",
            "WEB ATTACK \x96 SQL INJECTION",
            "DOSHULK", "DOSGOLDENEYE", "DOSSLOWLORIS"
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
# LOADER — CIC-IDS-2017
# Verified columns from actual files
# =========================
def load_cic2017(filepath: str, detector: str) -> pd.DataFrame:
    print(f"  Loading CIC-IDS-2017 : {Path(filepath).name}")
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()

    df = df.rename(columns={k: v for k, v in CIC_COLUMN_MAP.items() if k in df.columns})

    # compute syn_ratio from SYN flag count and total packets
    if "syn_count" in df.columns and "total_packets" in df.columns:
        df["syn_ratio"] = df["syn_count"] / df["total_packets"].replace(0, 1)

    # unique_ports not available in CIC — fill with 0
    if "unique_ports" not in df.columns:
        df["unique_ports"] = 0

    # total_attempts = total_packets for brute force context
    if "total_attempts" not in df.columns and "total_packets" in df.columns:
        df["total_attempts"] = df["total_packets"]

    # port_focus_ratio not available — fill with 0
    if "port_focus_ratio" not in df.columns:
        df["port_focus_ratio"] = 0

    df["label"]          = df["label_raw"].apply(lambda x: standardize_label(x, "cic2017"))
    df["dataset_source"] = "cic2017"
    df = df[df["label"] != -1]

    # drop rows with inf values — CIC-IDS-2017 has some inf in Flow Packets/s
    df = df.replace([float("inf"), float("-inf")], float("nan"))

    feature_cols = FEATURES.get(detector, [])
    available    = [c for c in feature_cols if c in df.columns]
    missing      = [c for c in feature_cols if c not in df.columns]

    if missing:
        print(f"  ⚠️  Missing columns for {detector} : {missing}")
        for col in missing:
            df[col] = 0

    return df[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
# LOADER — UNSW-NB15
# Verified columns from actual file
# label col is lowercase 'label', attack col is 'attack_cat'
# =========================
def load_unsw_nb15(filepath: str, detector: str) -> pd.DataFrame:
    print(f"  Loading UNSW-NB15 : {Path(filepath).name}")
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()

    # verified column names from actual file
    column_map = {
        "rate"    : "pps",
        "dur"     : "duration",
        "spkts"   : "total_packets",
        "sinpkt"  : "avg_interval",
        "smean"   : "avg_packet_size",
        "dmean"   : "max_packet_size",
    }
    df = df.rename(columns={k: v for k, v in column_map.items() if k in df.columns})

    # UNSW label column is numeric 0/1 in 'label' (lowercase)
    df["label"]          = df["label"].apply(lambda x: standardize_label(str(x), "unsw_nb15"))
    df["dataset_source"] = "unsw_nb15"
    df = df[df["label"] != -1]

    df = df.replace([float("inf"), float("-inf")], float("nan"))

    feature_cols = FEATURES.get(detector, [])
    available    = [c for c in feature_cols if c in df.columns]
    missing      = [c for c in feature_cols if c not in df.columns]

    if missing:
        print(f"  ⚠️  Missing columns for {detector} : {missing}")
        for col in missing:
            df[col] = 0

    return df[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
# LOADER — CIRA-CIC-DoH
# Verified columns from actual file
# =========================
# LOADER — KAGGLE DNS TUNNELING QUERIES
# Dataset has no header — col 0 = label, col 1 = raw query string
# We compute all DNS features directly from the query string
# =========================
def load_dns_kaggle(filepath: str) -> pd.DataFrame:
    print(f"  Loading Kaggle DNS : {Path(filepath).name}")
    df = pd.read_csv(filepath, header=None, names=["label", "query"])

    df["label"]          = pd.to_numeric(df["label"], errors="coerce")
    df["dataset_source"] = "kaggle_dns"
    df = df.dropna(subset=["label", "query"])
    df["label"] = df["label"].astype(int)

    # =========================
    # COMPUTE FEATURES FROM RAW QUERY STRING
    # Each row is one DNS query — we simulate session-level
    # features by grouping consecutive queries into windows
    # =========================

    # strip trailing dot that DNS adds
    df["query"] = df["query"].str.rstrip(".")

    # avg_qname_len — length of the full query string
    df["avg_qname_len"] = df["query"].str.len().astype(float)

    # extract base domain (last two parts of the query)
    def base_domain(q):
        parts = str(q).split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else q

    df["base_domain"] = df["query"].apply(base_domain)

    # subdomain part — everything before the base domain
    def subdomain(q):
        parts = str(q).split(".")
        return ".".join(parts[:-2]) if len(parts) > 2 else ""

    df["subdomain_str"] = df["query"].apply(subdomain)

    # compute window-based features manually
    # rolling on string columns doesn't work in older pandas
    # so we use a pure python sliding window approach
    window = 20

    unique_domains_list      = []
    domain_diversity_list    = []
    top_domain_ratio_list    = []
    total_requests_list      = []

    base_domains = df["base_domain"].tolist()

    for i in range(len(base_domains)):
        start   = max(0, i - window + 1)
        window_vals = base_domains[start : i + 1]
        total   = len(window_vals)

        from collections import Counter
        counts  = Counter(window_vals)
        unique  = len(counts)
        top_r   = max(counts.values()) / total if total > 0 else 0
        div_r   = unique / total if total > 0 else 0

        unique_domains_list.append(float(unique))
        domain_diversity_list.append(round(div_r, 3))
        top_domain_ratio_list.append(round(top_r, 3))
        total_requests_list.append(float(total))

    df["unique_domains"]         = unique_domains_list
    df["domain_diversity_ratio"] = domain_diversity_list
    df["top_domain_ratio"]       = top_domain_ratio_list
    df["total_requests"]         = total_requests_list

    # pps — not available per query, fill with 0
    # avg_interval — not available per query, fill with 0
    # unique_qtypes — not available per query, fill with 0
    df["pps"]           = 0.0
    df["duration"]      = 0.0
    df["avg_interval"]  = 0.0
    df["unique_qtypes"] = 0

    feature_cols = FEATURES.get("dns", [])
    missing      = [c for c in feature_cols if c not in df.columns]
    if missing:
        print(f"  ⚠️  Still missing after compute : {missing}")
        for col in missing:
            df[col] = 0

    print(f"  ✅ Computed features from {len(df)} query rows")
    return df[feature_cols + ["label", "dataset_source"]].dropna().reset_index(drop=True)

# =========================
def load_cira_doh(filepath: str, detector: str) -> pd.DataFrame:
    print(f"  Loading CIRA-CIC-DoH : {Path(filepath).name}")
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()

    # verified column names from actual file
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
    missing      = [c for c in feature_cols if c not in df.columns]

    if missing:
        print(f"  ⚠️  Missing columns for {detector} : {missing}")
        for col in missing:
            df[col] = 0

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
    missing      = [c for c in feature_cols if c not in df.columns]
    for col in missing:
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

    if detector == "syn":
        for f in [
            "datasets/Wednesday-workingHours.pcap_ISCX.csv",
            "datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "datasets/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "datasets/Monday-WorkingHours.pcap_ISCX.csv",
        ]:
            if Path(f).exists(): frames.append(load_cic2017(f, detector))

    elif detector == "icmp":
        for f in [
            "datasets/Wednesday-workingHours.pcap_ISCX.csv",
            "datasets/Monday-WorkingHours.pcap_ISCX.csv",
        ]:
            if Path(f).exists(): frames.append(load_cic2017(f, detector))
        if Path("datasets/UNSW_NB15_training-set.csv").exists():
            frames.append(load_unsw_nb15("datasets/UNSW_NB15_training-set.csv", detector))

    elif detector in {"bruteforce", "ftp"}:
        if Path("datasets/Tuesday-WorkingHours.pcap_ISCX.csv").exists():
            frames.append(load_cic2017("datasets/Tuesday-WorkingHours.pcap_ISCX.csv", detector))
        if Path("datasets/Monday-WorkingHours.pcap_ISCX.csv").exists():
            frames.append(load_cic2017("datasets/Monday-WorkingHours.pcap_ISCX.csv", detector))

    elif detector == "arp":
        pass   # no public dataset with ARP-specific features
               # use attack_scripts/arp_attack.py to generate own data

    elif detector == "dns":
        # CIRA-CIC-DoH — flow level features (pps, duration, avg_interval, avg_qname_len)
        if Path("datasets/BCCC-CIRA-CIC-DoHBrw-2020.csv").exists():
            frames.append(load_cira_doh("datasets/BCCC-CIRA-CIC-DoHBrw-2020.csv", detector))
        # Kaggle DNS tunneling — query level features (avg_qname_len, unique_domains,
        # domain_diversity_ratio, top_domain_ratio, total_requests)
        for f in ["datasets/training.csv", "datasets/validating.csv"]:
            if Path(f).exists():
                frames.append(load_dns_kaggle(f))

    elif detector == "dhcp":
        pass   # own data only

    # own data
    if own_weight > 0:
        own_df = load_own(detector)
        if not own_df.empty:
            for _ in range(own_weight):
                frames.append(own_df)

    if not frames:
        print(f"  ❌ No data found for {detector}")
        return pd.DataFrame()

    # ensure all frames have identical columns before concat
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