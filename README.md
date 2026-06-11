# 🛡️ AI-IDS — Intelligent Intrusion Detection System

![Python](https://img.shields.io/badge/Python-14354C?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2C2D72?style=for-the-badge&logo=python&logoColor=white)
![ML](https://img.shields.io/badge/Machine_Learning-FF6F00?style=for-the-badge&logo=scikitlearn&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)

## 📌 Overview

**AI-IDS** is a full-stack network intrusion detection system built as a 4th-year cybersecurity engineering capstone at **Université Saad Dahleb Blida 1**.

It combines **rule-based detection** with a **Random Forest + XGBoost ML layer** to detect and classify 7 attack categories in real time. All traffic is stored in a local **SQLite** database and visualized through a **React dashboard** with live config updates.

> ⚠️ **Intended for ethical and educational use only.**  
> Deploy only on networks you own or have explicit permission to monitor.

---

## 🏗️ Architecture

```
Network Traffic
      │
      ▼
  Scapy sniff()
      │
      ▼
  Queue (10,000 packets)
      │
      ▼
  Worker Thread
      │
      ▼
┌──────────────────────────────────────────┐
│              7 Detectors                 │
│  SYN · ARP · ICMP · DNS                 │
│  BruteForce · FTP · DHCP                │
│                                          │
│  Rule-Based ──→ AI/ML Layer             │
│  (thresholds)    (RF + XGBoost)         │
└──────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────┐
│  Correlation + Long Window               │
│  + Distributed Detection                 │
└──────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────┐
│  Terminal  │  JSONL logs  │  SQLite DB   │
└──────────────────────────────────────────┘
      │
      ▼
  React Dashboard (port 3000)
  Node.js API  (port 3001)
```

---

## 🎯 Detection Layers

### 🔴 Rule-Based Detection

| Detector | Attack Types Detected |
|---|---|
| `SYNDetector` | SYN_FLOOD · SYN_SCAN · SLOW_SYN_SCAN |
| `ICMPDetector` | ICMP_FLOOD · ICMP_REDIRECT |
| `DNSDetector` | DNS_FLOOD · DNS_TUNNEL · DNS_AI · SLOW_DNS_FLOOD |
| `BruteForceDetector` | BRUTE_FORCE · CREDENTIAL_STUFFING · MULTI_SOURCE_BRUTE · SLOW_BRUTE_FORCE |
| `FTPDetector` | FTP_BRUTE_FORCE · FTP_BOUNCE |
| `ARPDetector` | ARP_SPOOFING (score-based, threshold = 8/12) |
| `DHCPDetector` | DHCP_STARVATION · DHCP_ROGUE_SERVER · DHCP_DECLINE_FLOOD · DHCP_RAPID_CYCLING |

### 🤖 AI/ML Layer

Each detector has an independent ML model trained on real-world datasets.  
The system automatically selects the best model (RF or XGBoost) per detector.

| Detector | Best Model | F1 Score |
|---|---|---|
| SYN | Random Forest | **0.9965** |
| ICMP | Random Forest | **0.9780** |
| DNS | Random Forest | **0.9922** |
| BruteForce | XGBoost | **0.9991** |
| FTP | XGBoost | **0.9991** |

**Triple-label alert system:**

| Label | Meaning |
|---|---|
| `RULE` | Triggered by rule-based threshold only |
| `AI_ONLY` | Triggered by ML model only (sub-threshold traffic) |
| `RULE+AI` | Both rule and ML agree — highest confidence |

### 🔍 Advanced Detection Layers

| Layer | Description |
|---|---|
| **Long Window** | Detects slow/stealthy attacks stretched over minutes |
| **Correlation Engine** | Links related alerts into attack campaigns |
| **Distributed Detection** | Tracks coordinated multi-source attacks |

---

## 📂 Project Structure

```
ai-ids/
├── manager.py                  ← Entry point, runs all detectors
├── config.py                   ← All thresholds and settings (centralized)
│
├── detectors/                  ← 7 detector classes
│   ├── syn.py
│   ├── arp.py
│   ├── icmp.py
│   ├── dns.py
│   ├── bruteforce.py
│   ├── ftp.py
│   └── dhcp.py
│
├── core/                       ← Engine components
│   ├── alert_store.py          ← SQLite storage (thread-safe)
│   ├── alerting.py             ← Alert builder
│   ├── correlation.py          ← Campaign correlation
│   ├── distributed.py          ← Multi-source tracking
│   ├── long_window.py          ← Slow attack detection
│   ├── persistence.py          ← State persistence (.pkl)
│   ├── threat_feed.py          ← Threat intelligence feed
│   ├── window.py               ← Sliding window utility
│   └── worker.py               ← Packet queue worker
│
├── ai/                         ← ML pipeline
│   ├── train.py                ← Train RF + XGBoost models
│   ├── predict.py              ← Inference engine
│   ├── retrain.py              ← Online retraining
│   └── load_datasets.py        ← Dataset loader + feature engineering
│
├── dashboard/
│   ├── backend/                ← Node.js + Express + WebSocket (port 3001)
│   │   └── server.js
│   └── frontend/               ← React + Vite (port 3000)
│       └── src/
│           ├── components/pages/
│           │   ├── LiveFeed.jsx
│           │   ├── Statistics.jsx
│           │   ├── Detectors.jsx
│           │   ├── ThreatMap.jsx
│           │   ├── SystemHealth.jsx
│           │   └── Settings.jsx
│           └── App.jsx
│
├── ai/models/                  ← Trained models (git-ignored except metrics)
│   └── metrics.json            ← F1 scores and model comparison
│
└── data/                       ← Runtime data (git-ignored)
    └── ids.db                  ← SQLite database
```

---

## 📦 Datasets

The ML models were trained on the following publicly available datasets.  
Download them and place all CSV files inside a `datasets/` folder at the project root.

### 1. CIC-IDS-2017
- **Source:** Canadian Institute for Cybersecurity
- **URL:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Files needed:**
  - `Monday-WorkingHours.pcap_ISCX.csv`
  - `Tuesday-WorkingHours.pcap_ISCX.csv`
  - `Wednesday-workingHours.pcap_ISCX.csv`
  - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
  - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
- **Used for:** SYN flood, port scan, brute force, DoS detection

### 2. CIC-IDS-2018
- **Source:** Canadian Institute for Cybersecurity
- **URL:** https://www.unb.ca/cic/datasets/ids-2018.html
- **Files needed:**
  - `02-14-2018.csv`
  - `02-16-2018.csv`
- **Used for:** brute force, FTP patternss, infiltration attacks

### 3. UNSW-NB15
- **Source:** Australian Centre for Cyber Security (UNSW)
- **URL:** https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Files needed:**
  - `UNSW_NB15_training-set.csv`
- **Used for:** general multi-class attack classification (includes DoS, Fuzzers, Backdoor, Exploits, Reconnaissance)

### 4. CIRA-CIC-DoHBrw-2020
- **Source:** Canadian Institute for Cybersecurity
- **URL:** https://www.unb.ca/cic/datasets/dohbrw-2020.html
- **Files needed:**
  - `BCCC-CIRA-CIC-DoHBrw-2020.csv`
- **Used for:** DNS-over-HTTPS tunnel detection

### 5. Kaggle DNS Dataset
- **Source:** Kaggle
- **URL:** https://www.kaggle.com/datasets/elmouatezbillahnacer/dns-tunneling-dataset
- **Files needed:**
  - `training.csv`
  - `validating.csv`
- **Used for:** DNS tunneling and DNS flood detection

### Folder layout after download
```
ai-ids/
└── datasets/
    ├── Monday-WorkingHours.pcap_ISCX.csv
    ├── Tuesday-WorkingHours.pcap_ISCX.csv
    ├── Wednesday-workingHours.pcap_ISCX.csv
    ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
    ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
    ├── 02-14-2018.csv
    ├── 02-16-2018.csv
    ├── UNSW_NB15_training-set.csv
    ├── BCCC-CIRA-CIC-DoHBrw-2020.csv
    ├── training.csv
    └── validating.csv
```

> The `datasets/` folder is git-ignored. You must download these files manually before training.

---

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Node.js 18+
- Root / sudo privileges (required for raw packet capture)
- Linux recommended (Kali, Ubuntu)

### 1. Clone the repository
```bash
git clone https://github.com/hami6och/ai-ids-project.git
cd ai-ids-project
```

### 2. Install Python dependencies
```bash
sudo pip install scapy scikit-learn xgboost numpy pandas --break-system-packages
```

> `sqlite3` is part of Python's standard library — no installation needed.

### 3. Install Node.js dependencies
```bash
cd dashboard/backend && npm install
cd ../frontend && npm install
cd ../..
```

### 4. Download datasets
Follow the [Datasets](#-datasets) section above, place all CSV files in `datasets/`.

### 5. Train the ML models
```bash
python3 ai/train.py
```

Trained models are saved to `ai/models/` as `.pkl` files. This step is required before running the IDS.

### 6. Create runtime directories
```bash
mkdir -p data data/.state
```

---

## ▶️ Usage

```bash
# Terminal 1 — IDS engine (requires root for packet capture)
sudo python3 manager.py

# Terminal 2 — Backend API
cd dashboard/backend && node server.js

# Terminal 3 — Frontend
cd dashboard/frontend && npm run dev
```

Open **http://localhost:3000** in your browser.

---

## 📊 Dashboard

| Page | Description |
|---|---|
| **Live Feed** | Real-time alert stream with type, severity, confidence, and source IP |
| **Statistics** | Attack distribution charts, detection rates over time |
| **Detectors** | Per-detector status, packet counts, alert counts |
| **Threat Map** | Geographic visualization of attack source IPs |
| **System Health** | Queue usage, CPU, memory, packet drop rate |
| **Configuration** | Live threshold editing — changes apply without restart |

### Live Config Update
The dashboard writes threshold changes directly to the SQLite `config` table.  
`manager.py` polls this table every **30 seconds** and applies updates at runtime — no restart required.

---

## 🗄️ SQLite Schema

```sql
-- Alerts (label = 1 only)
CREATE TABLE alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT,
    detector    TEXT,
    attack_type TEXT,
    severity    TEXT,
    source_ip   TEXT,
    dest_ip     TEXT,
    label_type  TEXT,    -- RULE / AI_ONLY / RULE+AI
    confidence  REAL,
    details     TEXT
);

-- All traffic (label 0 and 1)
CREATE TABLE traffic (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip    TEXT,
    dst_ip    TEXT,
    protocol  TEXT,
    label     INTEGER   -- 0 = normal, 1 = attack
);

-- Live configuration
CREATE TABLE config (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT
);
```

---

## ✅ Test Results

| Test Suite | Result |
|---|---|
| Legitimate traffic (8 scenarios) | ✅ **0 / 8** false positives |
| Standard attacks (13 types) | ✅ **13 / 13** detected |
| AI evasive attacks (6 types) | ✅ **5 / 6** detected |
| Queue drop rate | ✅ **0.0%** (2,657 packets) |

---

## ⚙️ Key Configuration (`config.py`)

```python
# AI confidence thresholds (tuned to eliminate false positives)
AI_THRESHOLD_SYN        = 0.75
AI_THRESHOLD_ICMP       = 0.80
AI_THRESHOLD_DNS        = 0.75
AI_THRESHOLD_BRUTEFORCE = 0.80
AI_THRESHOLD_FTP        = 0.80

# DNS false positive fixes
DNS_REQUEST_THRESHOLD   = 30
DNS_FLOOD_MIN_PPS       = 10
DNS_AI_MIN_REQUESTS     = 10

# Storage
SQLITE_DB_PATH          = "data/ids.db"

# Known safe hosts
KNOWN_GATEWAYS          = ["192.168.100.1", "192.168.56.254"]
DHCP_LEGITIMATE_SERVERS = ["192.168.68.1"]
```

All thresholds can also be changed live from the dashboard Configuration page without restarting the IDS.

---

## 🖥️ Lab Environment

| Component | Details |
|---|---|
| IDS Machine | Kali Linux · 192.168.68.130 · eth0 |
| Attacker Machine | Kali Linux · 192.168.68.131 |
| Network Simulator | GNS3 + VMware Workstation |
| Router | VyOS |

---

## 📜 License

Built as an academic cybersecurity capstone project.  
Intended for ethical learning, lab environments, and research only.  
Unauthorized use on networks without permission is prohibited.