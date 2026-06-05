"""
config.py — Central Configuration
====================================
Single source of truth for all IDS parameters.
All detectors, AI layer, and core modules import from here.

HOW TO TUNE :
    Raise threshold   → fewer alerts, may miss slow attacks
    Lower threshold   → more alerts, may increase false positives
    Raise window      → catches slow/patient attacks, uses more memory
    Lower window      → faster response, misses patient attackers
"""

# =========================
# NETWORK INTERFACE
# =========================
IFACE = None    # None = auto-detect. Set to "eth0", "ens33" etc for explicit

# =========================
# SYN DETECTOR
# =========================
SYN_TIME_WINDOW         = 5
SYN_FLOOD_RATE          = 10
PORT_SCAN_THRESHOLD     = 5
SYN_ALERT_COOLDOWN      = 20
SYN_PRUNE_INTERVAL      = 60
SYN_AI_MIN_PACKETS      = 8

# =========================
# ICMP DETECTOR
# =========================
ICMP_TIME_WINDOW        = 5
ICMP_FLOOD_RATE         = 20
ICMP_ALERT_COOLDOWN     = 20
ICMP_PRUNE_INTERVAL     = 60
ICMP_AI_MIN_PACKETS     = 10

# =========================
# DNS DETECTOR
# =========================
DNS_TIME_WINDOW         = 5
DNS_REQUEST_THRESHOLD   = 30    # raised from 20 — 20 fires on normal page loads
DNS_TUNNEL_QNAME_LEN    = 50
DNS_ALERT_COOLDOWN      = 20
DNS_PRUNE_INTERVAL      = 60
DNS_AI_MIN_REQUESTS     = 10    # raised from 5 — fewer = normal browsing
DNS_FLOOD_MIN_PPS       = 10    # min pps to fire DNS_FLOOD

# =========================
# BRUTEFORCE DETECTOR
# =========================
BRUTE_TIME_WINDOW       = 10
BRUTE_ATTEMPT_THRESHOLD = 15
BRUTE_ALERT_COOLDOWN    = 20
BRUTE_PRUNE_INTERVAL    = 60
BRUTE_TARGET_PORTS      = {22, 21, 23}
BRUTE_AI_MIN_ATTEMPTS   = 8

# =========================
# FTP DETECTOR
# =========================
FTP_TIME_WINDOW         = 10
FTP_ATTEMPT_THRESHOLD   = 10
FTP_BOUNCE_THRESHOLD    = 3
FTP_ALERT_COOLDOWN      = 20
FTP_PRUNE_INTERVAL      = 60
FTP_AI_MIN_ATTEMPTS     = 8
FTP_AI_MIN_PORT_CMDS    = 3

# =========================
# ARP DETECTOR
# =========================
ARP_RATE_WINDOW         = 10
ARP_RATE_THRESHOLD      = 5
ARP_NETWORK_RATE_THRESH = 50
ARP_ALERT_THRESHOLD     = 8
ARP_ALERT_COOLDOWN      = 20
ARP_PRUNE_INTERVAL      = 60

# =========================
# DHCP DETECTOR
# =========================
DHCP_TIME_WINDOW        = 10
DHCP_ALERT_COOLDOWN     = 20
DHCP_PRUNE_INTERVAL     = 60
DHCP_STARVATION_PPS     = 10
DHCP_STARVATION_MACS    = 20
DHCP_DECLINE_THRESHOLD  = 5
DHCP_RELEASE_THRESHOLD  = 8
DHCP_LEGITIMATE_SERVERS = {
    "192.168.1.1", "192.168.1.254",
    "10.0.0.1",
    "192.168.68.1", "192.168.68.2", "192.168.68.254",
    "192.168.100.1",
    "192.168.56.254", "192.168.24.254"
    # NOTE : MAC addresses removed — DHCP_LEGITIMATE_SERVERS must be IP addresses only
    # The detector checks src_ip against this set, not MAC addresses
}

# =========================
# AI LAYER
# =========================
AI_THRESHOLD            = 0.80
MODELS_DIR              = "ai/models"

# =========================
# PER-DETECTOR AI THRESHOLDS
# =========================
AI_THRESHOLD_SYN        = 0.75   # raised — 0.60 fires on normal HTTPS browsing
AI_THRESHOLD_ICMP       = 0.80
AI_THRESHOLD_DNS        = 0.75   # raised — 0.60 fires on normal DNS lookups
AI_THRESHOLD_BRUTEFORCE = 0.80
AI_THRESHOLD_FTP        = 0.80
AI_THRESHOLD_ARP        = 0.80
AI_THRESHOLD_DHCP       = 0.80

# =========================
# MODEL MODE
# =========================
MODEL_MODE              = "best"      # "ensemble" | "best" | "force_rf" | "force_xgb"
ENSEMBLE_RF_WEIGHT      = 0.5
ENSEMBLE_XGB_WEIGHT     = 0.5

# =========================
# RETRAINING PIPELINE
# =========================
USE_OWN_DATA            = False
OWN_DATA_WEIGHT         = 3

# =========================
# LOGGER / LOG ROTATION
# =========================
LOG_MAX_BYTES           = 10 * 1024 * 1024
LOG_BACKUP_COUNT        = 5

# =========================
# PERSISTENCE
# =========================
STATE_DIR               = "data/.state"
SAVE_INTERVAL           = 60

# =========================
# WORKER / QUEUE
# =========================
QUEUE_SIZE              = 10000
WORKER_COUNT            = 1

# =========================
# CORRELATION ENGINE
# =========================
CORRELATION_WINDOW      = 120
CORRELATION_THRESHOLD   = 2
CAMPAIGN_COOLDOWN       = 300

# =========================
# DISTRIBUTED DETECTOR
# =========================
DIST_WINDOW             = 30
DIST_SYN_THRESHOLD      = 10
DIST_ICMP_THRESHOLD     = 8
DIST_DNS_THRESHOLD      = 8
DIST_BRUTE_THRESHOLD    = 5
DIST_COOLDOWN           = 120

# =========================
# WHITELISTS
# =========================
WHITELIST               = {"127.0.0.1"}

# =========================
# THREAT FEED — AbuseIPDB
# =========================
THREAT_FEED_ENABLED     = False
ABUSEIPDB_API_KEY       = ""

# =========================
# LONG WINDOW — SLOW ATTACK DETECTION
# =========================
LW_SYN_WINDOW           = 600
LW_SYN_THRESHOLD        = 10
LW_SYN_COOLDOWN         = 600

LW_BRUTE_WINDOW         = 600
LW_BRUTE_THRESHOLD      = 20
LW_BRUTE_COOLDOWN       = 600

LW_DNS_WINDOW           = 300
LW_DNS_THRESHOLD        = 40
LW_DNS_COOLDOWN         = 300

# =========================
# MULTI-SOURCE BRUTE FORCE
# =========================
MULTI_SOURCE_WINDOW     = 60
MULTI_SOURCE_THRESHOLD  = 8
MULTI_SOURCE_COOLDOWN   = 120

# =========================
# ICMP REDIRECT DETECTION
# =========================
KNOWN_GATEWAYS          = {
    "192.168.68.1", "192.168.68.2",
    "10.0.0.1",
    "192.168.1.1",
    "192.168.100.1",
    "192.168.56.254"
}
ICMP_REDIRECT_COOLDOWN  = 60

# =========================
# DATABASE — SQLite
# =========================
SQLITE_DB_PATH          = "data/ids.db"