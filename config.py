"""
config.py — Central Configuration
====================================
Single source of truth for all IDS parameters.
All detectors, AI layer, and core modules import from here.

During dashboard phase, the dashboard will read and write this file
to allow runtime configuration without restarting the IDS.

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
SYN_TIME_WINDOW         = 5     # seconds — sliding window for SYN tracking
SYN_FLOOD_RATE          = 10    # SYN packets/sec to one port → flood alert
PORT_SCAN_THRESHOLD     = 5     # unique destination ports → scan alert
SYN_ALERT_COOLDOWN      = 20    # seconds between alerts for same source IP
SYN_PRUNE_INTERVAL      = 60
SYN_AI_MIN_PACKETS      = 8     # minimum packets before AI runs

# =========================
# ICMP DETECTOR
# =========================
ICMP_TIME_WINDOW        = 5
ICMP_FLOOD_RATE         = 20    # ICMP packets/sec → flood alert
ICMP_ALERT_COOLDOWN     = 20
ICMP_PRUNE_INTERVAL     = 60
ICMP_AI_MIN_PACKETS     = 10    # minimum packets before AI runs

# =========================
# DNS DETECTOR
# =========================
DNS_TIME_WINDOW         = 5
DNS_REQUEST_THRESHOLD   = 20    # requests in window → flood alert
DNS_TUNNEL_QNAME_LEN    = 80    # avg query name length → tunnel alert
DNS_ALERT_COOLDOWN      = 20
DNS_PRUNE_INTERVAL      = 60
DNS_AI_MIN_REQUESTS     = 5     # minimum requests before AI runs

# =========================
# BRUTEFORCE DETECTOR
# =========================
BRUTE_TIME_WINDOW       = 10
BRUTE_ATTEMPT_THRESHOLD = 15    # connection attempts → brute force alert
BRUTE_ALERT_COOLDOWN    = 20
BRUTE_PRUNE_INTERVAL    = 60
BRUTE_TARGET_PORTS      = {22, 21, 23}   # ports monitored for brute force
BRUTE_AI_MIN_ATTEMPTS   = 8     # minimum attempts before AI runs

# =========================
# FTP DETECTOR
# =========================
FTP_TIME_WINDOW         = 10
FTP_ATTEMPT_THRESHOLD   = 10    # connection attempts → brute force alert
FTP_BOUNCE_THRESHOLD    = 3     # suspicious PORT commands → bounce alert
FTP_ALERT_COOLDOWN      = 20
FTP_PRUNE_INTERVAL      = 60
FTP_AI_MIN_ATTEMPTS     = 8
FTP_AI_MIN_PORT_CMDS    = 3

# =========================
# ARP DETECTOR
# =========================
ARP_RATE_WINDOW         = 10
ARP_RATE_THRESHOLD      = 5     # ARP replies/sec per IP → rate signal
ARP_NETWORK_RATE_THRESH = 50    # total ARP replies/sec across ALL IPs
ARP_ALERT_THRESHOLD     = 8     # suspicion score to fire alert (max=12)
ARP_ALERT_COOLDOWN      = 20
ARP_PRUNE_INTERVAL      = 60

# =========================
# DHCP DETECTOR
# =========================
DHCP_TIME_WINDOW        = 10
DHCP_ALERT_COOLDOWN     = 20
DHCP_PRUNE_INTERVAL     = 60
DHCP_STARVATION_PPS     = 10    # DISCOVER packets/sec per MAC
DHCP_STARVATION_MACS    = 20    # unique MACs in window → starvation
DHCP_DECLINE_THRESHOLD  = 5     # DECLINEs from same MAC → conflict attack
DHCP_RELEASE_THRESHOLD  = 8     # rapid RELEASE+DISCOVER cycles
DHCP_LEGITIMATE_SERVERS = {
    "192.168.1.1", "192.168.1.254",
    "10.0.0.1",
    "192.168.68.1", "192.168.68.2", "192.168.68.254"
}

# =========================
# AI LAYER
# =========================
AI_THRESHOLD            = 0.80  # confidence >= this to flag as attack
                                 # raise to 0.90 → fewer false positives
                                 # lower to 0.70 → catch more evasive attacks
MODELS_DIR              = "ai/models"

# =========================
# RETRAINING PIPELINE
# =========================
USE_OWN_DATA            = False  # set True when lab JSONL data is ready
                                  # enables own data in retraining pipeline
OWN_DATA_WEIGHT         = 3      # how many times to repeat own data rows
                                  # vs external datasets (amplifies own data)

# =========================
# LOGGER / LOG ROTATION
# =========================
LOG_MAX_BYTES           = 10 * 1024 * 1024   # 10MB per file
LOG_BACKUP_COUNT        = 5                   # keep 5 rotated files = 50MB max

# =========================
# PERSISTENCE
# =========================
STATE_DIR               = "data/.state"
SAVE_INTERVAL           = 60    # seconds between state saves

# =========================
# WORKER / QUEUE
# =========================
QUEUE_SIZE              = 10000  # max packets buffered before dropping
WORKER_COUNT            = 1      # single worker (class refactor needed for >1)

# =========================
# CORRELATION ENGINE
# =========================
CORRELATION_WINDOW      = 120    # seconds — track alerts in this window
CORRELATION_THRESHOLD   = 2      # distinct detector types to fire campaign
CAMPAIGN_COOLDOWN       = 300    # seconds between campaign alerts per IP

# =========================
# DISTRIBUTED DETECTOR
# =========================
DIST_WINDOW             = 30     # seconds — per-dst tracking window
DIST_SYN_THRESHOLD      = 10     # unique source IPs hitting same dst
DIST_ICMP_THRESHOLD     = 8
DIST_DNS_THRESHOLD      = 8
DIST_BRUTE_THRESHOLD    = 5
DIST_COOLDOWN           = 120    # seconds between distributed alerts per dst

# =========================
# WHITELISTS
# =========================
WHITELIST               = {"127.0.0.1"}   # IPs never flagged by any detector

# =========================
# THREAT FEED — AbuseIPDB
# =========================
THREAT_FEED_ENABLED     = False  # set True after adding API key below
ABUSEIPDB_API_KEY       = ""     # get free key at https://www.abuseipdb.com
                                  # free tier: 1000 queries/day
                                  # with caching: well within limits

# =========================
# LONG WINDOW — SLOW ATTACK DETECTION
# =========================
LW_SYN_WINDOW           = 600    # seconds — slow scan tracking window
LW_SYN_THRESHOLD        = 10     # unique ports in window → slow scan alert
LW_SYN_COOLDOWN         = 600

LW_BRUTE_WINDOW         = 600    # seconds — slow brute force window
LW_BRUTE_THRESHOLD      = 20     # attempts in window → slow brute alert
LW_BRUTE_COOLDOWN       = 600

LW_DNS_WINDOW           = 300    # seconds — slow DNS flood window
LW_DNS_THRESHOLD        = 40     # requests in window → slow DNS alert
LW_DNS_COOLDOWN         = 300