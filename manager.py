from scapy.all import sniff, conf
from detectors import syn, arp, icmp, dns, bruteforce, ftp, dhcp
from ai.predict  import preload_all
from core.persistence import restore_all, save_all
import atexit

# =========================
# IFACE
# =========================
IFACE = None    # None = auto-detect

# =========================
# UNIFIED PACKET ROUTER
# =========================
def route(packet):
    syn.detect(packet)
    arp.detect_arp(packet)
    icmp.detect(packet)
    dns.detect(packet)
    bruteforce.detect(packet)
    ftp.detect(packet)
    dhcp.detect(packet)

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 AI-IDS MANAGER RUNNING on [{iface}]")
    print("   Detectors: SYN | ARP | ICMP | DNS | BRUTEFORCE | FTP | DHCP")
    restore_all()   # restore detector state from last session
    preload_all()   # load all ML models into memory before sniffing
    atexit.register(save_all)   # save state on exit
    sniff(
        iface=iface,
        prn=route,
        store=0
    )