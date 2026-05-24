"""
core/persistence.py — State Persistence
========================================
Saves and restores runtime state so the IDS resumes where it left off
after a restart. Without this, arp_table, alerted_ips and other
in-memory state is lost every time manager.py stops.

What gets saved :
    arp_table       — known IP → MAC mappings (prevents false mac_changed alerts on restart)
    alerted_ips     — last alert timestamp per IP (prevents alert storms on restart)
    mac_history     — unique MACs seen per IP
    server_seen     — first-seen timestamp per DHCP server

Usage in detectors :
    from core.persistence import StateManager
    state = StateManager("data/.state/arp.pkl")
    state.restore(arp_table, alerted_ips, mac_history)   # call at startup
    # state auto-saves every SAVE_INTERVAL seconds on each packet

Usage in manager.py :
    from core.persistence import save_all, restore_all
    restore_all()    # call before sniff()
    # saving happens automatically inside each detector
"""

import pickle
import os
import time
import threading
from pathlib import Path

# =========================
# CONFIG
# =========================
from config import STATE_DIR, SAVE_INTERVAL


class StateManager:
    """
    Manages persistence for one detector's state dicts.
    Auto-saves on a background timer every SAVE_INTERVAL seconds.
    Thread-safe via a lock.
    """

    def __init__(self, filepath: str, save_interval: int = SAVE_INTERVAL):
        self.filepath      = filepath
        self.save_interval = save_interval
        self._dicts        = []       # list of dicts to save/restore
        self._lock         = threading.Lock()
        self._last_save    = time.time()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

    def register(self, *dicts):
        """
        Register state dicts to be saved/restored.
        Order must match between register() and restore() calls.

        Example :
            state.register(arp_table, alerted_ips, mac_history)
        """
        self._dicts = list(dicts)

    def save(self):
        """Save all registered dicts to disk."""
        with self._lock:
            try:
                with open(self.filepath, "wb") as f:
                    pickle.dump(self._dicts, f)
            except Exception as e:
                print(f"⚠️  State save failed ({self.filepath}): {e}")

    def restore(self):
        """
        Load saved state from disk and update registered dicts in-place.
        Returns True if state was restored, False if no saved state found.
        """
        if not Path(self.filepath).exists():
            return False

        try:
            with open(self.filepath, "rb") as f:
                saved = pickle.load(f)

            # update dicts in-place so detector's local references stay valid
            for target, source in zip(self._dicts, saved):
                target.update(source)

            print(f"  ✅ State restored from {self.filepath}")
            return True

        except Exception as e:
            print(f"  ⚠️  State restore failed ({self.filepath}): {e}")
            return False

    def maybe_save(self, now: float = None):
        """
        Call this on every packet. Saves only if SAVE_INTERVAL has elapsed.
        Designed to be called inside detect() with zero overhead most of the time.

        Example in detect() :
            state.maybe_save(now)
        """
        now = now or time.time()
        if now - self._last_save >= self.save_interval:
            self.save()
            self._last_save = now

    def clear(self):
        """Delete saved state file — useful for testing or fresh start."""
        try:
            os.remove(self.filepath)
            print(f"  🗑️  State cleared: {self.filepath}")
        except FileNotFoundError:
            pass


# =========================
# CONVENIENCE — one StateManager per detector
# Pre-instantiated so detectors just import and use
# =========================
state_syn        = StateManager(f"{STATE_DIR}/syn.pkl")
state_arp        = StateManager(f"{STATE_DIR}/arp.pkl")
state_icmp       = StateManager(f"{STATE_DIR}/icmp.pkl")
state_dns        = StateManager(f"{STATE_DIR}/dns.pkl")
state_bruteforce = StateManager(f"{STATE_DIR}/bruteforce.pkl")
state_ftp        = StateManager(f"{STATE_DIR}/ftp.pkl")
state_dhcp       = StateManager(f"{STATE_DIR}/dhcp.pkl")


def save_all():
    """Save all detector states — call on shutdown."""
    for s in [state_syn, state_arp, state_icmp, state_dns,
              state_bruteforce, state_ftp, state_dhcp]:
        s.save()
    print("💾 All state saved.")


def restore_all():
    """Restore all detector states — call at startup in manager.py."""
    print("🔄 Restoring IDS state...")
    for s in [state_syn, state_arp, state_icmp, state_dns,
              state_bruteforce, state_ftp, state_dhcp]:
        s.restore()