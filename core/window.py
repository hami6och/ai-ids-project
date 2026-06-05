from collections import deque


def clean_old(dq: deque, now: float, window: float, ts_index=None):
    """
    Evict entries older than `window` seconds from the left of the deque.
    O(1) per removal using popleft().

    ts_index — position of the timestamp in each tuple entry.
               None means each entry IS the timestamp (no tuple).

    Detector        storage shape                ts_index
    --------        -------------                --------
    ARP             deque[float]                 None
    ICMP            deque[(ts, size)]            0
    DNS             deque[(ts, qname, qtype)]    0
    SYN             deque[(port, ts)]            1
    Bruteforce      deque[(port, ts, flags)]     1
    FTP attempts    deque[(ts, flags)]           0
    FTP bounce      deque[(ts, target_ip)]       0
    DHCP requests   deque[(ts, msg_type)]        0
    DHCP declines   deque[float]                 None
    DHCP releases   deque[float]                 None
    DHCP offers     deque[float]                 None

    Usage:
        from core.window import clean_old, prune_stale
        clean_old(traffic_data[ip], now, TIME_WINDOW, ts_index=0)
    """
    while dq:
        entry = dq[0]
        ts = entry if ts_index is None else entry[ts_index]
        if now - ts > window:
            dq.popleft()
        else:
            break


def prune_stale(main_dict: dict, *related_dicts):
    """
    Delete keys with empty deques from main_dict and any related dicts.
    Call periodically (every PRUNE_INTERVAL seconds), not on every packet.

    Usage:
        prune_stale(traffic_data, alerted_ips)
        prune_stale(packet_times, mac_history, alerted_ips)   # ARP has 3
        prune_stale(mac_requests, mac_declines, mac_releases, alerted_macs)  # DHCP
    """
    stale = [key for key, dq in main_dict.items() if not dq]
    for key in stale:
        del main_dict[key]
        for d in related_dicts:
            d.pop(key, None)