"""
core/worker.py — Producer/Consumer Worker
==========================================
Decouples packet capture from packet processing.
Scapy's sniff thread only enqueues packets (microseconds).
The worker thread processes them at its own pace (no drops).

Architecture :
    sniff thread  →  queue.put(packet)     ultra fast, never blocks
    worker thread →  queue.get() → route() processes at own pace

Stats are tracked for dashboard monitoring :
    packets_received  — total packets seen by sniff
    packets_processed — total packets processed by worker
    packets_dropped   — queue was full (overload indicator)
    queue_size        — current queue depth
"""

import queue
import threading
import time
from collections import defaultdict

# =========================
# CONFIG
# =========================
QUEUE_SIZE   = 10000   # max packets in queue before dropping
WORKER_COUNT = 1       # single worker — detectors share global state
                       # increase only after class-based refactor

# =========================
# STATS
# =========================
stats = {
    "packets_received"  : 0,
    "packets_processed" : 0,
    "packets_dropped"   : 0,
    "queue_size"        : 0,
    "start_time"        : time.time(),
}

# =========================
# QUEUE
# =========================
packet_queue = queue.Queue(maxsize=QUEUE_SIZE)
_stop_event  = threading.Event()


def enqueue(packet):
    """
    Called by Scapy's sniff() on every packet — must be ultra fast.
    Just puts the packet in the queue and returns immediately.
    Never blocks — drops packet if queue is full (backpressure).
    """
    stats["packets_received"] += 1
    try:
        packet_queue.put_nowait(packet)
    except queue.Full:
        stats["packets_dropped"] += 1


def start_worker(route_fn):
    """
    Start the worker thread that reads from the queue and calls route_fn.
    route_fn is manager.py's route() function that dispatches to detectors.

    Returns the thread object so manager.py can join it on shutdown.
    """
    def _worker_loop():
        while not _stop_event.is_set() or not packet_queue.empty():
            try:
                # timeout=0.1 so thread checks _stop_event regularly
                packet = packet_queue.get(timeout=0.1)
                route_fn(packet)
                packet_queue.task_done()
                stats["packets_processed"] += 1
                stats["queue_size"] = packet_queue.qsize()
            except queue.Empty:
                continue
            except Exception as e:
                # never crash the worker — log and continue
                print(f"⚠️  Worker error: {e}")
                stats["packets_processed"] += 1

    thread = threading.Thread(target=_worker_loop, daemon=True, name="ids-worker")
    thread.start()
    return thread


def stop_worker(thread, timeout=10):
    """
    Signal the worker to stop and wait for it to drain the queue.
    Called by manager.py on shutdown.
    """
    print(f"⏳ Draining queue ({packet_queue.qsize()} packets remaining)...")
    _stop_event.set()
    thread.join(timeout=timeout)
    if thread.is_alive():
        print("⚠️  Worker did not stop cleanly within timeout")
    else:
        print("✅ Worker stopped cleanly")


def get_stats() -> dict:
    """Return current stats — polled by dashboard."""
    elapsed = time.time() - stats["start_time"]
    return {
        **stats,
        "queue_size"    : packet_queue.qsize(),
        "uptime_seconds": round(elapsed, 1),
        "pps_avg"       : round(stats["packets_processed"] / max(elapsed, 1), 1),
        "drop_rate_pct" : round(
            stats["packets_dropped"] / max(stats["packets_received"], 1) * 100, 2
        ),
    }