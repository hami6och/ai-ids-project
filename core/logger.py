import json
import atexit
import os
from logging.handlers import RotatingFileHandler
import logging


class Logger:
    """
    Persistent JSONL logger with automatic rotation.
    Creates the parent directory automatically if it does not exist.

    Rotation config :
        max_bytes    : max file size before rotation (default 10MB)
        backup_count : number of rotated files to keep (default 5)

    Example with defaults :
        logger = Logger("data/syn_dataset.jsonl")
        → rotates at 10MB, keeps syn_dataset.jsonl.1 ... .5

    Example with custom limits :
        logger = Logger("data/syn_dataset.jsonl", max_bytes=5*1024*1024, backup_count=3)

    Usage :
        from core.logger import Logger
        logger = Logger("data/syn_dataset.jsonl")
        logger.log({"timestamp": ..., "pps": ...})
    """

    def __init__(self,
                 filepath: str,
                 max_bytes: int = 10 * 1024 * 1024,   # 10 MB per file
                 backup_count: int = 5):               # keep 5 rotated files = 50MB max

        self.filepath = filepath
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # use Python's RotatingFileHandler for reliable rotation
        self._handler = RotatingFileHandler(
            filepath,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8"
        )

        # wrap in a logger instance — one per filepath
        self._logger = logging.getLogger(f"ids.{filepath}")
        self._logger.setLevel(logging.INFO)

        # avoid adding duplicate handlers if Logger is reinstantiated
        if not self._logger.handlers:
            self._logger.addHandler(self._handler)

        # prevent propagation to root logger (no console output)
        self._logger.propagate = False

        atexit.register(self.close)

    def log(self, data: dict):
        """Write one JSON record. Rotation happens automatically."""
        self._handler.emit(
            logging.makeLogRecord({
                "msg"    : json.dumps(data, ensure_ascii=False),
                "level"  : logging.INFO,
                "name"   : self._logger.name
            })
        )

    def close(self):
        self._handler.close()
        self._logger.removeHandler(self._handler)

    @property
    def current_size_mb(self) -> float:
        """Current log file size in MB — useful for monitoring."""
        try:
            return os.path.getsize(self.filepath) / (1024 * 1024)
        except FileNotFoundError:
            return 0.0