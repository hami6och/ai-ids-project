import json
import atexit
import os


class Logger:
    """
    Persistent JSONL logger.
    Opens the file once, flushes on every write, closes safely on exit.
    Creates the parent directory automatically if it does not exist.

    Usage:
        from core.logger import Logger
        logger = Logger("data/syn_dataset.jsonl")
        logger.log({"timestamp": ..., "pps": ...})
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        os.makedirs(os.path.dirname(filepath), exist_ok=True)  # create data/ if missing
        self._file = open(filepath, "a")
        atexit.register(self.close)

    def log(self, data: dict):
        self._file.write(json.dumps(data) + "\n")
        self._file.flush()

    def close(self):
        if not self._file.closed:
            self._file.close()