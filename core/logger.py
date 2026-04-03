import json
import atexit


class Logger:
    """
    Persistent JSONL logger.
    Opens the file once, flushes on every write, closes safely on exit.

    Usage:
        from core.logger import Logger
        logger = Logger("data/syn_dataset.jsonl")
        logger.log({"timestamp": ..., "pps": ...})
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file = open(filepath, "a")
        atexit.register(self.close)

    def log(self, data: dict):
        self._file.write(json.dumps(data) + "\n")
        self._file.flush()

    def close(self):
        if not self._file.closed:
            self._file.close()