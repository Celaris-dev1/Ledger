"""On-disk JSONL spool used by ``Ledger`` so records survive process/ledgerd outages.

Records are appended as JSON lines before being handed to the background sender, and are only
removed from the file once the server has accepted them. On restart, any leftover lines are
loaded and replayed in their original order before newly queued records are sent, so writes
made while ledgerd (or the network) was unavailable are never lost or reordered.

This is intentionally simple (whole-file rewrite on pop) rather than a segmented log: SDK
throughput is bounded by HTTP round trips anyway, and simplicity here means fewer ways for the
durability guarantee itself to have a bug.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional


class Spool:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._lines: List[str] = []
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as f:
            self._lines = [ln for ln in f.read().splitlines() if ln.strip()]

    def _rewrite(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for ln in self._lines:
                f.write(ln + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def push(self, record: Dict[str, Any]) -> None:
        """Durably append a record. Returns only after it is safely on disk."""
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._lines.append(line)

    def peek_front(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not self._lines:
                return None
            return json.loads(self._lines[0])

    def pop_front(self) -> None:
        with self._lock:
            if not self._lines:
                return
            self._lines.pop(0)
            self._rewrite()

    def drop_front(self, n: int) -> None:
        """Evict the oldest n entries without sending them (bounded-queue overflow policy)."""
        with self._lock:
            if n <= 0:
                return
            del self._lines[:n]
            self._rewrite()

    def __len__(self) -> int:
        with self._lock:
            return len(self._lines)

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [json.loads(ln) for ln in self._lines]


__all__ = ["Spool"]
