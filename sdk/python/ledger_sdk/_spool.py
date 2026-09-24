"""On-disk JSONL spool used by ``Ledger`` so records survive process/ledgerd outages.

Records are appended as JSON lines before being handed to the background sender, and are only
removed from the file once the server has accepted them. On restart, any leftover lines are
loaded and replayed in their original order before newly queued records are sent, so writes
made while ledgerd (or the network) was unavailable are never lost or reordered.

This is intentionally simple (whole-file rewrite on pop) rather than a segmented log: SDK
throughput is bounded by HTTP round trips anyway, and simplicity here means fewer ways for the
durability guarantee itself to have a bug.

Security: the spool holds unsent evidence and is replayed with the client's token, so it is
private to the current user. Files are created 0600 without following symlinks, and an
existing spool that another user owns, or that others can write, is refused rather than
replayed (otherwise a local user could pre-create it and inject records sent under your
identity, or point it at another file to clobber).
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class SpoolSecurityError(RuntimeError):
    pass


def _check_owned(st: os.stat_result, what: str) -> None:
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise SpoolSecurityError(f"ledger spool {what} is owned by uid {st.st_uid}, not you; refusing to use it")
    if os.name == "posix" and st.st_mode & 0o022:
        raise SpoolSecurityError(f"ledger spool {what} is writable by other users; refusing to use it")


def _open_private(path: str, flags: int):
    fd = os.open(path, flags | _NOFOLLOW, 0o600)
    try:
        _check_owned(os.fstat(fd), path)
        if os.name == "posix":
            os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    return fd


def private_dir(base: str) -> str:
    """Return a per-user 0700 directory under base, verifying ownership (shared /tmp safe)."""
    uid = os.getuid() if hasattr(os, "getuid") else None
    d = os.path.join(base, f"ledger-sdk-{uid}" if uid is not None else "ledger-sdk")
    try:
        os.mkdir(d, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(d)
    import stat as _stat
    if not _stat.S_ISDIR(st.st_mode):
        raise SpoolSecurityError(f"ledger spool dir {d} is not a directory (symlink?); refusing to use it")
    _check_owned(st, d)
    if os.name == "posix" and st.st_mode & 0o077:
        os.chmod(d, 0o700)
    return d


class Spool:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._lines: List[str] = []
        self._load()

    def _load(self) -> None:
        try:
            fd = _open_private(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            self._lines = [ln for ln in f.read().splitlines() if ln.strip()]

    def _rewrite(self) -> None:
        tmp = self.path + ".tmp"
        try:
            os.unlink(tmp)  # never write through a pre-planted file or symlink
        except FileNotFoundError:
            pass
        with os.fdopen(_open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL), "w", encoding="utf-8") as f:
            for ln in self._lines:
                f.write(ln + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def push(self, record: Dict[str, Any]) -> None:
        """Durably append a record. Returns only after it is safely on disk."""
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        with self._lock:
            with os.fdopen(_open_private(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND), "a", encoding="utf-8") as f:
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


__all__ = ["Spool", "SpoolSecurityError", "private_dir"]
