"""Ledger Python SDK (stdlib only).

    from ledger_sdk import Ledger
    from ledger_sdk.actor_chain import human, agent

    ledger = Ledger(chain="harbour")            # LEDGER_URL / LEDGER_TOKEN from env
    ledger.record("harbour.goal.transition", {"to": "running"},
                  [human("alice"), agent("planner")], goal_id="g-1")

If LEDGER_URL is unset the client is a no-op recorder and ``record`` returns None immediately.

Writes are asynchronous: ``record()`` appends the record to an on-disk JSONL spool (durable
before the call returns) and hands it to a background sender thread, which POSTs it with
retries (exponential backoff + jitter) and never reorders records within a chain. If ledgerd
is unreachable, records simply accumulate in the spool and are sent in order once it recovers
-- including across process restarts, since the spool is reloaded on construction. The queue
is bounded (``max_queue``, default 10000 spooled-but-unsent records per chain+endpoint); once
full, the oldest unsent record is dropped to bound disk/memory use rather than blocking the
caller or growing without limit.

Call ``flush(timeout=...)`` to block until the spool drains (e.g. before a short-lived script
exits); this also happens automatically at interpreter exit via ``atexit`` unless
``flush_on_exit=False`` is passed.

Every record carries an ``idempotency_key`` (auto-generated with ``uuid4`` unless you supply
one) so that retries -- including ones that happen to succeed on the server but time out on
the client -- never double-append.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import random
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List, Optional

from ._spool import Spool

__all__ = ["Ledger", "LedgerError"]


class LedgerError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"ledger: HTTP {status}: {body}")
        self.status = status
        self.body = body


def _default_spool_path(chain: str, url: str) -> str:
    key = hashlib.sha256(f"{url}|{chain}".encode()).hexdigest()[:16]
    return os.path.join(tempfile.gettempdir(), f"ledger-sdk-spool-{key}.jsonl")


class Ledger:
    def __init__(
        self,
        chain: str,
        url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 5.0,
        *,
        spool_path: Optional[str] = None,
        max_queue: int = 10000,
        max_retry_delay: float = 30.0,
        base_retry_delay: float = 0.2,
        flush_on_exit: bool = True,
        transport: Optional[Any] = None,
    ):
        self.chain = chain
        self.url = (url if url is not None else os.environ.get("LEDGER_URL", "")).rstrip("/")
        self.token = token if token is not None else os.environ.get("LEDGER_TOKEN", "")
        self.timeout = timeout
        self.max_queue = max_queue
        self.max_retry_delay = max_retry_delay
        self.base_retry_delay = base_retry_delay
        self._transport = transport or self._http_post
        self._closed = False
        self._cv = threading.Condition()
        self._thread: Optional[threading.Thread] = None

        if self.enabled:
            self._spool = Spool(spool_path or _default_spool_path(chain, self.url))
            self._thread = threading.Thread(target=self._run, name="ledger-sdk-sender", daemon=True)
            self._thread.start()
            if flush_on_exit:
                atexit.register(self.flush, timeout=5.0)
        else:
            self._spool = None  # type: ignore[assignment]

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    # -- public API ---------------------------------------------------------------------

    def record(
        self,
        type: str,
        payload: Dict[str, Any],
        actor_chain: List[Dict[str, str]],
        *,
        goal_id: Optional[str] = None,
        policy_version: Optional[str] = None,
        chain: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Queue a record for durable, ordered, retried delivery. Non-blocking.

        Returns the body that was queued (not the server's response, since delivery is
        asynchronous) or ``None`` if this client is disabled (no LEDGER_URL configured).
        """
        if not actor_chain or actor_chain[0].get("kind") != "human":
            raise ValueError("actor_chain must start with the originating human (kind='human')")
        if not self.enabled:
            return None
        body: Dict[str, Any] = {
            "chain": chain or self.chain,
            "type": type,
            "actor_chain": actor_chain,
            "payload": payload or {},
            "idempotency_key": idempotency_key or uuid.uuid4().hex,
        }
        if goal_id:
            body["goal_id"] = goal_id
        if policy_version:
            body["policy_version"] = policy_version
        self._enqueue(body)
        return body

    def flush(self, timeout: Optional[float] = None) -> bool:
        """Block until the spool is empty (all queued records sent), or timeout elapses.

        Returns True if the spool drained, False on timeout. No-op (returns True) if disabled.
        """
        if not self.enabled:
            return True
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._cv:
            while len(self._spool) > 0:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return False
                self._cv.wait(timeout=remaining)
        return True

    def pending(self) -> int:
        """Number of records durably spooled but not yet confirmed sent."""
        return len(self._spool) if self.enabled else 0

    def close(self) -> None:
        """Stop the background sender. Does not wait for the spool to drain; call flush() first."""
        self._closed = True
        with self._cv:
            self._cv.notify_all()

    def verify(self, chain: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        return self._http_get("/v1/chains/%s/verify" % urllib.parse.quote(chain or self.chain, safe=""))

    def replay(self, goal_id: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        return self._http_get("/v1/goals/%s/replay" % urllib.parse.quote(goal_id, safe=""))

    # -- internals ------------------------------------------------------------------------

    def _enqueue(self, body: Dict[str, Any]) -> None:
        self._spool.push(body)
        with self._cv:
            if len(self._spool) > self.max_queue:
                self._spool.drop_front(len(self._spool) - self.max_queue)
            self._cv.notify_all()

    def _run(self) -> None:
        attempt = 0
        while not self._closed:
            item = self._spool.peek_front()
            if item is None:
                with self._cv:
                    self._cv.wait(timeout=0.5)
                continue
            try:
                self._transport("/v1/records", item)
                self._spool.pop_front()
                attempt = 0
                with self._cv:
                    self._cv.notify_all()
            except LedgerError as e:
                if 400 <= e.status < 500:
                    # Non-retryable: server rejected the record itself. Drop it so a single
                    # bad record cannot block every later one on this chain forever.
                    self._spool.pop_front()
                    attempt = 0
                    with self._cv:
                        self._cv.notify_all()
                    continue
                attempt += 1
                self._sleep_backoff(attempt)
            except Exception:
                attempt += 1
                self._sleep_backoff(attempt)

    def _sleep_backoff(self, attempt: int) -> None:
        delay = min(self.max_retry_delay, self.base_retry_delay * (2 ** (attempt - 1)))
        delay = delay * (0.5 + random.random())  # full jitter around [0.5x, 1.5x)
        with self._cv:
            self._cv.wait(timeout=delay)

    def _http_post(self, path: str, body: Any) -> Any:
        return self._req("POST", path, body)

    def _http_get(self, path: str) -> Any:
        return self._req("GET", path, None)

    def _req(self, method: str, path: str, body: Any) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            raise LedgerError(e.code, e.read().decode(errors="replace")) from None
