"""Ledger Python SDK (stdlib only).

    from ledger_sdk import Ledger
    ledger = Ledger(chain="harbour")            # LEDGER_URL / LEDGER_TOKEN from env
    ledger.record("harbour.goal.transition", {"to": "running"},
                  [{"kind": "human", "id": "alice"}, {"kind": "agent", "id": "planner"}],
                  goal_id="g-1")

If LEDGER_URL is unset the client is a no-op recorder and ``record`` returns None.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

__all__ = ["Ledger", "LedgerError"]


class LedgerError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"ledger: HTTP {status}: {body}")
        self.status = status
        self.body = body


class Ledger:
    def __init__(self, chain: str, url: Optional[str] = None, token: Optional[str] = None, timeout: float = 5.0):
        self.chain = chain
        self.url = (url if url is not None else os.environ.get("LEDGER_URL", "")).rstrip("/")
        self.token = token if token is not None else os.environ.get("LEDGER_TOKEN", "")
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def _req(self, method: str, path: str, body: Any = None) -> Any:
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

    def record(self, type: str, payload: Dict[str, Any], actor_chain: List[Dict[str, str]], *,
               goal_id: Optional[str] = None, policy_version: Optional[str] = None,
               chain: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not actor_chain or actor_chain[0].get("kind") != "human":
            raise ValueError("actor_chain must start with the originating human (kind='human')")
        if not self.enabled:
            return None
        body: Dict[str, Any] = {"chain": chain or self.chain, "type": type,
                                "actor_chain": actor_chain, "payload": payload or {}}
        if goal_id:
            body["goal_id"] = goal_id
        if policy_version:
            body["policy_version"] = policy_version
        return self._req("POST", "/v1/records", body)

    def verify(self, chain: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        return self._req("GET", "/v1/chains/%s/verify" % urllib.parse.quote(chain or self.chain, safe=""))

    def replay(self, goal_id: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        return self._req("GET", "/v1/goals/%s/replay" % urllib.parse.quote(goal_id, safe=""))
