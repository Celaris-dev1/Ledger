"""Shared plumbing for framework adapters: map a framework event onto a ledger.* record with
goal_id/run ids and the human actor kept first in actor_chain, regardless of how many
delegation hops (agents/tools/services) sit under it.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .. import vocab
from ..actor_chain import agent as agent_actor
from ..actor_chain import build as build_chain
from ..actor_chain import human as human_actor


class Emitter:
    """Wraps a Ledger client with the human-first actor chain and goal/run bookkeeping that
    every adapter needs, so each adapter is just "map framework event -> emit(...)".
    """

    def __init__(self, ledger, *, human_id: str, agent_id: str = "agent",
                 model: Optional[str] = None, model_version: Optional[str] = None,
                 goal_id: Optional[str] = None, policy_version: Optional[str] = None):
        self.ledger = ledger
        self.human_id = human_id
        self.agent_id = agent_id
        self.model = model
        self.model_version = model_version
        self.goal_id = goal_id
        self.policy_version = policy_version

    def actor_chain(self, extra_hops: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, str]]:
        hops = [human_actor(self.human_id), agent_actor(self.agent_id, self.model, self.model_version)]
        if extra_hops:
            hops.extend(extra_hops)
        return build_chain(*hops)

    def emit(self, type: str, payload: Dict[str, Any], *, goal_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if self.ledger is None:
            return None
        return self.ledger.record(
            type, payload, self.actor_chain(),
            goal_id=goal_id or self.goal_id, policy_version=self.policy_version,
        )


__all__ = ["Emitter", "vocab"]
