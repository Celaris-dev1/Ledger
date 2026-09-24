"""Helpers for building ``actor_chain`` lists that always keep the originating human first.

    from ledger_sdk.actor_chain import human, agent, service, build

    chain = build(human("alice"), agent("planner", model="gpt-5"), service("scheduler"))
    # -> [{"kind": "human", "id": "alice"},
    #     {"kind": "agent", "id": "planner", "model": "gpt-5"},
    #     {"kind": "service", "id": "scheduler"}]

``build`` raises if the first hop is not a human, and ``extend`` appends a new delegation hop
to an existing chain without ever letting the human be dropped or reordered.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

Actor = Dict[str, str]


def _actor(kind: str, id: str, model: Optional[str] = None, model_version: Optional[str] = None) -> Actor:
    if not id:
        raise ValueError("actor id is required")
    a: Actor = {"kind": kind, "id": id}
    if model:
        a["model"] = model
    if model_version:
        a["model_version"] = model_version
    return a


def human(id: str) -> Actor:
    """The originating human. Always the first hop of an actor_chain."""
    return _actor("human", id)


def agent(id: str, model: Optional[str] = None, model_version: Optional[str] = None) -> Actor:
    return _actor("agent", id, model, model_version)


def service(id: str, model: Optional[str] = None, model_version: Optional[str] = None) -> Actor:
    return _actor("service", id, model, model_version)


def build(*hops: Actor) -> List[Actor]:
    """Assemble an actor_chain, enforcing that the first hop is the originating human."""
    if not hops:
        raise ValueError("actor_chain must be non-empty")
    if hops[0].get("kind") != "human":
        raise ValueError("actor_chain[0] must be the originating human (use actor_chain.human(...))")
    return list(hops)


def extend(chain: List[Actor], *hops: Actor) -> List[Actor]:
    """Append delegation hop(s) to an existing chain, keeping the originating human first."""
    if not chain or chain[0].get("kind") != "human":
        raise ValueError("chain must already start with the originating human")
    return [*chain, *hops]


__all__ = ["Actor", "human", "agent", "service", "build", "extend"]
