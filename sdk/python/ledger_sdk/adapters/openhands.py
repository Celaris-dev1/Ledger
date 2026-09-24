"""OpenHands event stream subscriber.

    from ledger_sdk import Ledger
    from ledger_sdk.adapters.openhands import LedgerEventSubscriber
    sub = LedgerEventSubscriber(Ledger(chain="harbour"), human_id="alice")
    event_stream.subscribe(EventStreamSubscriber.LEDGER, sub.on_event, "ledger")

Matches OpenHands' ``EventStream.subscribe(id, callback, callback_id)`` shape: ``on_event`` is
a plain callable taking one event object, duck-typed on ``.__class__.__name__`` and common
attributes (``action``/``observation``/``success``) so no ``openhands`` import is required.
"""
from __future__ import annotations

from typing import Any, Optional

from ._common import Emitter, vocab


class LedgerEventSubscriber:
    def __init__(self, ledger, *, human_id: str, agent_id: str = "openhands",
                 model: Optional[str] = None, model_version: Optional[str] = None,
                 goal_id: Optional[str] = None, policy_version: Optional[str] = None):
        self._emitter = Emitter(ledger, human_id=human_id, agent_id=agent_id, model=model,
                                 model_version=model_version, goal_id=goal_id,
                                 policy_version=policy_version)

    def on_event(self, event: Any) -> None:
        name = type(event).__name__
        is_action = "Action" in name
        is_observation = "Observation" in name
        payload = {"event": name, "id": getattr(event, "id", None)}
        if is_action:
            payload["action"] = getattr(event, "action", name)
            self._emitter.emit(vocab.ACTION_ATTEMPTED, payload)
        elif is_observation:
            success = getattr(event, "success", None)
            payload["observation"] = getattr(event, "observation", name)
            if success is False:
                payload["ok"] = False
                self._emitter.emit(vocab.VERIFICATION_RECORDED, payload)
            else:
                self._emitter.emit(vocab.ACTION_COMPLETED, payload)
        else:
            self._emitter.emit(vocab.STEP_PLANNED, payload)


__all__ = ["LedgerEventSubscriber"]
