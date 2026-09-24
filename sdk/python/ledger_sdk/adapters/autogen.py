"""AutoGen message hook / runtime intervention handler.

    from ledger_sdk import Ledger
    from ledger_sdk.adapters.autogen import LedgerMessageHook
    hook = LedgerMessageHook(Ledger(chain="harbour"), human_id="alice")
    agent.register_hook("process_message_before_send", hook.before_send)

``before_send`` matches the classic ``autogen.ConversableAgent.register_hook`` signature
(sender, message, recipient, silent) -> message (the message is returned unchanged, so this
is safe to register alongside other hooks); ``intervene`` matches the newer autogen-core
``InterventionHandler.on_send``-style signature (message, sender, recipient) -> message, for
use as a runtime intervention handler. Neither imports autogen.
"""
from __future__ import annotations

from typing import Any, Optional

from ._common import Emitter, vocab


def _text(message: Any) -> str:
    if isinstance(message, dict):
        return str(message.get("content", message))
    return str(message)


class LedgerMessageHook:
    def __init__(self, ledger, *, human_id: str, agent_id: str = "autogen",
                 model: Optional[str] = None, model_version: Optional[str] = None,
                 goal_id: Optional[str] = None, policy_version: Optional[str] = None):
        self._emitter = Emitter(ledger, human_id=human_id, agent_id=agent_id, model=model,
                                 model_version=model_version, goal_id=goal_id,
                                 policy_version=policy_version)

    def before_send(self, sender: Any, message: Any, recipient: Any, silent: bool = False) -> Any:
        """``register_hook("process_message_before_send", ...)`` style hook."""
        self._emitter.emit(vocab.ACTION_ATTEMPTED, {
            "from": str(getattr(sender, "name", sender)),
            "to": str(getattr(recipient, "name", recipient)),
            "message": _text(message)[:2000],
        })
        return message

    def intervene(self, message: Any, sender: Any = None, recipient: Any = None) -> Any:
        """autogen-core ``InterventionHandler``-style hook: called for every routed message."""
        self._emitter.emit(vocab.ACTION_COMPLETED, {
            "from": str(getattr(sender, "name", sender)) if sender is not None else None,
            "to": str(getattr(recipient, "name", recipient)) if recipient is not None else None,
            "message": _text(message)[:2000],
        })
        return message


__all__ = ["LedgerMessageHook"]
