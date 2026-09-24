"""CrewAI step/task callbacks.

    from ledger_sdk import Ledger
    from ledger_sdk.adapters.crewai import LedgerCrewCallback
    cb = LedgerCrewCallback(Ledger(chain="harbour"), human_id="alice")
    crew = Crew(agents=[...], tasks=[...], step_callback=cb.step, task_callback=cb.task)

No import of ``crewai`` is required: CrewAI calls plain callables with its own step/task
objects, so this adapter only duck-types the attributes it needs (``description``/``raw``/
``name``/``agent``), and works against CrewAI's real objects or any lightweight stand-in with
the same shape (which is what the tests use).
"""
from __future__ import annotations

from typing import Any, Optional

from ._common import Emitter, vocab


def _attr(obj: Any, *names: str, default: Any = None) -> Any:
    for n in names:
        v = getattr(obj, n, None)
        if v is not None:
            return v
    return default


class LedgerCrewCallback:
    def __init__(self, ledger, *, human_id: str, agent_id: str = "crewai",
                 model: Optional[str] = None, model_version: Optional[str] = None,
                 goal_id: Optional[str] = None, policy_version: Optional[str] = None):
        self._emitter = Emitter(ledger, human_id=human_id, agent_id=agent_id, model=model,
                                 model_version=model_version, goal_id=goal_id,
                                 policy_version=policy_version)

    def step(self, step: Any) -> None:
        """Pass as ``Crew(step_callback=cb.step)``. Fires on every agent step (thought/action)."""
        ok = _attr(step, "error", default=None) is None
        payload = {
            "agent": str(_attr(step, "agent", default="")),
            "action": str(_attr(step, "tool", "action", default="")),
            "ok": ok,
        }
        self._emitter.emit(vocab.ACTION_COMPLETED if ok else vocab.VERIFICATION_RECORDED, payload)

    def task(self, task_output: Any) -> None:
        """Pass as ``Crew(task_callback=cb.task)``. Fires when a task completes."""
        self._emitter.emit(vocab.STEP_PLANNED, {
            "description": str(_attr(task_output, "description", "name", default="")),
            "raw": str(_attr(task_output, "raw", default=""))[:2000],
        })


__all__ = ["LedgerCrewCallback"]
