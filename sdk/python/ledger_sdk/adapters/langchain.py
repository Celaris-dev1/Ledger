"""LangChain / LangGraph callback handler.

    from ledger_sdk import Ledger
    from ledger_sdk.adapters.langchain import LedgerCallbackHandler
    ledger = Ledger(chain="harbour")
    chain.invoke(x, config={"callbacks": [LedgerCallbackHandler(ledger, human_id="alice")]})

Requires ``langchain-core`` (``pip install ledger-sdk[langchain]``); importing this module
without it raises ImportError only when the handler is actually constructed, not at
``import ledger_sdk`` time.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from ._common import Emitter, vocab

try:  # pragma: no cover - exercised only when langchain-core is installed
    from langchain_core.callbacks import BaseCallbackHandler as _Base
except ImportError:  # pragma: no cover
    _Base = object


class LedgerCallbackHandler(_Base):
    """Maps LangChain/LangGraph chain, tool and LLM start/end/error callbacks to ledger.*
    records. One instance per run is fine; goal_id defaults to the LangChain run_id so steps
    of the same run replay together.
    """

    def __init__(self, ledger, *, human_id: str, agent_id: str = "langchain",
                 model: Optional[str] = None, model_version: Optional[str] = None,
                 goal_id: Optional[str] = None, policy_version: Optional[str] = None):
        if _Base is object:
            raise ImportError("langchain-core is required: pip install ledger-sdk[langchain]")
        super().__init__()
        self._emitter = Emitter(ledger, human_id=human_id, agent_id=agent_id, model=model,
                                 model_version=model_version, goal_id=goal_id,
                                 policy_version=policy_version)

    def _goal(self, run_id: Any) -> str:
        return self._emitter.goal_id or str(run_id)

    # -- chains: treated as planned steps ------------------------------------------------
    def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any], *, run_id, **kw):
        self._emitter.emit(vocab.STEP_PLANNED,
                            {"name": (serialized or {}).get("name"), "run_id": str(run_id)},
                            goal_id=self._goal(run_id))

    def on_chain_end(self, outputs: Dict[str, Any], *, run_id, **kw):
        self._emitter.emit(vocab.ACTION_COMPLETED, {"run_id": str(run_id), "kind": "chain"},
                            goal_id=self._goal(run_id))

    def on_chain_error(self, error: BaseException, *, run_id, **kw):
        self._emitter.emit(vocab.VERIFICATION_RECORDED,
                            {"run_id": str(run_id), "kind": "chain", "ok": False, "error": str(error)},
                            goal_id=self._goal(run_id))

    # -- tools: treated as attempted/completed actions -----------------------------------
    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, *, run_id, **kw):
        self._emitter.emit(vocab.ACTION_ATTEMPTED,
                            {"tool": (serialized or {}).get("name"), "input": input_str, "run_id": str(run_id)},
                            goal_id=self._goal(run_id))

    def on_tool_end(self, output: Any, *, run_id, **kw):
        self._emitter.emit(vocab.ACTION_COMPLETED, {"run_id": str(run_id), "output": str(output)},
                            goal_id=self._goal(run_id))

    def on_tool_error(self, error: BaseException, *, run_id, **kw):
        self._emitter.emit(vocab.VERIFICATION_RECORDED,
                            {"run_id": str(run_id), "kind": "tool", "ok": False, "error": str(error)},
                            goal_id=self._goal(run_id))

    # -- LLM calls: also attempted/completed actions, carrying model info ----------------
    def on_llm_start(self, serialized: Dict[str, Any], prompts, *, run_id, **kw):
        self._emitter.emit(vocab.ACTION_ATTEMPTED,
                            {"model": (serialized or {}).get("name"), "kind": "llm", "run_id": str(run_id)},
                            goal_id=self._goal(run_id))

    def on_llm_end(self, response: Any, *, run_id, **kw):
        self._emitter.emit(vocab.ACTION_COMPLETED, {"run_id": str(run_id), "kind": "llm"},
                            goal_id=self._goal(run_id))

    def on_llm_error(self, error: BaseException, *, run_id, **kw):
        self._emitter.emit(vocab.VERIFICATION_RECORDED,
                            {"run_id": str(run_id), "kind": "llm", "ok": False, "error": str(error)},
                            goal_id=self._goal(run_id))


__all__ = ["LedgerCallbackHandler"]
