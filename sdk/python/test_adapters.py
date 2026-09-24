"""Adapter tests. Framework-specific tests import their framework lazily and skip cleanly if
it is not installed (e.g. CrewAI/AutoGen/OpenHands, which are heavy); LangChain-core is small
enough that CI installs it for a real integration test in addition to the stub-based one.
"""
import unittest
from typing import Any, Dict, List
from uuid import uuid4


class FakeLedger:
    """Records what would be sent, without any network or background thread."""

    def __init__(self):
        self.records: List[Dict[str, Any]] = []

    def record(self, type, payload, actor_chain, *, goal_id=None, policy_version=None, chain=None):
        if not actor_chain or actor_chain[0].get("kind") != "human":
            raise ValueError("actor_chain must start with human")
        rec = {"type": type, "payload": payload, "actor_chain": actor_chain, "goal_id": goal_id}
        self.records.append(rec)
        return rec


class LangChainAdapterTest(unittest.TestCase):
    def test_stub_handler_maps_events(self):
        from ledger_sdk.adapters.langchain import LedgerCallbackHandler
        ledger = FakeLedger()
        h = LedgerCallbackHandler(ledger, human_id="alice")
        run_id = uuid4()
        h.on_chain_start({"name": "root"}, {}, run_id=run_id)
        h.on_tool_start({"name": "search"}, "query", run_id=run_id)
        h.on_tool_end("result", run_id=run_id)
        h.on_llm_start({"name": "gpt"}, ["hi"], run_id=run_id)
        h.on_llm_end(object(), run_id=run_id)
        h.on_chain_end({}, run_id=run_id)
        types = [r["type"] for r in ledger.records]
        self.assertEqual(types, [
            "ledger.step.planned", "ledger.action.attempted", "ledger.action.completed",
            "ledger.action.attempted", "ledger.action.completed", "ledger.action.completed",
        ])
        self.assertEqual(ledger.records[0]["actor_chain"][0]["id"], "alice")
        self.assertTrue(all(r["goal_id"] == str(run_id) for r in ledger.records))

    def test_stub_handler_maps_errors(self):
        from ledger_sdk.adapters.langchain import LedgerCallbackHandler
        ledger = FakeLedger()
        h = LedgerCallbackHandler(ledger, human_id="alice")
        run_id = uuid4()
        h.on_tool_error(RuntimeError("boom"), run_id=run_id)
        self.assertEqual(ledger.records[-1]["type"], "ledger.verification.recorded")
        self.assertFalse(ledger.records[-1]["payload"]["ok"])

    def test_real_langchain_core_integration(self):
        try:
            from langchain_core.runnables import RunnableLambda
        except ImportError:
            self.skipTest("langchain-core not installed")
        from ledger_sdk.adapters.langchain import LedgerCallbackHandler
        ledger = FakeLedger()
        handler = LedgerCallbackHandler(ledger, human_id="alice", goal_id="g-real")
        runnable = RunnableLambda(lambda x: x.upper())
        result = runnable.invoke("hi", config={"callbacks": [handler]})
        self.assertEqual(result, "HI")
        types = [r["type"] for r in ledger.records]
        self.assertIn("ledger.step.planned", types)
        self.assertIn("ledger.action.completed", types)
        self.assertTrue(all(r["goal_id"] == "g-real" for r in ledger.records))


class CrewAIAdapterTest(unittest.TestCase):
    class _FakeStep:
        def __init__(self, agent="researcher", tool="search", error=None):
            self.agent, self.tool, self.error = agent, tool, error

    class _FakeTaskOutput:
        def __init__(self, description="find facts", raw="the facts"):
            self.description, self.raw = description, raw

    def test_step_and_task_callbacks(self):
        from ledger_sdk.adapters.crewai import LedgerCrewCallback
        ledger = FakeLedger()
        cb = LedgerCrewCallback(ledger, human_id="alice")
        cb.step(self._FakeStep())
        cb.step(self._FakeStep(error="boom"))
        cb.task(self._FakeTaskOutput())
        types = [r["type"] for r in ledger.records]
        self.assertEqual(types, ["ledger.action.completed", "ledger.verification.recorded", "ledger.step.planned"])

    def test_real_crewai_if_installed(self):
        try:
            import crewai  # noqa: F401
        except ImportError:
            self.skipTest("crewai not installed (heavy optional dependency)")
        self.skipTest("crewai present but full-crew integration exercise skipped by design (no network/LLM)")


class AutoGenAdapterTest(unittest.TestCase):
    class _FakeAgent:
        def __init__(self, name):
            self.name = name

    def test_before_send_and_intervene(self):
        from ledger_sdk.adapters.autogen import LedgerMessageHook
        ledger = FakeLedger()
        hook = LedgerMessageHook(ledger, human_id="alice")
        a, b = self._FakeAgent("planner"), self._FakeAgent("coder")
        msg = hook.before_send(a, {"content": "do the thing"}, b)
        self.assertEqual(msg["content"], "do the thing")
        hook.intervene("routed message", sender=a, recipient=b)
        types = [r["type"] for r in ledger.records]
        self.assertEqual(types, ["ledger.action.attempted", "ledger.action.completed"])

    def test_real_autogen_if_installed(self):
        try:
            import autogen  # noqa: F401
        except ImportError:
            self.skipTest("autogen not installed (heavy optional dependency)")
        self.skipTest("autogen present but full-runtime integration exercise skipped by design (no network/LLM)")


class OpenHandsAdapterTest(unittest.TestCase):
    class FakeAction:
        def __init__(self):
            self.id = 1
            self.action = "run"

    class FakeObservation:
        def __init__(self, success=True):
            self.id = 2
            self.observation = "run"
            self.success = success

    def test_action_and_observation_events(self):
        from ledger_sdk.adapters.openhands import LedgerEventSubscriber
        ledger = FakeLedger()
        sub = LedgerEventSubscriber(ledger, human_id="alice")
        sub.on_event(self.FakeAction())
        sub.on_event(self.FakeObservation(success=True))
        sub.on_event(self.FakeObservation(success=False))
        types = [r["type"] for r in ledger.records]
        self.assertEqual(types, ["ledger.action.attempted", "ledger.action.completed", "ledger.verification.recorded"])

    def test_real_openhands_if_installed(self):
        try:
            import openhands  # noqa: F401
        except ImportError:
            self.skipTest("openhands not installed (heavy optional dependency)")
        self.skipTest("openhands present but full-runtime integration exercise skipped by design (no network)")


if __name__ == "__main__":
    unittest.main()
