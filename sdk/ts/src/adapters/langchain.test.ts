import { test } from "node:test";
import assert from "node:assert/strict";
import { LedgerCallbackHandler } from "./langchain.js";
import type { Actor } from "../index.js";

class FakeLedger {
  records: Array<{ type: string; payload: unknown; goalId?: string }> = [];
  record(type: string, payload: unknown, actorChain: Actor[], opts: { goalId?: string } = {}) {
    if (actorChain[0]?.kind !== "human") throw new Error("actor_chain must start with human");
    this.records.push({ type, payload, goalId: opts.goalId });
    return null;
  }
}

test("stub handler maps chain/tool/llm start/end/error", () => {
  const ledger = new FakeLedger();
  const h = new LedgerCallbackHandler(ledger as any, "alice", { goalId: "g1" });
  h.handleChainStart({}, {}, "r1");
  h.handleToolStart({}, "query", "r1");
  h.handleToolEnd("result", "r1");
  h.handleLLMStart({}, ["hi"], "r1");
  h.handleLLMEnd({}, "r1");
  h.handleChainEnd({}, "r1");
  assert.deepEqual(ledger.records.map((r) => r.type), [
    "ledger.step.planned", "ledger.action.attempted", "ledger.action.completed",
    "ledger.action.attempted", "ledger.action.completed", "ledger.action.completed",
  ]);
  assert.ok(ledger.records.every((r) => r.goalId === "g1"));
});

test("stub handler maps errors to verification.recorded", () => {
  const ledger = new FakeLedger();
  const h = new LedgerCallbackHandler(ledger as any, "alice");
  h.handleToolError(new Error("boom"), "r1");
  assert.equal(ledger.records[0].type, "ledger.verification.recorded");
  assert.equal((ledger.records[0].payload as any).ok, false);
});

test("real @langchain/core integration: RunnableLambda invoke fires callbacks", async () => {
  const { RunnableLambda } = await import("@langchain/core/runnables");
  const ledger = new FakeLedger();
  const handler = new LedgerCallbackHandler(ledger as any, "alice", { goalId: "g-real" });
  const runnable = RunnableLambda.from((x: string) => x.toUpperCase());
  const result = await runnable.invoke("hi", { callbacks: [handler] });
  assert.equal(result, "HI");
  const types = ledger.records.map((r) => r.type);
  assert.ok(types.includes("ledger.step.planned") || types.includes("ledger.action.attempted"));
  assert.ok(types.includes("ledger.action.completed"));
  assert.ok(ledger.records.every((r) => r.goalId === "g-real"));
});
