import { test } from "node:test";
import assert from "node:assert/strict";
import { withLedger } from "./withLedger.js";
import type { Actor } from "./index.js";

class FakeLedger {
  records: Array<{ type: string; payload: unknown; actorChain: Actor[] }> = [];
  record(type: string, payload: unknown, actorChain: Actor[]) {
    if (actorChain[0]?.kind !== "human") throw new Error("actor_chain must start with human");
    this.records.push({ type, payload, actorChain });
    return null;
  }
}

test("withLedger records attempted/completed around a successful call", async () => {
  const ledger = new FakeLedger();
  const search = withLedger(ledger as any, "alice", "search", async (q: string) => `results for ${q}`);
  const result = await search("weather");
  assert.equal(result, "results for weather");
  assert.deepEqual(ledger.records.map((r) => r.type), ["ledger.action.attempted", "ledger.action.completed"]);
  assert.equal(ledger.records[0].actorChain[0].id, "alice");
});

test("withLedger records verification.recorded on throw and rethrows", async () => {
  const ledger = new FakeLedger();
  const fail = withLedger(ledger as any, "alice", "flaky", async () => {
    throw new Error("boom");
  });
  await assert.rejects(fail(), /boom/);
  assert.deepEqual(ledger.records.map((r) => r.type), ["ledger.action.attempted", "ledger.verification.recorded"]);
});

test("withLedger is a no-op passthrough when ledger is null", async () => {
  const fn = withLedger(null, "alice", "noop", async (x: number) => x + 1);
  assert.equal(await fn(1), 2);
});
