import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Ledger, LedgerError } from "./index.js";

function tmpSpool(): string {
  return path.join(os.tmpdir(), `ledger-sdk-ts-test-${Math.random().toString(36).slice(2)}.jsonl`);
}

test("no-op without url", async () => {
  const l = new Ledger({ chain: "gate", url: "" });
  assert.equal(l.record("t", {}, [{ kind: "human", id: "a" }]), null);
});

test("rejects non-human first actor", async () => {
  const l = new Ledger({ chain: "gate", url: "" });
  assert.throws(() => l.record("t", {}, [{ kind: "agent", id: "a" }]));
});

test("posts contract body with bearer token and idempotency key", async () => {
  const seen: Array<{ url: string; init: RequestInit }> = [];
  const fake = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return new Response(JSON.stringify({ id: "u", chain: "gate", seq: 1, hash: "h", prev_hash: "", created_at: "t" }), { status: 201 });
  }) as unknown as typeof fetch;
  const l = new Ledger({ chain: "gate", url: "http://x/", token: "tok", fetch: fake, spoolPath: tmpSpool(), flushOnExit: false });
  const queued = l.record("gate.run.started", { a: 1 }, [{ kind: "human", id: "alice" }], { goalId: "g1" });
  assert.ok(queued && queued.idempotency_key);
  assert.equal(await l.flush(5000), true);
  assert.equal(l.pending, 0);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, "http://x/v1/records");
  assert.equal((seen[0].init.headers as Record<string, string>)["Authorization"], "Bearer tok");
  const body = JSON.parse(seen[0].init.body as string);
  assert.equal(body.goal_id, "g1");
  assert.equal(body.idempotency_key, queued!.idempotency_key);
  l.close();
});

test("http 400 errors are dropped, not retried forever", async () => {
  const fake = (async () => new Response("{}", { status: 400 })) as unknown as typeof fetch;
  const l = new Ledger({ chain: "gate", url: "http://x", fetch: fake, spoolPath: tmpSpool(), flushOnExit: false, baseRetryDelayMs: 10 });
  l.record("t", {}, [{ kind: "human", id: "a" }]);
  assert.equal(await l.flush(5000), true);
  l.close();
});

test("retries with backoff then succeeds", async () => {
  let calls = 0;
  const fake = (async () => {
    calls += 1;
    if (calls < 3) return new Response("{}", { status: 503 });
    return new Response(JSON.stringify({ id: "u", chain: "gate", seq: 1, hash: "h", prev_hash: "", created_at: "t" }), { status: 201 });
  }) as unknown as typeof fetch;
  const l = new Ledger({ chain: "gate", url: "http://x", fetch: fake, spoolPath: tmpSpool(), flushOnExit: false, baseRetryDelayMs: 10, maxRetryDelayMs: 30 });
  l.record("t", {}, [{ kind: "human", id: "a" }]);
  assert.equal(await l.flush(10000), true);
  assert.equal(calls, 3);
  l.close();
});

test("spool survives restart and replays in order", async () => {
  const spoolPath = tmpSpool();
  const seen: number[] = [];
  const deadFetch = (async () => {
    throw new Error("unreachable");
  }) as unknown as typeof fetch;
  const l1 = new Ledger({ chain: "gate", url: "http://dead", fetch: deadFetch, spoolPath, flushOnExit: false, baseRetryDelayMs: 10, maxRetryDelayMs: 20 });
  l1.record("t", { n: 1 }, [{ kind: "human", id: "a" }]);
  l1.record("t", { n: 2 }, [{ kind: "human", id: "a" }]);
  l1.record("t", { n: 3 }, [{ kind: "human", id: "a" }]);
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(l1.pending, 3);
  l1.close();

  const okFetch = (async (_url: string, init: RequestInit) => {
    const body = JSON.parse(init.body as string);
    seen.push(body.payload.n);
    return new Response(JSON.stringify({ id: "u", chain: "gate", seq: seen.length, hash: "h", prev_hash: "", created_at: "t" }), { status: 201 });
  }) as unknown as typeof fetch;
  const l2 = new Ledger({ chain: "gate", url: "http://x", fetch: okFetch, spoolPath, flushOnExit: false, baseRetryDelayMs: 10 });
  assert.equal(await l2.flush(5000), true);
  assert.deepEqual(seen, [1, 2, 3]);
  l2.close();
});

test("bounded queue drops oldest", async () => {
  const deadFetch = (async () => {
    throw new Error("unreachable");
  }) as unknown as typeof fetch;
  const l = new Ledger({ chain: "gate", url: "http://dead", fetch: deadFetch, spoolPath: tmpSpool(), flushOnExit: false, maxQueue: 2, baseRetryDelayMs: 5000, maxRetryDelayMs: 5000 });
  l.record("t", { n: 1 }, [{ kind: "human", id: "a" }]);
  l.record("t", { n: 2 }, [{ kind: "human", id: "a" }]);
  l.record("t", { n: 3 }, [{ kind: "human", id: "a" }]);
  await new Promise((r) => setTimeout(r, 50));
  assert.ok(l.pending <= 2);
  l.close();
});

test("LedgerError carries status and body", () => {
  const e = new LedgerError(400, "bad");
  assert.equal(e.status, 400);
  assert.equal(e.body, "bad");
});
