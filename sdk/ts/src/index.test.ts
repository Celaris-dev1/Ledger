import { test } from "node:test";
import assert from "node:assert/strict";
import { Ledger, LedgerError } from "./index.js";

test("no-op without url", async () => {
  const l = new Ledger({ chain: "gate", url: "" });
  assert.equal(await l.record("t", {}, [{ kind: "human", id: "a" }]), null);
});

test("rejects non-human first actor", async () => {
  const l = new Ledger({ chain: "gate", url: "" });
  await assert.rejects(l.record("t", {}, [{ kind: "agent", id: "a" }]));
});

test("posts contract body with bearer token", async () => {
  let seen: { url: string; init: RequestInit } | undefined;
  const fake = (async (url: string, init: RequestInit) => {
    seen = { url, init };
    return new Response(JSON.stringify({ id: "u", chain: "gate", seq: 1, hash: "h", prev_hash: "", created_at: "t" }), { status: 201 });
  }) as unknown as typeof fetch;
  const l = new Ledger({ chain: "gate", url: "http://x/", token: "tok", fetch: fake });
  const r = await l.record("gate.run.started", { a: 1 }, [{ kind: "human", id: "alice" }], { goalId: "g1" });
  assert.equal(r?.seq, 1);
  assert.equal(seen?.url, "http://x/v1/records");
  assert.equal((seen?.init.headers as Record<string, string>)["Authorization"], "Bearer tok");
  assert.equal(JSON.parse(seen?.init.body as string).goal_id, "g1");
});

test("http errors raise LedgerError", async () => {
  const fake = (async () => new Response("{}", { status: 400 })) as unknown as typeof fetch;
  const l = new Ledger({ chain: "gate", url: "http://x", fetch: fake });
  await assert.rejects(l.record("t", {}, [{ kind: "human", id: "a" }]), LedgerError);
});
