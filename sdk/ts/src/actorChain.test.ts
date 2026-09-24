import { test } from "node:test";
import assert from "node:assert/strict";
import { agent, build, extend, human, service } from "./actorChain.js";

test("build keeps human first", () => {
  const chain = build(human("alice"), agent("planner", { model: "gpt-5" }));
  assert.deepEqual(chain[0], { kind: "human", id: "alice" });
  assert.equal(chain[1].model, "gpt-5");
});

test("build rejects non-human first", () => {
  assert.throws(() => build(agent("x")));
});

test("extend appends delegation hop", () => {
  const chain = build(human("alice"));
  const chain2 = extend(chain, service("scheduler"));
  assert.equal(chain2.length, 2);
  assert.equal(chain2[0].kind, "human");
});

test("extend requires human first", () => {
  assert.throws(() => extend([agent("x")], service("y")));
});
