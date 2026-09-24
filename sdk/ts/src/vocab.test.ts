import { test } from "node:test";
import assert from "node:assert/strict";
import * as vocab from "./vocab.js";

test("vocabulary names match the shared brief", () => {
  assert.deepEqual(new Set(vocab.ALL), new Set([
    "ledger.goal.created", "ledger.step.planned", "ledger.action.attempted",
    "ledger.action.completed", "ledger.verification.recorded", "ledger.approval.requested",
    "ledger.approval.granted", "ledger.approval.denied", "ledger.budget.charged",
  ]));
});
