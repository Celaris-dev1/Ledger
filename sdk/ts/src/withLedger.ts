/**
 * Generic wrapper for instrumenting any tool/agent-loop function in a few lines:
 *
 *   import { withLedger } from "@celaris/ledger-sdk/withLedger";
 *   const search = withLedger(ledger, "alice", "search", rawSearch);
 *   await search("weather in nyc");
 */
import type { Actor, Ledger } from "./index.js";
import { agent as agentActor, build, human } from "./actorChain.js";
import * as vocab from "./vocab.js";

export interface WithLedgerOptions {
  agentId?: string;
  model?: string;
  modelVersion?: string;
  goalId?: string;
  policyVersion?: string;
  extraActors?: Actor[];
}

/** Wraps `fn` so every call emits ledger.action.attempted/completed (or verification.recorded
 *  on throw), carrying humanId as the root actor and toolName as the payload's action name. */
export function withLedger<A extends unknown[], R>(
  ledger: Ledger | null | undefined,
  humanId: string,
  toolName: string,
  fn: (...args: A) => R | Promise<R>,
  opts: WithLedgerOptions = {},
): (...args: A) => Promise<R> {
  const chain = () =>
    build(human(humanId), agentActor(opts.agentId ?? toolName, { model: opts.model, modelVersion: opts.modelVersion }), ...(opts.extraActors ?? []));

  return async (...args: A): Promise<R> => {
    ledger?.record(vocab.ACTION_ATTEMPTED, { tool: toolName, args }, chain(), {
      goalId: opts.goalId,
      policyVersion: opts.policyVersion,
    });
    try {
      const result = await fn(...args);
      ledger?.record(vocab.ACTION_COMPLETED, { tool: toolName, ok: true }, chain(), {
        goalId: opts.goalId,
        policyVersion: opts.policyVersion,
      });
      return result;
    } catch (err) {
      ledger?.record(
        vocab.VERIFICATION_RECORDED,
        { tool: toolName, ok: false, error: err instanceof Error ? err.message : String(err) },
        chain(),
        { goalId: opts.goalId, policyVersion: opts.policyVersion },
      );
      throw err;
    }
  };
}
