/**
 * Helpers for building actor_chain arrays that always keep the originating human first.
 *
 *   import { human, agent, service, build } from "@celaris/ledger-sdk/actorChain";
 *   const chain = build(human("alice"), agent("planner", { model: "gpt-5" }));
 */
import type { Actor, ActorKind } from "./index.js";

export interface ActorOpts {
  model?: string;
  modelVersion?: string;
}

function actor(kind: ActorKind, id: string, opts: ActorOpts = {}): Actor {
  if (!id) throw new Error("actor id is required");
  const a: Actor = { kind, id };
  if (opts.model) a.model = opts.model;
  if (opts.modelVersion) a.model_version = opts.modelVersion;
  return a;
}

export const human = (id: string): Actor => actor("human", id);
export const agent = (id: string, opts: ActorOpts = {}): Actor => actor("agent", id, opts);
export const service = (id: string, opts: ActorOpts = {}): Actor => actor("service", id, opts);

/** Assemble an actor_chain, enforcing that the first hop is the originating human. */
export function build(...hops: Actor[]): Actor[] {
  if (hops.length === 0) throw new Error("actor_chain must be non-empty");
  if (hops[0].kind !== "human") {
    throw new Error("actor_chain[0] must be the originating human (use human(...))");
  }
  return [...hops];
}

/** Append delegation hop(s) to an existing chain, keeping the originating human first. */
export function extend(chain: Actor[], ...hops: Actor[]): Actor[] {
  if (chain.length === 0 || chain[0].kind !== "human") {
    throw new Error("chain must already start with the originating human");
  }
  return [...chain, ...hops];
}
