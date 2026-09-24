/**
 * LangChain.js callback handler.
 *
 *   import { LedgerCallbackHandler } from "@celaris/ledger-sdk/adapters/langchain";
 *   const handler = new LedgerCallbackHandler(ledger, "alice");
 *   await chain.invoke(x, { callbacks: [handler] });
 *
 * Requires `@langchain/core` (a peer dependency, not bundled): importing this module without
 * it installed only fails once you construct the handler, not at package import time.
 */
import { BaseCallbackHandler } from "@langchain/core/callbacks/base";
import type { Ledger } from "../index.js";
import { agent as agentActor, build, human } from "../actorChain.js";
import * as vocab from "../vocab.js";

export interface LedgerCallbackHandlerOptions {
  agentId?: string;
  model?: string;
  modelVersion?: string;
  goalId?: string;
  policyVersion?: string;
}

export class LedgerCallbackHandler extends BaseCallbackHandler {
  name = "LedgerCallbackHandler";

  constructor(
    private readonly ledger: Ledger | null | undefined,
    private readonly humanId: string,
    private readonly opts: LedgerCallbackHandlerOptions = {},
  ) {
    super();
  }

  private chain() {
    return build(human(this.humanId), agentActor(this.opts.agentId ?? "langchain", {
      model: this.opts.model,
      modelVersion: this.opts.modelVersion,
    }));
  }

  private emit(type: string, payload: Record<string, unknown>, runId: string) {
    this.ledger?.record(type, payload, this.chain(), {
      goalId: this.opts.goalId ?? runId,
      policyVersion: this.opts.policyVersion,
    });
  }

  handleChainStart(chainSer: unknown, _inputs: unknown, runId: string): void {
    this.emit(vocab.STEP_PLANNED, { kind: "chain", run_id: runId }, runId);
  }
  handleChainEnd(_outputs: unknown, runId: string): void {
    this.emit(vocab.ACTION_COMPLETED, { kind: "chain", run_id: runId }, runId);
  }
  handleChainError(err: Error, runId: string): void {
    this.emit(vocab.VERIFICATION_RECORDED, { kind: "chain", ok: false, error: String(err), run_id: runId }, runId);
  }

  handleToolStart(tool: unknown, input: string, runId: string): void {
    this.emit(vocab.ACTION_ATTEMPTED, { kind: "tool", input, run_id: runId }, runId);
  }
  handleToolEnd(output: unknown, runId: string): void {
    this.emit(vocab.ACTION_COMPLETED, { kind: "tool", output: String(output), run_id: runId }, runId);
  }
  handleToolError(err: Error, runId: string): void {
    this.emit(vocab.VERIFICATION_RECORDED, { kind: "tool", ok: false, error: String(err), run_id: runId }, runId);
  }

  handleLLMStart(llm: unknown, _prompts: string[], runId: string): void {
    this.emit(vocab.ACTION_ATTEMPTED, { kind: "llm", run_id: runId }, runId);
  }
  handleLLMEnd(_output: unknown, runId: string): void {
    this.emit(vocab.ACTION_COMPLETED, { kind: "llm", run_id: runId }, runId);
  }
  handleLLMError(err: Error, runId: string): void {
    this.emit(vocab.VERIFICATION_RECORDED, { kind: "llm", ok: false, error: String(err), run_id: runId }, runId);
  }
}
