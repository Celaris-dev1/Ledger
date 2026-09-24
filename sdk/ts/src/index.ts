/**
 * Ledger TypeScript SDK (no runtime dependencies; uses global fetch and Node's fs/crypto/os,
 * Node >= 18).
 *
 *   import { Ledger } from "@celaris/ledger-sdk";
 *   import { human, agent } from "@celaris/ledger-sdk/actorChain";
 *   const ledger = new Ledger({ chain: "warrant" });   // LEDGER_URL / LEDGER_TOKEN from env
 *   ledger.record("warrant.token.issued", { scope: "repo:read" },
 *     [human("alice"), agent("coder")], { goalId: "g-1" });
 *
 * If no URL is configured, record() is a no-op. Otherwise it is asynchronous: the record is
 * appended to an on-disk JSONL spool (durable before record() returns) and a background pump
 * sends it with retries (exponential backoff + jitter), never reordering records within a
 * chain. If ledgerd is unreachable, records accumulate in the spool and are sent once it
 * recovers, including across process restarts (the spool reloads on construction). The queue
 * is bounded (`maxQueue`, default 10000); once full, the oldest unsent record is dropped.
 *
 * Call `flush()` to await the spool draining (e.g. before a short-lived script exits); unless
 * `flushOnExit: false` is passed, this also happens automatically on the `beforeExit` event.
 *
 * Every record carries an `idempotency_key` (auto-generated with `crypto.randomUUID()` unless
 * supplied) so retries never double-append.
 */
import * as crypto from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";
import { Spool } from "./spool.js";

export type ActorKind = "human" | "agent" | "service";
export interface Actor {
  kind: ActorKind;
  id: string;
  model?: string;
  model_version?: string;
}
export interface RecordResponse {
  id: string;
  chain: string;
  seq: number;
  hash: string;
  prev_hash: string;
  created_at: string;
  idempotency_key?: string;
}
export interface VerifyResponse {
  chain: string;
  ok: boolean;
  length: number;
  head: string;
  broken_at: number | null;
}
export interface LedgerOptions {
  chain: string;
  url?: string;
  token?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  spoolPath?: string;
  maxQueue?: number;
  baseRetryDelayMs?: number;
  maxRetryDelayMs?: number;
  flushOnExit?: boolean;
}
export interface RecordOptions {
  goalId?: string;
  policyVersion?: string;
  chain?: string;
  idempotencyKey?: string;
}

export class LedgerError extends Error {
  constructor(public status: number, public body: string) {
    super(`ledger: HTTP ${status}: ${body}`);
  }
}

const env = (k: string): string =>
  (typeof process !== "undefined" && process.env && process.env[k]) || "";

interface QueuedBody {
  chain: string;
  type: string;
  actor_chain: Actor[];
  payload: Record<string, unknown>;
  idempotency_key: string;
  goal_id?: string;
  policy_version?: string;
}

function defaultSpoolPath(chain: string, url: string): string {
  const key = crypto.createHash("sha256").update(`${url}|${chain}`).digest("hex").slice(0, 16);
  return path.join(os.tmpdir(), `ledger-sdk-spool-${key}.jsonl`);
}

export class Ledger {
  readonly chain: string;
  readonly url: string;
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxQueue: number;
  private readonly baseRetryDelayMs: number;
  private readonly maxRetryDelayMs: number;
  private readonly spool: Spool | null = null;
  private closed = false;
  private pumpRunning = false;
  private waiters: Array<() => void> = [];
  private exitHandler?: () => void;

  constructor(opts: LedgerOptions) {
    this.chain = opts.chain;
    this.url = (opts.url ?? env("LEDGER_URL")).replace(/\/+$/, "");
    this.token = opts.token ?? env("LEDGER_TOKEN");
    this.fetchImpl = opts.fetch ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.maxQueue = opts.maxQueue ?? 10000;
    this.baseRetryDelayMs = opts.baseRetryDelayMs ?? 200;
    this.maxRetryDelayMs = opts.maxRetryDelayMs ?? 30000;

    if (this.enabled) {
      this.spool = new Spool(opts.spoolPath ?? defaultSpoolPath(this.chain, this.url));
      if (opts.flushOnExit !== false && typeof process !== "undefined" && process.on) {
        this.exitHandler = () => {
          void this.flush(5000);
        };
        process.on("beforeExit", this.exitHandler);
      }
      this.schedulePump();
    }
  }

  get enabled(): boolean {
    return this.url !== "";
  }

  /** Number of records durably spooled but not yet confirmed sent. */
  get pending(): number {
    return this.spool ? this.spool.length : 0;
  }

  /** Queue a record for durable, ordered, retried delivery. Non-blocking; returns the body
   *  that was queued (delivery is asynchronous), or null if this client is disabled. */
  record(
    type: string,
    payload: Record<string, unknown>,
    actorChain: Actor[],
    opts: RecordOptions = {},
  ): QueuedBody | null {
    if (actorChain.length === 0 || actorChain[0].kind !== "human") {
      throw new Error("actor_chain must start with the originating human (kind 'human')");
    }
    if (!this.enabled || !this.spool) return null;
    const body: QueuedBody = {
      chain: opts.chain ?? this.chain,
      type,
      actor_chain: actorChain,
      payload: payload ?? {},
      idempotency_key: opts.idempotencyKey ?? crypto.randomUUID(),
    };
    if (opts.goalId) body.goal_id = opts.goalId;
    if (opts.policyVersion) body.policy_version = opts.policyVersion;
    this.spool.push(body);
    if (this.spool.length > this.maxQueue) {
      this.spool.dropFront(this.spool.length - this.maxQueue);
    }
    this.schedulePump();
    return body;
  }

  /** Resolves once the spool drains, or after timeoutMs elapses (resolves false on timeout). */
  async flush(timeoutMs?: number): Promise<boolean> {
    if (!this.enabled || !this.spool) return true;
    if (this.spool.length === 0) return true;
    return new Promise<boolean>((resolve) => {
      let done = false;
      const finish = (ok: boolean) => {
        if (done) return;
        done = true;
        resolve(ok);
      };
      this.waiters.push(() => finish(true));
      if (timeoutMs !== undefined) {
        setTimeout(() => finish(this.spool!.length === 0), timeoutMs).unref?.();
      }
      this.schedulePump();
    });
  }

  /** Stops the background pump. Does not wait for the spool to drain; call flush() first. */
  close(): void {
    this.closed = true;
    if (this.exitHandler && typeof process !== "undefined" && process.off) {
      process.off("beforeExit", this.exitHandler);
    }
  }

  async verify(chain?: string): Promise<VerifyResponse | null> {
    if (!this.enabled) return null;
    return this.req("GET", `/v1/chains/${encodeURIComponent(chain ?? this.chain)}/verify`);
  }

  async replay(goalId: string): Promise<unknown> {
    if (!this.enabled) return null;
    return this.req("GET", `/v1/goals/${encodeURIComponent(goalId)}/replay`);
  }

  // -- internals ------------------------------------------------------------------------

  private schedulePump(): void {
    if (this.pumpRunning || this.closed || !this.spool) return;
    this.pumpRunning = true;
    void this.pump();
  }

  private async pump(): Promise<void> {
    let attempt = 0;
    try {
      while (!this.closed) {
        const item = this.spool!.peekFront<QueuedBody>();
        if (item === null) {
          this.drainWaiters();
          return;
        }
        try {
          await this.req("POST", "/v1/records", item);
          this.spool!.popFront();
          attempt = 0;
        } catch (err) {
          if (err instanceof LedgerError && err.status >= 400 && err.status < 500) {
            // Non-retryable: drop so one bad record can't block the chain forever.
            this.spool!.popFront();
            attempt = 0;
            continue;
          }
          attempt += 1;
          await this.sleepBackoff(attempt);
        }
      }
    } finally {
      this.pumpRunning = false;
      this.drainWaiters();
    }
  }

  private drainWaiters(): void {
    const w = this.waiters;
    this.waiters = [];
    for (const f of w) f();
  }

  private sleepBackoff(attempt: number): Promise<void> {
    const raw = Math.min(this.maxRetryDelayMs, this.baseRetryDelayMs * 2 ** (attempt - 1));
    const delay = raw * (0.5 + Math.random());
    return new Promise((resolve) => setTimeout(resolve, delay));
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(this.url + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await res.text();
      if (!res.ok) throw new LedgerError(res.status, text);
      return JSON.parse(text) as T;
    } finally {
      clearTimeout(timer);
    }
  }
}
