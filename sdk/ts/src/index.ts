/**
 * Ledger TypeScript SDK (no runtime dependencies; uses global fetch, Node >= 18).
 *
 *   const ledger = new Ledger({ chain: "warrant" });   // LEDGER_URL / LEDGER_TOKEN from env
 *   await ledger.record("warrant.token.issued", { scope: "repo:read" },
 *     [{ kind: "human", id: "alice" }, { kind: "agent", id: "coder" }], { goalId: "g-1" });
 *
 * If no URL is configured, record() is a no-op and resolves to null.
 */

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
}
export interface RecordOptions {
  goalId?: string;
  policyVersion?: string;
  chain?: string;
}

export class LedgerError extends Error {
  constructor(public status: number, public body: string) {
    super(`ledger: HTTP ${status}: ${body}`);
  }
}

const env = (k: string): string =>
  (typeof process !== "undefined" && process.env && process.env[k]) || "";

export class Ledger {
  readonly chain: string;
  readonly url: string;
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: LedgerOptions) {
    this.chain = opts.chain;
    this.url = (opts.url ?? env("LEDGER_URL")).replace(/\/+$/, "");
    this.token = opts.token ?? env("LEDGER_TOKEN");
    this.fetchImpl = opts.fetch ?? fetch;
  }

  get enabled(): boolean {
    return this.url !== "";
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const res = await this.fetchImpl(this.url + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new LedgerError(res.status, text);
    return JSON.parse(text) as T;
  }

  async record(
    type: string,
    payload: Record<string, unknown>,
    actorChain: Actor[],
    opts: RecordOptions = {},
  ): Promise<RecordResponse | null> {
    if (actorChain.length === 0 || actorChain[0].kind !== "human") {
      throw new Error("actor_chain must start with the originating human (kind 'human')");
    }
    if (!this.enabled) return null;
    const body: Record<string, unknown> = {
      chain: opts.chain ?? this.chain,
      type,
      actor_chain: actorChain,
      payload: payload ?? {},
    };
    if (opts.goalId) body.goal_id = opts.goalId;
    if (opts.policyVersion) body.policy_version = opts.policyVersion;
    return this.req<RecordResponse>("POST", "/v1/records", body);
  }

  async verify(chain?: string): Promise<VerifyResponse | null> {
    if (!this.enabled) return null;
    return this.req("GET", `/v1/chains/${encodeURIComponent(chain ?? this.chain)}/verify`);
  }

  async replay(goalId: string): Promise<unknown> {
    if (!this.enabled) return null;
    return this.req("GET", `/v1/goals/${encodeURIComponent(goalId)}/replay`);
  }
}
