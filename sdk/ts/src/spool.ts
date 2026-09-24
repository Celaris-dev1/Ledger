/**
 * On-disk JSONL spool so queued records survive process restarts and ledgerd outages, and are
 * replayed in their original order on reconnect. Zero runtime dependencies: only Node's `fs`.
 */
import * as fs from "node:fs";

export class Spool {
  private lines: string[] = [];

  constructor(private readonly path: string) {
    this.load();
  }

  private load(): void {
    try {
      const text = fs.readFileSync(this.path, "utf8");
      this.lines = text.split("\n").filter((l) => l.trim() !== "");
    } catch {
      this.lines = [];
    }
  }

  private rewrite(): void {
    const tmp = this.path + ".tmp";
    fs.writeFileSync(tmp, this.lines.map((l) => l + "\n").join(""), { flag: "w" });
    fs.renameSync(tmp, this.path);
  }

  push(record: unknown): void {
    const line = JSON.stringify(record);
    fs.appendFileSync(this.path, line + "\n");
    this.lines.push(line);
  }

  peekFront<T = unknown>(): T | null {
    if (this.lines.length === 0) return null;
    return JSON.parse(this.lines[0]) as T;
  }

  popFront(): void {
    if (this.lines.length === 0) return;
    this.lines.shift();
    this.rewrite();
  }

  dropFront(n: number): void {
    if (n <= 0) return;
    this.lines.splice(0, n);
    this.rewrite();
  }

  get length(): number {
    return this.lines.length;
  }
}
