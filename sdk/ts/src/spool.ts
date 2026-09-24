/**
 * On-disk JSONL spool so queued records survive process restarts and ledgerd outages, and are
 * replayed in their original order on reconnect. Zero runtime dependencies: only Node's `fs`.
 */
import * as fs from "node:fs";
import * as path from "node:path";

/*
 * Security: the spool holds unsent evidence and is replayed with the client's token, so it is
 * private to the current user. Files are created 0600 without following symlinks, and an
 * existing spool that another user owns, or that others can write, is refused rather than
 * replayed (a local user could otherwise pre-create it in a shared temp dir and inject records
 * sent under your identity, or plant a symlink to clobber another file).
 */
const C = fs.constants;
const NOFOLLOW = C.O_NOFOLLOW ?? 0;
const posix = process.platform !== "win32";

export class SpoolSecurityError extends Error {}

export function checkOwned(st: { uid: number; mode: number }, what: string): void {
  if (posix && typeof process.getuid === "function" && st.uid !== process.getuid()) {
    throw new SpoolSecurityError(`ledger spool ${what} is owned by uid ${st.uid}, not you; refusing to use it`);
  }
  if (posix && (st.mode & 0o022) !== 0) {
    throw new SpoolSecurityError(`ledger spool ${what} is writable by other users; refusing to use it`);
  }
}

function openPrivate(p: string, flags: number): number {
  const fd = fs.openSync(p, flags | NOFOLLOW, 0o600);
  try {
    checkOwned(fs.fstatSync(fd), p);
    if (posix) fs.fchmodSync(fd, 0o600);
  } catch (e) {
    fs.closeSync(fd);
    throw e;
  }
  return fd;
}

/** A per-user 0700 directory under base, ownership-checked (safe in a shared /tmp). */
export function privateDir(base: string): string {
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  const d = path.join(base, uid === undefined ? "ledger-sdk" : `ledger-sdk-${uid}`);
  try {
    fs.mkdirSync(d, { mode: 0o700 });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
  }
  const st = fs.lstatSync(d);
  if (!st.isDirectory()) throw new SpoolSecurityError(`ledger spool dir ${d} is not a directory (symlink?); refusing to use it`);
  checkOwned(st, d);
  if (posix && (st.mode & 0o077) !== 0) fs.chmodSync(d, 0o700);
  return d;
}

export class Spool {
  private lines: string[] = [];

  constructor(private readonly path: string) {
    this.load();
  }

  private load(): void {
    let fd: number;
    try {
      fd = openPrivate(this.path, C.O_RDONLY);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") {
        this.lines = [];
        return;
      }
      throw e;
    }
    try {
      const text = fs.readFileSync(fd, "utf8");
      this.lines = text.split("\n").filter((l) => l.trim() !== "");
    } finally {
      fs.closeSync(fd);
    }
  }

  private rewrite(): void {
    const tmp = this.path + ".tmp";
    fs.rmSync(tmp, { force: true }); // never write through a pre-planted file or symlink
    const fd = openPrivate(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL);
    try {
      fs.writeFileSync(fd, this.lines.map((l) => l + "\n").join(""));
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.path);
  }

  push(record: unknown): void {
    const line = JSON.stringify(record);
    const fd = openPrivate(this.path, C.O_WRONLY | C.O_CREAT | C.O_APPEND);
    try {
      fs.writeSync(fd, line + "\n");
    } finally {
      fs.closeSync(fd);
    }
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
