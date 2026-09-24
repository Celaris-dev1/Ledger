// Regression tests: the spool must be private (0600 files in a per-user 0700 dir) and must
// never follow a planted symlink or replay a file other users can write.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Spool, SpoolSecurityError, checkOwned, privateDir } from "./spool.js";

const posix = process.platform !== "win32";
const mode = (p: string) => fs.statSync(p).mode & 0o777;

test("spool files and dir are private", { skip: !posix }, () => {
  const d = privateDir(fs.mkdtempSync(path.join(os.tmpdir(), "sp-")));
  assert.equal(mode(d), 0o700);
  const p = path.join(d, "s.jsonl");
  const sp = new Spool(p);
  sp.push({ a: 1 });
  sp.push({ a: 2 });
  assert.equal(mode(p), 0o600);
  sp.popFront();
  assert.equal(mode(p), 0o600);
});

test("planted symlinks are not followed", { skip: !posix }, () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "sp-"));
  const victim = path.join(base, "victim");
  fs.writeFileSync(victim, "precious\n");
  const p = path.join(base, "s.jsonl");
  fs.symlinkSync(victim, p);
  assert.throws(() => new Spool(p));
  fs.unlinkSync(p);
  const sp = new Spool(p);
  sp.push({ a: 1 });
  fs.symlinkSync(victim, p + ".tmp");
  sp.popFront();
  assert.equal(fs.readFileSync(victim, "utf8"), "precious\n");
});

test("world-writable spool is refused, not replayed", { skip: !posix }, () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "sp-"));
  const p = path.join(base, "s.jsonl");
  fs.writeFileSync(p, '{"type":"injected"}\n');
  fs.chmodSync(p, 0o666);
  assert.throws(() => new Spool(p), SpoolSecurityError);
});

test("symlinked private dir and foreign owner are refused", { skip: !posix }, () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "sp-"));
  const uid = process.getuid!();
  fs.symlinkSync(fs.mkdtempSync(path.join(os.tmpdir(), "sp-")), path.join(base, `ledger-sdk-${uid}`));
  assert.throws(() => privateDir(base), SpoolSecurityError);
  assert.throws(() => checkOwned({ uid: uid + 1, mode: 0o600 }, "x"), SpoolSecurityError);
});
