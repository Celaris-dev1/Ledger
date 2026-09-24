// e2e driver for the TypeScript SDK (see sdk_driver.py for the protocol).
// usage: node sdk_driver.mjs SDK_DIST SPOOL CHAIN GOAL START COUNT FLUSH_TIMEOUT_S [lose-first-ack]
const [dist, spool, chain, goal, start, count, flushTimeout, mode] = process.argv.slice(2);
const { Ledger } = await import(dist + "/index.js");
let lost = false;
const lossy = async (url, init) => {
  const res = await fetch(url, init);
  if (mode === "lose-first-ack" && res.ok && !lost) {
    lost = true;
    throw new TypeError("e2e: response lost after commit");
  }
  return res;
};
const led = new Ledger({
  chain, spoolPath: spool, flushOnExit: false, baseRetryDelayMs: 50, maxRetryDelayMs: 500, timeoutMs: 2000, fetch: lossy,
});
const actors = [{ kind: "human", id: "alice" }, { kind: "agent", id: "ts-agent", model: "m", model_version: "1" }];
for (let i = Number(start); i < Number(start) + Number(count); i++) {
  led.record("ledger.memory.written", { key: "n", n: i, sdk: "ts" }, actors, { goalId: goal });
}
console.log("queued");
await led.flush(Number(flushTimeout) * 1000);
led.close();
console.log(`pending=${led.pending}`);
process.exit(0);
