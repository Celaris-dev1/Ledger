"""e2e driver for the Python SDK (run as a real subprocess by e2e/sdk_test.go).

usage: sdk_driver.py SPOOL CHAIN GOAL START COUNT FLUSH_TIMEOUT [lose-first-ack]
Records COUNT records (payload {"n": START+i}) and flushes; prints "pending=<n>".
With lose-first-ack the first successful POST's response is dropped (as if the connection died
after ledgerd committed), so the SDK re-sends it and only the idempotency key prevents a duplicate.
"""
import sys

from ledger_sdk import Ledger

spool, chain, goal, start, count, flush_timeout = sys.argv[1:7]
lose = len(sys.argv) > 7 and sys.argv[7] == "lose-first-ack"
led = Ledger(chain, spool_path=spool, flush_on_exit=False, base_retry_delay=0.05, max_retry_delay=0.5, timeout=2.0)
if lose:
    real = led._transport
    state = {"lost": False}

    def lossy(path, body):
        res = real(path, body)
        if not state["lost"]:
            state["lost"] = True
            raise ConnectionResetError("e2e: response lost after commit")
        return res

    led._transport = lossy
actors = [{"kind": "human", "id": "alice"}, {"kind": "agent", "id": "py-agent", "model": "m", "model_version": "1"}]
for i in range(int(start), int(start) + int(count)):
    led.record("ledger.memory.written", {"key": "n", "n": i, "sdk": "python"}, actors, goal_id=goal)
print("queued", flush=True)
led.flush(timeout=float(flush_timeout))
led.close()
print("pending=%d" % led.pending(), flush=True)
