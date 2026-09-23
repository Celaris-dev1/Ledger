import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from ledger_sdk import Ledger, LedgerError


class _H(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _H.seen.append((self.path, self.headers.get("Authorization"), body))
        if body["actor_chain"][0]["id"] == "bad":
            self.send_response(400); self.end_headers(); self.wfile.write(b'{"error":"x"}'); return
        self.send_response(201); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"id": "u", "chain": body["chain"], "seq": 1, "hash": "h", "prev_hash": "", "created_at": "t"}).encode())

    def log_message(self, *a):
        pass


class SDKTest(unittest.TestCase):
    def test_noop_without_url(self):
        self.assertIsNone(Ledger("gate", url="").record("t", {}, [{"kind": "human", "id": "a"}]))

    def test_requires_human_first(self):
        with self.assertRaises(ValueError):
            Ledger("gate", url="").record("t", {}, [{"kind": "agent", "id": "a"}])

    def test_posts_contract_body(self):
        srv = HTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            l = Ledger("gate", url="http://127.0.0.1:%d" % srv.server_port, token="tok")
            r = l.record("gate.run.started", {"a": 1}, [{"kind": "human", "id": "alice"}], goal_id="g1")
            self.assertEqual(r["seq"], 1)
            path, auth, body = _H.seen[-1]
            self.assertEqual(path, "/v1/records")
            self.assertEqual(auth, "Bearer tok")
            self.assertEqual(body["goal_id"], "g1")
            with self.assertRaises(LedgerError):
                l.record("t", {}, [{"kind": "human", "id": "bad"}])
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
