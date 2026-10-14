#!/usr/bin/env python3
# Fake keep-alive backend that counts distinct TCP connections (accepts).
# Each new connection gets a monotonically increasing conn_id; the response
# reports that connection's id plus the cumulative total. Reused connections
# report the SAME conn_id; every freshly-opened connection bumps total_conns.
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

lock = threading.Lock()
counter = {"n": 0}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive by default

    def setup(self):
        with lock:
            counter["n"] += 1
            self.conn_id = counter["n"]
        super().setup()

    def do_GET(self):
        body = json.dumps(
            {"conn_id": self.conn_id, "total_conns": counter["n"]},
            separators=(",", ":"),
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
