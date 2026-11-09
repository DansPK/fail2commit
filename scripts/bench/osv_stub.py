#!/usr/bin/env python3
"""Loopback-only OSV stub for the benchmarks (T-012). Never reaches a network.

Usage: osv_stub.py PORT_FILE. Binds 127.0.0.1:0, writes the port to PORT_FILE.
POST /v1/querybatch -> one clean result per query; GET /__hits -> request count.
"""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

HITS = {"n": 0}


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        HITS["n"] += 1
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        self._send(200, {"results": [{} for _ in body.get("queries", [])]})

    def do_GET(self):
        if self.path == "/__hits":
            return self._send(200, {"hits": HITS["n"]})
        HITS["n"] += 1
        self._send(404, {})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", 0), H)
    with open(sys.argv[1], "w") as f:
        f.write(str(srv.server_port))
    srv.serve_forever()
