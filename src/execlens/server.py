"""Tiny live server: dashboard at /, JSON at /api/data, health at /healthz. Stdlib only."""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import dashboard
from .app import State


def make_handler(state: State):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body: bytes, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                self._send(200, dashboard.render(None).encode(), "text/html; charset=utf-8")
            elif path == "/api/data":
                self._send(200, json.dumps(state.payload()).encode(), "application/json")
            elif path == "/healthz":
                self._send(200, b"ok", "text/plain")
            else:
                self._send(404, b"not found", "text/plain")

        def do_HEAD(self):
            self.send_response(200 if self.path.split("?")[0] in ("/", "/index.html", "/healthz", "/api/data") else 404)
            self.end_headers()

        def log_message(self, fmt, *args):  # quiet
            pass
    return H


def serve(state: State, host: str = "127.0.0.1", port: int = 8080, simulate: bool = False) -> None:
    if simulate:
        def loop():
            while True:
                time.sleep(4)
                state.tick(2)
        threading.Thread(target=loop, daemon=True).start()
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    print(f"ExecLens live at http://{host}:{port}  (simulate={'on' if simulate else 'off'})  Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
