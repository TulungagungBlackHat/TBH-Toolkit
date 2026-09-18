"""Local mock HTTP server fixture: never hits public internet."""
from __future__ import annotations

import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/reflect":
            q = qs.get("q", [""])[0]
            body = f"<html><body>echo:{q}</body></html>"
            self._send(200, body)
        elif parsed.path == "/sql":
            q = qs.get("q", qs.get("id", [""]))[0] if qs else ""
            body = "You have an error in your SQL syntax near ''" if q in ("'", '"') else "ok"
            self._send(200, body)
        elif parsed.path == "/headers":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b"<html>hi</html>")
        elif parsed.path == "/cors":
            self.send_response(200)
            origin = self.headers.get("Origin", "")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"cors")
        elif parsed.path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n", ctype="text/plain")
        elif parsed.path in ("/security.txt", "/.well-known/security.txt"):
            self._send(200, "Contact: mailto:security@example.com\n", ctype="text/plain")
        elif parsed.path == "/sitemap.xml":
            self._send(200, "<urlset/>", ctype="text/xml")
        elif parsed.path == "/slow":
            import time
            time.sleep(0.05)
            self._send(200, "slow ok")
        else:
            body = "<html><body>lab home <a href='/app.js'>js</a></body></html>"
            self._send(200, body)

    def do_POST(self):
        self._send(200, "posted")

    def _send(self, code, body, ctype="text/html"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="session")
def lab_server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
