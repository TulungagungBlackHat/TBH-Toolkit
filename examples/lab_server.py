"""Bundled vulnerable lab server (127.0.0.1 only). For `toolkit scan` demos.

Run:  python examples/lab_server.py 8000
Then: toolkit scan --target http://127.0.0.1:8000
"""
from __future__ import annotations

import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


class Lab(BaseHTTPRequestHandler):
    server_version = "LabServer/1.0"

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/reflect":
            q = qs.get("q", [""])[0]
            body = f"<html><body>echo:{q}</body></html>"
            self._send(200, body)
        elif parsed.path == "/sql":
            v = qs.get("id", qs.get("q", [""]))[0] if qs else ""
            body = "You have an error in your SQL syntax" if v in ("'", '"') else "row ok"
            self._send(200, body)
        elif parsed.path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n", ctype="text/plain")
        elif parsed.path in ("/security.txt", "/.well-known/security.txt"):
            self._send(200, "Contact: mailto:security@example.com\n", ctype="text/plain")
        elif parsed.path == "/sitemap.xml":
            self._send(200, "<urlset/>", ctype="text/xml")
        elif parsed.path == "/admin":
            self._send(403, "forbidden")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b"<html><body>TBH lab home</body></html>")

    def _send(self, code, body, ctype="text/html"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        sys.stderr.write(f"[lab] {self.command} {self.path} -> done\n")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"[lab] http://127.0.0.1:{port} (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", port), Lab).serve_forever()
