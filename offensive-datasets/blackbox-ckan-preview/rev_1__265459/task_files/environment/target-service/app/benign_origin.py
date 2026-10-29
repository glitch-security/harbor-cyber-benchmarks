"""Benign public content origin for the seeded open-data portal.

Serves a handful of ordinary files (image / webpage / text / CSV) with plain
Content-Length framing on loopback. The seeded public datasets link their
resources here, so previewing linked resources through the gateway is a normal,
pervasive portal feature exercised across many datasets -- not something unique
to any one resource. Carries no private data.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.getenv("BENIGN_PORT", "5222"))

FILES = {
    "/logo.svg": ("image/svg+xml",
                  b'<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40">'
                  b'<rect width="120" height="40" fill="#1f6feb"/>'
                  b'<text x="8" y="26" fill="#fff" font-size="16">OpenData</text></svg>'),
    "/about.html": ("text/html",
                    b"<!doctype html><html><head><title>About</title></head><body>"
                    b"<h1>City Open Data</h1><p>Public datasets published by the city.</p>"
                    b"</body></html>"),
    "/readme.txt": ("text/plain",
                    b"City Open Data portal\n\nThis portal publishes public datasets.\n"
                    b"Each dataset may carry one or more resources with preview views.\n"),
    "/timetable.csv": ("text/csv",
                       b"route,stop,minutes\n12,Central,0\n12,Market,4\n12,Harbour,9\n"
                       b"34,Central,0\n34,Airport,21\n"),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _serve(self, write_body):
        entry = FILES.get(self.path.split("?", 1)[0])
        if entry is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        ctype, body = entry
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if write_body:
            self.wfile.write(body)

    def do_HEAD(self):
        self._serve(False)

    def do_GET(self):
        self._serve(True)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
