#!/usr/bin/env python3
# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""LOCAL DEMO for the MSc edition. Binds 127.0.0.1 only. Do not deploy.

The home page is plain HTTP, with a password field and a cookie that has
neither HttpOnly nor Secure. /next has the two framing and sniffing headers.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
HOME = """<!DOCTYPE html>
<html><head><title>LOCAL DEMO</title></head>
<body>
<p>LOCAL DEMO / EXAMPLE. Not a real application. Do not deploy.</p>
<form method="post" action="/login">
  <input name="username" type="text">
  <input name="password" type="password">
  <button type="submit">Sign in</button>
</form>
<p><a href="/next">A second page on this origin</a></p>
<p><a href="http://example.com/outside">This link is a different origin</a></p>
</body></html>
"""
NEXT = """<!DOCTYPE html>
<html><head><title>LOCAL DEMO next</title></head>
<body><p>LOCAL DEMO / EXAMPLE. Second page.</p></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # pylint: disable=invalid-name
        if self.path.startswith("/go-file"):
            self.send_response(302)
            self.send_header("Location", "file:///tmp/not-requested")
            self.end_headers()
            return
        if self.path.startswith("/next"):
            body = NEXT.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
        else:
            body = HOME.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "demo=1; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # pylint: disable=arguments-differ
        return


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
    server = ThreadingHTTPServer((HOST, port), Handler)
    print(f"MSc demo on http://{HOST}:{port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
