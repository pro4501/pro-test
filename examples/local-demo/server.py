#!/usr/bin/env python3
# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""LOCAL DEMO / EXAMPLE fixture for Pro-Test passive checks.

Intentionally missing ordinary browser protections (security headers, cookie
flags, HTTPS). It is not an application. It does not run commands, read files,
query a database, or reflect the request into the page.

Bind address is always 127.0.0.1. Do not deploy this process.
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
BANNER = "LOCAL DEMO / EXAMPLE"
WARNING = (
    "Intentionally insecure localhost fixture for passive checks. "
    "Never deploy. Not a real application."
)

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LOCAL DEMO / EXAMPLE — do not deploy</title>
</head>
<body>
<h1>LOCAL DEMO / EXAMPLE</h1>
<p><strong>{warning}</strong></p>
<p>This response is static. Query strings and posted fields are discarded and are not shown back.</p>
<p>Example server path, included on purpose so a passive check can see it:
/var/www/local-demo/app/index.html</p>
<p><a href="/debug">Local demo debug page</a></p>
<form method="post" action="/login">
  <label>Username <input name="username" type="text" autocomplete="off"></label>
  <label>Password <input name="password" type="password" autocomplete="off"></label>
  <button type="submit">Sign in</button>
</form>
</body>
</html>
"""

DEBUG_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LOCAL DEMO / EXAMPLE — debug</title>
</head>
<body>
<h1>LOCAL DEMO / EXAMPLE</h1>
<p><strong>{warning}</strong></p>
<p>The block below is a fake traceback written into this static page. Nothing raised it.</p>
<pre>
Traceback (most recent call last):
  File "/var/www/local-demo/app/debug.py", line 12, in demo
    raise RuntimeError("local demo fixture")
RuntimeError: local demo fixture
</pre>
<p><a href="/">Back to the local demo home page</a></p>
</body>
</html>
"""

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LOCAL DEMO / EXAMPLE — login</title>
</head>
<body>
<h1>LOCAL DEMO / EXAMPLE</h1>
<p><strong>{warning}</strong></p>
<p>This local demo does not store, check, or display credentials.</p>
<p><a href="/">Back to the local demo home page</a></p>
</body>
</html>
"""

NOT_FOUND = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LOCAL DEMO / EXAMPLE — not found</title>
</head>
<body>
<h1>LOCAL DEMO / EXAMPLE</h1>
<p>That path is not part of this fixture. The requested path is not repeated here.</p>
<p><a href="/">Back to the local demo home page</a></p>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Pro-Test-Local-Demo"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("local-demo: " + (fmt % args) + "\n")

    def _send(self, status: int, body: str) -> None:
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            status = 403
            body = "<!DOCTYPE html><html><body><p>LOCAL DEMO / EXAMPLE refuses non-local clients.</p></body></html>"
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", "demo_session=local-example; Path=/")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _page(self, template: str) -> str:
        return template.format(warning=WARNING)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, self._page(PAGE))
        elif path == "/debug":
            self._send(200, self._page(DEBUG_PAGE))
        elif path == "/login":
            self._send(200, self._page(LOGIN_PAGE))
        else:
            self._send(404, NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(min(length, 1_000_000))
        path = self.path.split("?", 1)[0]
        if path == "/login":
            self._send(200, self._page(LOGIN_PAGE))
        else:
            self._send(404, NOT_FOUND)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()


def serve(port: int = 8765) -> ThreadingHTTPServer:
    """Listen on 127.0.0.1 only. ``port`` 0 asks the OS for a free port."""
    return ThreadingHTTPServer((HOST, port), Handler)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    port = 8765
    if args:
        try:
            port = int(args[0])
        except ValueError:
            print("Usage: python examples/local-demo/server.py [port]", file=sys.stderr)
            return 2
    try:
        server = serve(port)
    except OSError as error:
        print(f"Could not listen on {HOST}:{port}: {error}", file=sys.stderr)
        return 1
    bound = server.server_address[1]
    print(f"{BANNER}")
    print(WARNING)
    print(f"Listening on http://{HOST}:{bound}/")
    print("Press Ctrl+C to stop. Do not expose this process.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
