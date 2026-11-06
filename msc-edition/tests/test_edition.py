# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Deterministic checks for the educational edition. Localhost only."""
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tempfile import TemporaryDirectory

from protest_msc.checks import Finding, cleartext_password, header_notices, inspect_page
from protest_msc.cli import main
from protest_msc.fetch import FetchedPage
from protest_msc.pause import Pause, resolve_policy
from protest_msc.scope import same_origin


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # pylint: disable=arguments-differ
        return


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _page(url: str, body: str, headers=None, status: int = 200) -> FetchedPage:
    return FetchedPage(url, status, headers or [("Content-Type", "text/html")], body, "")


class CheckRulesTest(unittest.TestCase):
    def test_cleartext_is_http_only(self):
        form = "<form><input type='password' name='p'></form>"
        http_findings = cleartext_password(_page("http://127.0.0.1/login", form))
        https_findings = cleartext_password(_page("https://127.0.0.1/login", form))
        self.assertEqual(len(http_findings), 1)
        self.assertEqual(http_findings[0].kind, "vulnerability")
        self.assertEqual(https_findings, [])

    def test_present_headers_are_not_findings(self):
        protected = _page("http://127.0.0.1/", "<html></html>", [
            ("Content-Type", "text/html"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Set-Cookie", "a=b; HttpOnly; Secure"),
        ])
        self.assertEqual(header_notices(protected), [])
        self.assertEqual([item.kind for item in inspect_page(protected)], [])
        missing = header_notices(_page("http://127.0.0.1/", "<html></html>"))
        self.assertEqual({item.name for item in missing}, {"No framing header", "No nosniff header"})
        self.assertTrue(all(item.kind == "notice" for item in missing))

    def test_other_port_is_not_the_same_origin(self):
        self.assertTrue(same_origin("http://127.0.0.1/a", "http://127.0.0.1/b"))
        self.assertFalse(same_origin("http://127.0.0.1/a", "http://127.0.0.1:9/b"))
        self.assertFalse(same_origin("http://127.0.0.1/a", "file:///tmp/x"))


class CrawlPolicyTest(unittest.TestCase):
    def _handler(self, hits, foreign_hits, foreign_url):
        class Handler(_Quiet):
            def do_GET(self):  # pylint: disable=invalid-name
                hits.append(self.path.split("?", 1)[0])
                if self.path.startswith("/next"):
                    body = b"<html><p>second</p></html>"
                else:
                    body = (
                        "<html><form><input type='password'></form>"
                        "<a href='/next'>next</a>"
                        f"<a href='{foreign_url}/foreign'>out</a></html>"
                    ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class Foreign(_Quiet):
            def do_GET(self):  # pylint: disable=invalid-name
                foreign_hits.append(self.path)
                self.send_response(200)
                self.end_headers()

        return Handler, Foreign

    def test_stop_does_not_fetch_the_next_page_and_keeps_the_report(self):
        hits, foreign_hits = [], []
        foreign, foreign_url = _serve(self._handler([], foreign_hits, "http://127.0.0.1")[1])
        Handler, _foreign_cls = self._handler(hits, foreign_hits, foreign_url)
        server, base = _serve(Handler)
        try:
            with TemporaryDirectory() as tmp:
                report = os.path.join(tmp, "report.txt")
                code = main([base + "/", "--max-depth", "2", "--on-finding", "stop", "--report", report])
                text = open(report, encoding="utf-8").read()
        finally:
            server.shutdown()
            foreign.shutdown()
        self.assertEqual(code, 0)
        self.assertEqual(hits, ["/"])
        self.assertEqual(foreign_hits, [])
        self.assertIn("Cleartext password field", text)
        self.assertIn("Stopped early: yes", text)
        self.assertIn("[vulnerability]", text)

    def test_continue_fetches_the_next_page_and_ignores_off_origin_targets(self):
        hits, foreign_hits = [], []
        foreign, foreign_url = _serve(self._handler([], foreign_hits, "http://127.0.0.1")[1])
        Handler, _foreign_cls = self._handler(hits, foreign_hits, foreign_url)
        server, base = _serve(Handler)
        try:
            code = main([base + "/", "--max-depth", "2", "--on-finding", "continue"])
        finally:
            server.shutdown()
            foreign.shutdown()
        self.assertEqual(code, 0)
        self.assertIn("/next", hits)
        self.assertEqual(foreign_hits, [])

    def test_redirects_off_origin_are_not_requested(self):
        hits = []

        class Handler(_Quiet):
            def do_GET(self):  # pylint: disable=invalid-name
                hits.append(self.path)
                self.send_response(302)
                target = "file:///tmp/not-requested" if self.path.startswith("/file") else "http://127.0.0.1:9/nope"
                self.send_header("Location", target)
                self.end_headers()

        server, base = _serve(Handler)
        try:
            with TemporaryDirectory() as tmp:
                report = os.path.join(tmp, "report.txt")
                code = main([base + "/file", "--on-finding", "continue", "--report", report])
                text = open(report, encoding="utf-8").read()
        finally:
            server.shutdown()
        self.assertEqual(code, 0)
        self.assertEqual(hits, ["/file"])
        self.assertIn("Redirect not followed", text)
        self.assertIn("file:///tmp/not-requested", text)

    def test_noninteractive_default_is_stop_and_repeat_does_not_ask_again(self):
        class Silent:
            def isatty(self):
                return False

        self.assertEqual(resolve_policy(None, Silent()), ("stop", False))
        calls = []

        def answer(_prompt):
            calls.append(1)
            return "1"

        pause = Pause("ask", True, read_line=answer)
        finding = Finding("vulnerability", "Cookie without HttpOnly", "http://127.0.0.1/a", "missing")
        pause.observe(finding)
        pause.observe(Finding("vulnerability", "Cookie without HttpOnly", "http://127.0.0.1/b", "missing"))
        pause.observe(Finding("notice", "No nosniff header", "http://127.0.0.1/a", "missing"))
        self.assertEqual(calls, [1])
        self.assertFalse(pause.stopped)

        def end(_prompt):
            raise EOFError

        stopping = Pause("ask", True, read_line=end)
        stopping.observe(finding)
        self.assertTrue(stopping.stopped)
