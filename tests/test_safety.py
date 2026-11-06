# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Localhost checks for scope, credentials, redirects, pause and storage.

Nothing here contacts a host other than 127.0.0.1. Extraction is not run.
"""
import os
import stat
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tempfile import TemporaryDirectory

from protest.app.cli import main
from protest.core.control import ScanControl, ScanStopped, resolve_vulnerability_policy
from protest.core.persister import Persister
from protest.core.vault import Vault, VaultError, VaultLegacyError
from protest.net.client import ClientConfiguration, HttpClient, HttpCredential
from protest.net.request import Request
from protest.net.response import Headers, Response
from protest.net.scope import Scope
from protest.passive.checks import ModuleInformationDisclosure


class _QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # pylint: disable=arguments-differ
        return


def _serve(handler) -> tuple:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class ScopeTruthTest(unittest.TestCase):
    def test_host_includes_port_and_subdomain_is_the_same_rule(self):
        base = Request("http://www.ex.com/app/")
        self.assertTrue(Scope(base, "host").check("http://www.ex.com/elsewhere"))
        self.assertFalse(Scope(base, "host").check("http://www.ex.com:8080/"))
        self.assertFalse(Scope(base, "subdomain").check("http://www.ex.com:8080/elsewhere"))
        self.assertTrue(Scope(base, "subdomain").check("http://www.ex.com/elsewhere"))
        self.assertFalse(Scope(base, "host").check("http://api.ex.com/"))

    def test_domain_does_not_guess_shared_suffixes(self):
        pages = Request("http://mine.github.io/course/")
        self.assertFalse(Scope(pages, "domain").check("http://other.github.io/"))
        self.assertTrue(Scope(pages, "domain").check("http://www.mine.github.io/x"))
        bucket = Request("http://bucket.s3.amazonaws.com/index.html")
        self.assertFalse(Scope(bucket, "domain").check("http://other.s3.amazonaws.com/"))
        internal = Request("http://app.internal.lan/")
        self.assertFalse(Scope(internal, "domain").check("http://other.internal.lan/"))
        self.assertTrue(Scope(internal, "domain").check("http://app.internal.lan/only"))

    def test_punk_rejects_non_web_schemes(self):
        base = Request("http://127.0.0.1/")
        self.assertFalse(Scope(base, "punk").check("file:///tmp/marker"))
        self.assertTrue(Scope(base, "punk").check("http://other.example/"))


class SecretAndRedirectTest(unittest.TestCase):
    def test_basic_credentials_stay_on_the_target_origin(self):
        seen = {"home": None, "other": None}

        class Home(_QuietHandler):
            def do_GET(self):  # pylint: disable=invalid-name
                seen["home"] = self.headers.get("Authorization")
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class Other(_QuietHandler):
            def do_GET(self):  # pylint: disable=invalid-name
                seen["other"] = self.headers.get("Authorization")
                body = b"other"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        home, home_url = _serve(Home)
        other, other_url = _serve(Other)
        try:
            origin = Request(home_url + "/")
            client = HttpClient(ClientConfiguration())
            client.bound_origin = origin
            client.scope = Scope(origin, "punk")
            client.config.credential = HttpCredential("user", "secret", "basic")
            client.send(Request(home_url + "/"))
            client.send(Request(other_url + "/"))
        finally:
            home.shutdown()
            other.shutdown()
        self.assertTrue(seen["home"] and seen["home"].startswith("Basic "))
        self.assertIsNone(seen["other"])

    def test_file_redirect_is_not_followed_and_cookie_is_not_forwarded(self):
        seen = {"cookie": "missing", "hits": 0}

        class Other(_QuietHandler):
            def do_GET(self):  # pylint: disable=invalid-name
                seen["hits"] += 1
                seen["cookie"] = self.headers.get("Cookie")
                body = b"landed"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        other, other_url = _serve(Other)

        class Home(_QuietHandler):
            def do_GET(self):  # pylint: disable=invalid-name
                if self.path.startswith("/file"):
                    self.send_response(302)
                    self.send_header("Location", "file:///tmp/protest-should-not-read")
                    self.end_headers()
                    return
                self.send_response(302)
                self.send_header("Location", other_url + "/landed")
                self.end_headers()

        home, home_url = _serve(Home)
        try:
            origin = Request(home_url + "/")
            client = HttpClient(ClientConfiguration())
            client.bound_origin = origin
            client.scope = Scope(origin, "punk")
            client.config.headers["Cookie"] = "session=secret"
            file_response = client.send(Request(home_url + "/file"), follow_redirects=True)
            hopped = client.send(Request(home_url + "/go"), follow_redirects=True)
        finally:
            home.shutdown()
            other.shutdown()
        self.assertEqual(file_response.status, 302)
        self.assertNotIn(b"protest-should-not-read", file_response.raw)
        self.assertEqual(hopped.status, 200)
        self.assertEqual(seen["hits"], 1)
        self.assertIsNone(seen["cookie"])


class PathAndConfidenceTest(unittest.TestCase):
    def test_link_paths_are_ignored_and_plain_paths_are_kept(self):
        html = '<a href="/home/about/team">team</a><p>log file /var/log/app</p>'
        response = Response("http://ex/", 200, Headers([("Content-Type", "text/html")]), html.encode(), 0.0)
        found = [item[2] for item in ModuleInformationDisclosure().analyze(Request("http://ex/"), response)]
        text = " ".join(found)
        self.assertIn("/var/log/app", text)
        self.assertNotIn("/home/about/team", text)

    def test_sql_error_confidence_rules(self):
        from protest.active.mod_sql import sql_error_confidence  # pylint: disable=import-outside-toplevel
        from protest.core.definitions import CONFIRMED, POSSIBLE, PROBABLE  # pylint: disable=import-outside-toplevel
        self.assertEqual(sql_error_confidence("SQL Injection (DBMS: MySQL)", True, "string"), CONFIRMED)
        self.assertEqual(sql_error_confidence("PHP PDO SQL Injection", True, "string"), PROBABLE)
        self.assertEqual(sql_error_confidence("SQL Injection (DBMS: MySQL)", False, "string"), POSSIBLE)
        self.assertEqual(sql_error_confidence("SQL Injection (DBMS: MySQL)", True, ""), PROBABLE)


class PauseAndStorageTest(unittest.TestCase):
    def test_policy_defaults_and_dedupe(self):
        class Silent:
            def isatty(self):
                return False

        class Terminal:
            def isatty(self):
                return True

        self.assertEqual(resolve_vulnerability_policy(None, Silent()), ("stop", False))
        self.assertEqual(resolve_vulnerability_policy(None, Terminal()), ("ask", True))
        self.assertEqual(resolve_vulnerability_policy("continue", Silent())[0], "continue")
        calls = []

        def answer(prompt):
            calls.append(prompt)
            return "1"

        control = ScanControl("ask", True, read_line=answer)
        control.observe("anomaly", "Internal Server Error", "http://h/a", "", "status")
        control.observe("vulnerability", "Clickjacking", "http://h/a", "", "missing header")
        control.observe("vulnerability", "Clickjacking", "http://h/b", "", "missing header")
        self.assertEqual(len(calls), 1)
        self.assertFalse(control.stopped)

        def end(_prompt):
            raise EOFError

        stopping = ScanControl("ask", True, read_line=end)
        stopping.observe("vulnerability", "Clickjacking", "http://h/a", "", "missing")
        self.assertTrue(stopping.stopped)
        with self.assertRaises(ScanStopped):
            stopping.before_request()

    def test_active_finding_blocks_the_next_request_and_legacy_vault_is_kept(self):
        with TemporaryDirectory() as tmp:
            control = ScanControl("stop", False)
            client = HttpClient(ClientConfiguration())
            client.control = control
            persister = Persister(os.path.join(tmp, "session.db"), control=control)
            mode = os.stat(persister.filename).st_mode & 0o777
            self.assertEqual(mode, 0o600)
            persister.add_finding("vulnerability", "sql", "SQL Injection", 4, Request("http://127.0.0.1/"),
                                  "id", "error text", [], None)
            with self.assertRaises(ScanStopped):
                client.send(Request("http://127.0.0.1/next"))
            persister.close()
            self.assertEqual(client.request_count, 0)

            vault = Vault(os.path.join(tmp, "k.key"))
            token = vault.encrypt("admin123")
            self.assertTrue(token.startswith("pt2:"))
            self.assertEqual(vault.decrypt(token), "admin123")
            with self.assertRaises(VaultLegacyError):
                vault.decrypt("pt1:aGVsbG8")
            with self.assertRaises(VaultError):
                vault.decrypt(token[:-4] + "AAAA")

    def test_stop_writes_a_report_and_does_not_request_the_next_page(self):
        hits = []

        class Handler(_QuietHandler):
            def do_GET(self):  # pylint: disable=invalid-name
                hits.append(self.path.split("?", 1)[0])
                if self.path.startswith("/next"):
                    body = b"<html><p>second page</p></html>"
                else:
                    body = b"<html><a href='/next'>next</a><p>home</p></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server, base = _serve(Handler)
        try:
            with TemporaryDirectory() as tmp:
                report = os.path.join(tmp, "report.txt")
                code = main([
                    "-u", base + "/", "-m", "passive", "--scope", "folder", "--tasks", "1", "-d", "2",
                    "--on-vulnerability", "stop", "--flush-session", "--no-database",
                    "--store-session", tmp, "-f", "txt", "-o", report,
                ])
                self.assertEqual(code, 0)
                self.assertTrue(os.path.isfile(report))
                text = open(report, encoding="utf-8").read()
                self.assertIn("Clickjacking", text)
                self.assertEqual(hits, ["/"])
                self.assertEqual(stat.S_IMODE(os.stat(report).st_mode), 0o600)
        finally:
            server.shutdown()

    def test_continue_reaches_the_second_page(self):
        hits = []

        class Handler(_QuietHandler):
            def do_GET(self):  # pylint: disable=invalid-name
                hits.append(self.path.split("?", 1)[0])
                body = b"<html><a href='/next'>next</a></html>" if not self.path.startswith("/next") else b"<html>ok</html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server, base = _serve(Handler)
        try:
            with TemporaryDirectory() as tmp:
                code = main([
                    "-u", base + "/", "-m", "passive", "--tasks", "1", "-d", "2",
                    "--on-vulnerability", "continue", "--flush-session", "--no-database",
                    "--store-session", tmp, "-f", "txt", "-o", os.path.join(tmp, "report.txt"),
                ])
                self.assertEqual(code, 0)
                self.assertIn("/next", hits)
        finally:
            server.shutdown()
