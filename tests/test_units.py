"""Unit tests for the core building blocks (no network)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# pylint: disable=wrong-import-position
from protest.active.base import Mutator, ParameterSituation, Payload
from protest.active.registry import resolve_module_settings
from protest.active.xss_engine import check_payload, generate_payloads, get_context_list
from protest.parsing.page import Html
from protest.net.request import Request
from protest.net.scope import Scope


class RequestTest(unittest.TestCase):
    def test_query_parsing_and_encoding(self):
        request = Request("http://example.com/a/b.php?x=1&y=&flag#frag")
        self.assertEqual(request.get_params, [["x", "1"], ["y", ""], ["flag", None]])
        self.assertEqual(request.url, "http://example.com/a/b.php?x=1&y=&flag")
        self.assertEqual(request.file_name, "b.php")
        self.assertEqual(request.dir_name, "http://example.com/a/")

    def test_post_and_identity(self):
        first = Request("http://example.com/login", post_params=[["user", "a"]])
        second = Request("http://example.com/login", post_params="user=a")
        self.assertEqual(first.method, "POST")
        self.assertEqual(first, second)
        self.assertEqual(Request.from_json(first.to_json()), first)

    def test_multipart_body(self):
        request = Request("http://example.com/up", post_params=[["a", "1"]],
                          file_params=[["f", ["x.gif", b"GIF89a", "image/gif"]]])
        body, content_type = request.build_body()
        self.assertIn(b'filename="x.gif"', body)
        self.assertTrue(content_type.startswith("multipart/form-data; boundary="))


class MutatorTest(unittest.TestCase):
    def test_every_parameter_is_mutated_once(self):
        request = Request("http://example.com/p?a=1&b=2", post_params=[["c", "3"]])
        mutations = list(Mutator().mutate(request, [Payload("[VALUE]X")]))
        names = [(param.name, param.situation) for _, param, _ in mutations]
        self.assertEqual(names, [("a", ParameterSituation.QUERY_STRING), ("b", ParameterSituation.QUERY_STRING),
                                 ("c", ParameterSituation.POST_BODY)])
        evil, _, payload = mutations[0]
        self.assertEqual(payload.payload, "1X")
        self.assertEqual(evil.get_params, [["a", "1X"], ["b", "2"]])

    def test_json_and_query_string_injection(self):
        request = Request("http://example.com/api", post_params='{"user": {"name": "bob"}, "ids": [1]}',
                          enctype="application/json")
        names = [param.name for _, param, _ in Mutator().mutate(request, [Payload("z")])]
        self.assertEqual(names, ["user.name", "ids.0"])
        qs = list(Mutator(qs_inject=True).mutate(Request("http://example.com/page"), [Payload("'")]))
        self.assertTrue(qs[0][1].is_qs_injection)
        self.assertEqual(qs[0][0].url, "http://example.com/page?%27")

    def test_skip_list(self):
        request = Request("http://example.com/p?a=1&__VIEWSTATE=x&b=2")
        names = [param.name for _, param, _ in Mutator(skip={"b"}).mutate(request, [Payload("z")])]
        self.assertEqual(names, ["a"])


class XssEngineTest(unittest.TestCase):
    def test_contexts(self):
        page = '<a href="TAINT">x</a><!-- TAINT --><textarea>TAINT</textarea><input value=TAINT>'
        types = {(c["type"], c.get("tag") or c.get("parent")) for c in get_context_list(page, "taint")}
        self.assertIn(("attrval", "a"), types)
        self.assertIn(("comment", "#document"), types)
        self.assertIn(("text", "textarea"), types)
        self.assertIn(("attrval", "input"), types)

    def test_payload_breaks_out_of_textarea(self):
        page = "<html><body><textarea>w1234567</textarea></body></html>"
        payloads = generate_payloads(page, "w1234567")
        self.assertTrue(payloads[0].payload.startswith("</textarea>"))
        rendered = page.replace("w1234567", payloads[0].payload)
        self.assertTrue(check_payload(rendered, payloads[0], "w1234567"))

    def test_escaped_payload_is_not_confirmed(self):
        import html  # pylint: disable=import-outside-toplevel
        page = "<p>w1234567</p>"
        payload = generate_payloads(page, "w1234567")[0]
        rendered = page.replace("w1234567", html.escape(payload.payload))
        self.assertFalse(check_payload(rendered, payload, "w1234567"))


class HtmlTest(unittest.TestCase):
    def test_links_and_forms(self):
        html = Html("""<base href="http://ex.com/dir/"><a href="page.php?id=1">a</a>
        <script>window.location = "/js-redirect.php";</script>
        <form method="post" action="login.php"><input name="user"><input type="password" name="pass">
        <select name="s"><option value="1">1</option></select><input type="submit" name="go" value="Go"></form>""",
                    "http://ex.com/index.html")
        self.assertIn("http://ex.com/dir/page.php?id=1", html.links)
        self.assertIn("http://ex.com/js-redirect.php", html.js_redirections)
        request = next(html.iter_forms()).to_requests()[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "http://ex.com/dir/login.php")
        self.assertEqual(request.post_params, [["user", "default"], ["pass", "Letm3in_"], ["s", "1"], ["go", "Go"]])


class ScopeAndModulesTest(unittest.TestCase):
    def test_scopes(self):
        base = Request("http://www.ex.com/app/index.php")
        self.assertTrue(Scope(base, "folder").check("http://www.ex.com/app/other.php"))
        self.assertFalse(Scope(base, "folder").check("http://www.ex.com/other.php"))
        self.assertFalse(Scope(base, "folder").check("http://api.ex.com/app/other.php"))
        self.assertFalse(Scope(base, "folder").check("http://www.ex.com.evil/app/other.php"))
        self.assertTrue(Scope(base, "domain").check("http://api.ex.com/"))
        self.assertFalse(Scope(base, "subdomain").check("http://api.ex.com/"))
        self.assertTrue(Scope(base, "subdomain").check("http://www.ex.com/elsewhere"))
        self.assertTrue(Scope(base, "punk").check("http://anywhere.example/"))
        self.assertTrue(Scope(base, "page").check("http://www.ex.com/app/index.php?x=1"))
        self.assertFalse(Scope(base, "url").check("http://www.ex.com/app/index.php?x=1"))

    def test_module_option_syntax(self):
        self.assertIn("xss", resolve_module_settings(None))
        self.assertEqual(resolve_module_settings(""), {})
        settings = resolve_module_settings("common,-xss,sql:get")
        self.assertNotIn("xss", settings)
        self.assertEqual(settings["sql"], {"GET"})
        with self.assertRaises(ValueError):
            resolve_module_settings("nonexistent")


class RateLimitAndProfileTest(unittest.TestCase):
    def test_rate_limiter_spaces_requests(self):
        import time  # pylint: disable=import-outside-toplevel
        from protest.net.client import RateLimiter  # pylint: disable=import-outside-toplevel
        limiter = RateLimiter(max_rps=20)
        start = time.monotonic()
        for _ in range(6):
            limiter.wait()
        self.assertGreaterEqual(time.monotonic() - start, 0.24)  # 5 intervals of 50 ms
        self.assertAlmostEqual(limiter.rate, 20)

    def test_auto_throttle_retries_on_429(self):
        import threading  # pylint: disable=import-outside-toplevel
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # pylint: disable=import-outside-toplevel
        from protest.net.client import ClientConfiguration, HttpClient  # pylint: disable=import-outside-toplevel

        calls = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):  # pylint: disable=invalid-name
                calls.append(1)
                status = 429 if len(calls) == 1 else 200
                self.send_response(status)
                self.send_header("Retry-After", "0")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            client = HttpClient(ClientConfiguration(timeout=5))
            response = client.get(f"http://127.0.0.1:{server.server_address[1]}/")
        finally:
            server.shutdown()
        self.assertEqual(response.status, 200)
        self.assertEqual(len(calls), 2)
        self.assertEqual(client.throttled_count, 1)
        self.assertGreater(client.limiter.interval, 0)  # the scan slowed down after the 429

    def test_profiles_only_override_defaults(self):
        from protest.app.cli import PROFILES, apply_profile, build_parser  # pylint: disable=C0415
        self.assertEqual(set(PROFILES), {"standard", "quick"})
        args = build_parser().parse_args(["-u", "http://example.com/", "--profile", "quick", "-d", "3"])
        apply_profile(args)
        self.assertEqual(args.depth, 3)                 # explicit value kept
        self.assertEqual(args.max_links_per_page, 30)   # profile value applied
        self.assertEqual(args.check_ssl, 1)             # TLS verification is on unless opted out
        self.assertEqual(build_parser().parse_args(["-u", "http://example.com/", "--verify-ssl", "0"]).check_ssl, 0)
        from protest.net.client import ClientConfiguration  # pylint: disable=import-outside-toplevel
        self.assertTrue(ClientConfiguration().verify_ssl)
        with self.assertRaises(SystemExit):             # removed profiles are rejected
            build_parser().parse_args(["-u", "http://example.com/", "--profile", "safe"])


class VaultAndDatabaseTest(unittest.TestCase):
    def setUp(self):
        import tempfile  # pylint: disable=import-outside-toplevel
        self.tmp = tempfile.mkdtemp(prefix="protest_vault_")

    def tearDown(self):
        import shutil  # pylint: disable=import-outside-toplevel
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_encrypt_decrypt_and_tamper_detection(self):
        from protest.core.vault import Vault, VaultError  # pylint: disable=import-outside-toplevel
        vault = Vault(os.path.join(self.tmp, "k.key"))
        token = vault.encrypt("admin123 ünïcode")
        self.assertNotIn("admin123", token)
        self.assertNotEqual(token, vault.encrypt("admin123 ünïcode"))      # random nonce every time
        self.assertEqual(vault.decrypt(token), "admin123 ünïcode")
        self.assertEqual(Vault(os.path.join(self.tmp, "k.key")).decrypt(token), "admin123 ünïcode")  # key reloaded
        tampered = token[:-6] + ("A" if token[-6] != "A" else "B") + token[-5:]
        with self.assertRaises(VaultError):
            vault.decrypt(tampered)
        with self.assertRaises(VaultError):
            Vault(os.path.join(self.tmp, "other.key")).decrypt(token)        # wrong key

    def test_inputs_and_credentials_helpers(self):
        from protest.core.database import describe_inputs, split_found_credentials  # pylint: disable=C0415
        request = Request("http://ex.com/a?q=1", post_params=[["user", "bob"]],
                          file_params=[["cv", ["cv.pdf", b"x", "application/pdf"]]])
        self.assertEqual(describe_inputs(request), [("q", "query string", "1"), ("user", "POST body", "bob"),
                                                    ("cv", "multipart file name", "cv.pdf")])
        api = Request("http://ex.com/api", post_params='{"a": {"b": 2}}', enctype="application/json")
        self.assertEqual(describe_inputs(api), [("a.b", "JSON body", "2")])
        self.assertEqual(describe_inputs(Request("http://ex.com/p"))[0][1], "raw query string (attack level 2 only)")
        self.assertEqual(split_found_credentials("username=admin&password=admin123"), ("admin", "admin123"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
