"""The localhost fixture stays local and does not reflect or interpret input."""
import os
import threading
import unittest
import urllib.error
import urllib.request
from importlib.machinery import SourceFileLoader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PATH = os.path.join(ROOT, "examples", "local-demo", "server.py")
server_mod = SourceFileLoader("local_demo_server", SERVER_PATH).load_module()


class LocalDemoFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = server_mod.serve(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _get(self, path: str):
        with urllib.request.urlopen(self.base + path, timeout=5) as response:
            return response.status, response.read().decode("utf-8"), response.headers

    def test_binds_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_home_page_is_labelled_and_insecure_on_purpose(self):
        status, body, headers = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("LOCAL DEMO / EXAMPLE", body)
        self.assertIn("Never deploy", body)
        self.assertNotIn("X-Frame-Options", headers)
        self.assertNotIn("Content-Security-Policy", headers)
        cookie = headers["Set-Cookie"]
        self.assertNotIn("HttpOnly", cookie)
        self.assertNotIn("Secure", cookie)

    def test_query_string_and_post_body_are_not_reflected(self):
        status, body, _headers = self._get("/?q=UNIQUE_DEMO_TOKEN_9421")
        self.assertEqual(status, 200)
        self.assertNotIn("UNIQUE_DEMO_TOKEN_9421", body)
        data = b"username=someone&password=not-a-real-secret-8844"
        request = urllib.request.Request(self.base + "/login", data=data, method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            posted = response.read().decode("utf-8")
        self.assertIn("does not store", posted)
        self.assertNotIn("not-a-real-secret-8844", posted)
        self.assertNotIn("someone", posted)

    def test_unknown_path_is_not_a_file_read(self):
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(self.base + "/../../etc/passwd", timeout=5)
        self.assertEqual(raised.exception.code, 404)
        body = raised.exception.read().decode("utf-8")
        self.assertNotIn("root:x:", body)
        self.assertNotIn("etc/passwd", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
