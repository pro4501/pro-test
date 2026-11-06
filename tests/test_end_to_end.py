# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""End-to-end test: scan the fictional Northbridge University practice site with every module and check the report.

The practice server (university_site.py) is not in this source tree. Both test
classes skip in that case. A skip is not a pass, and this file does not invent
a replacement target.

Run:  python -m unittest tests.test_end_to_end -v
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))            # .../Pro-Test
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.join(os.path.dirname(PROJECT), "Test-Server"))       # .../Test-Server

try:
    import university_site  # noqa: E402  pylint: disable=wrong-import-position
except ImportError:
    # The fictional practice server lived beside this tree (../Test-Server/university_site.py)
    # and was not part of the source archive. It is not recreated here.
    university_site = None
from urllib.parse import urlsplit  # noqa: E402  pylint: disable=wrong-import-position


def urlsplit_path(url: str) -> str:
    return urlsplit(url).path
from protest.app.cli import main  # noqa: E402  pylint: disable=wrong-import-position

# category -> URL paths that MUST be reported
EXPECTED = {
    "Cross Site Scripting": ["/courses/search", "/apply", "/contact"],
    "SQL Injection": ["/students/record", "/library/search", "/events/view"],
    "Command execution": ["/it-services/ping", "/cgi-bin/status.cgi"],
    "Path Traversal": ["/timetable/view"],
    "Open Redirect": ["/portal/logout"],
    "CRLF Injection": ["/set-language"],
    "LDAP Injection": ["/directory/search"],
    "Stored Cross Site Scripting": ["/news/comments"],
    "Weak credentials": ["/portal/login"],
    "Cross Site Request Forgery": ["/portal/login", "/portal/profile"],
    "Weak restriction bypass": ["/admin/"],
    "Backup file": ["/enrol.php.bak"],
    "Stack Trace Disclosure": ["/research/debug"],
    "HTTP Methods": ["/api/files"],
    "Clickjacking Protection": [],
    "MIME Type Confusion": [],
    "Content Security Policy Configuration": [],
    "HttpOnly Flag cookie": [],
    "Secure Flag cookie": [],
    "Cleartext Submission of Password": ["/portal/login"],
    "Unencrypted Channels": [],
    "Information Disclosure - Full Path": [],
    "Fingerprint web technology": [],
}
# category -> URL paths that must NOT be reported (false positive checks: these pages are coded safely)
FORBIDDEN = {
    "Cross Site Scripting": ["/news/search"],
    "SQL Injection": ["/staff/profile", "/news/search"],
    "Command execution": ["/staff/profile"],
}


@unittest.skipUnless(
    university_site is not None,
    "Practice server university_site.py is not in this source tree; active end-to-end scan was not run",
)
class EndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = university_site.start(0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/"
        cls.tmp = tempfile.mkdtemp(prefix="protest_test_")
        cls.report_file = os.path.join(cls.tmp, "report.json")
        exit_code = main([
            "-u", cls.base, "-m", "all", "-t", "3", "--tasks", "8", "-f", "json", "-o", cls.report_file,
            "--store-session", cls.tmp, "--flush-session", "-dr", "2",
            "--database", os.path.join(cls.tmp, "protest.db"), "-C", "nbu_session=my-own-session",
        ])
        assert exit_code == 0, f"scan exited with {exit_code}"
        with open(cls.report_file, encoding="utf-8") as handle:
            cls.report = json.load(handle)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def findings(self, category):
        for section in ("vulnerabilities", "anomalies", "additionals"):
            if category in self.report[section]:
                return self.report[section][category]
        self.fail(f"Unknown category {category}")
        return []

    def test_expected_findings(self):
        missing = []
        for category, paths in EXPECTED.items():
            items = self.findings(category)
            if not items:
                missing.append(f"{category}: nothing reported")
                continue
            reported_paths = {item["path"] for item in items}
            for path in paths:
                if path not in reported_paths:
                    missing.append(f"{category}: {path} not reported (got {sorted(reported_paths)})")
        self.assertEqual(missing, [], "\n".join(missing))

    def test_no_false_positives(self):
        problems = []
        for category, paths in FORBIDDEN.items():
            reported_paths = {item["path"] for item in self.findings(category)}
            problems += [f"{category}: false positive on {p}" for p in paths if p in reported_paths]
        self.assertEqual(problems, [], "\n".join(problems))

    def evidence_for(self, category, path):
        return [item for item in self.findings(category) if item["path"] == path]

    def assert_evidence(self, category, path, *needles):
        items = self.evidence_for(category, path)
        self.assertTrue(items, f"{category} on {path} not reported")
        text = "\n".join(item["evidence"] + "\n" + item["payload"] for item in items)
        for needle in needles:
            self.assertIn(needle, text, f"{category} on {path}: '{needle}' missing from evidence:\n{text}")

    def test_evidence_shows_the_actual_weakness(self):
        # The working password is shown
        self.assert_evidence("Weak credentials", "/portal/login", "admin123", "username = admin")
        # The leaked database error and the inferred vulnerable query are shown
        self.assert_evidence("SQL Injection", "/students/record", "OperationalError", "WHERE id = 1")
        self.assert_evidence("SQL Injection", "/library/search", "WHERE author = 'Smith'", "same page as normal")
        self.assert_evidence("SQL Injection", "/events/view", "Normal response time")
        # Leaked file content, command output, secrets in the backup file
        self.assert_evidence("Path Traversal", "/timetable/view", "root:x:0:0")
        self.assert_evidence("Command execution", "/it-services/ping", "PATH=")
        self.assert_evidence("Backup file", "/enrol.php.bak", "S3cr3t!", "Sensitive values")
        # The injected script as returned by the server
        self.assert_evidence("Cross Site Scripting", "/courses/search", "unescaped", "alert")
        self.assert_evidence("Open Redirect", "/portal/logout", "Location:")
        self.assert_evidence("CRLF Injection", "/set-language", "Pro-Test-Injected")
        self.assert_evidence("Cross Site Request Forgery", "/portal/profile", "Real token")
        self.assert_evidence("HttpOnly Flag cookie", "/", "Set-Cookie: nbu_session=abc123")

    def test_confidence_levels(self):
        # Every finding carries a confidence level
        for section in ("vulnerabilities", "anomalies", "additionals"):
            for category, items in self.report[section].items():
                for item in items:
                    self.assertIn(item["confidence"], ("Confirmed", "Probable", "Possible"),
                                  f"{category} {item['path']} has no confidence")
        # Findings proven by reproduction / direct evidence are Confirmed
        for category, path in (("SQL Injection", "/students/record"), ("SQL Injection", "/library/search"),
                               ("SQL Injection", "/events/view"), ("Weak credentials", "/portal/login"),
                               ("Path Traversal", "/timetable/view"), ("Command execution", "/it-services/ping"),
                               ("Cross Site Scripting", "/courses/search"),
                               ("Stored Cross Site Scripting", "/news/comments")):
            levels = {item["confidence"] for item in self.evidence_for(category, path)}
            self.assertIn("Confirmed", levels, f"{category} on {path}: {levels}")
        # Plain server errors are never more than Possible
        self.assertEqual({item["confidence"] for item in self.findings("Internal Server Error")}, {"Possible"})

    def test_live_verification_step4(self):
        from protest.app.cli import session_file  # pylint: disable=import-outside-toplevel
        from protest.net.client import ClientConfiguration, HttpClient  # pylint: disable=import-outside-toplevel
        from protest.net.request import Request  # pylint: disable=import-outside-toplevel
        from protest.core.persister import Persister  # pylint: disable=import-outside-toplevel
        from protest.reporting.verify import NOT_REPRODUCED, STILL_VULNERABLE, verify  # pylint: disable=C0415

        persister = Persister(session_file(Request(self.base), "folder", self.tmp))
        findings = [f for f in persister.get_findings() if f.type == "vulnerability"]
        baselines = persister.get_crawled_urls()
        persister.close()
        client = HttpClient(ClientConfiguration(timeout=5))

        verdicts = {}
        for finding in findings:
            result = verify(client, finding, baselines)
            verdicts.setdefault((finding.category, finding.request.path.rsplit(":", 1)[-1].split("/", 1)[-1]),
                                set()).add(result.verdict)
        expected = [("SQL Injection", "students/record"), ("SQL Injection", "library/search"),
                    ("SQL Injection", "events/view"), ("Cross Site Scripting", "courses/search"),
                    ("Stored Cross Site Scripting", "news/comments"), ("Path Traversal", "timetable/view"),
                    ("Command execution", "it-services/ping"), ("Command execution", "cgi-bin/status.cgi"),
                    ("Open Redirect", "portal/logout"), ("CRLF Injection", "set-language"),
                    ("Weak credentials", "portal/login"), ("Backup file", "enrol.php.bak"),
                    ("LDAP Injection", "directory/search"), ("Weak restriction bypass", "admin/")]
        problems = [f"{key}: {verdicts.get(key)}" for key in expected
                    if STILL_VULNERABLE not in verdicts.get(key, set())]
        self.assertEqual(problems, [], "\n".join(problems))

        # The same XSS attack sent to the news search (which escapes its output) must not be reproduced
        xss = next(f for f in findings
                   if f.category == "Cross Site Scripting" and f.request.path.endswith("/courses/search"))
        fixed = Request(xss.request.path.replace("/courses/search", "/news/search"),
                        get_params=xss.request.get_params)
        xss.request = fixed
        self.assertEqual(verify(client, xss, baselines).verdict, NOT_REPRODUCED)

    def test_central_database(self):
        import sqlite3  # pylint: disable=import-outside-toplevel
        from protest.core.database import ScanDatabase  # pylint: disable=import-outside-toplevel

        path = os.path.join(self.tmp, "protest.db")
        database = ScanDatabase(path)
        try:
            scan = database.list_scans(1)[0]
            self.assertEqual((scan["target"], scan["status"]), (self.base, "completed"))
            self.assertGreater(scan["weaknesses"], 10)
            # the inputs that were tested, with where they live
            inputs = {(urlsplit_path(p["url"]), p["name"], p["location"]) for p in database.parameters(scan["id"])}
            for expected in (("/students/record", "id", "query string"),
                             ("/portal/login", "password", "POST body"),
                             ("/it-services/ping", "host", "POST body")):
                self.assertIn(expected, inputs)
            # credentials: the weak login found, and the cookie we provided - both decryptable
            stored = {(c["origin"], c["kind"], c["username"], c["secret"])
                      for c in database.credentials(scan["id"], reveal=True)}
            self.assertIn(("found", "form login", "admin", "admin123"), stored)
            self.assertIn(("provided", "cookie header", "", "nbu_session=my-own-session"), stored)
        finally:
            database.close()
        # ...but nothing secret is readable in the raw database file
        raw = sqlite3.connect(path)
        try:
            dump = "\n".join(raw.iterdump())
        finally:
            raw.close()
        self.assertNotIn("admin123", dump)
        self.assertNotIn("my-own-session", dump)

    def test_report_infos(self):
        self.assertEqual(self.report["infos"]["target"], self.base)
        self.assertGreater(self.report["infos"]["crawled_pages_nbr"], 20)


@unittest.skipUnless(
    university_site is not None,
    "Practice server university_site.py is not in this source tree; access-control end-to-end scan was not run",
)
class AccessControlTest(unittest.TestCase):
    """Crawl as alice, replay alice's pages as bilal and logged out, and check the IDOR findings."""

    @classmethod
    def setUpClass(cls):
        cls.server = university_site.start(0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/"
        cls.tmp = tempfile.mkdtemp(prefix="protest_access_")
        cls.report_file = os.path.join(cls.tmp, "report.json")
        code = main(["-u", cls.base, "-m", "access_control", "-t", "4", "-f", "json", "-o", cls.report_file,
                     "--form-url", cls.base + "portal/login", "--form-user", "alice", "--form-password", "alice2027",
                     "--compare-form-user", "bilal", "--compare-form-password", "bilal2027",
                     "--store-session", cls.tmp, "--flush-session", "--database", os.path.join(cls.tmp, "p.db")])
        assert code == 0
        with open(cls.report_file, encoding="utf-8") as handle:
            cls.items = json.load(handle)["vulnerabilities"]["Broken Access Control"]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def by_path(self):
        return {item["path"]: item for item in self.items}

    def test_idor_between_two_students(self):
        grades = self.by_path().get("/portal/grades")
        self.assertIsNotNone(grades, sorted(self.by_path()))
        self.assertIn("read by user bilal", grades["info"])
        self.assertEqual(grades["parameter"], "student")
        self.assertEqual(grades["confidence"], "Confirmed")

    def test_missing_authentication(self):
        report = self.by_path().get("/portal/admin-report")
        self.assertIsNotNone(report, sorted(self.by_path()))
        self.assertIn("without logging in", report["info"])
        self.assertEqual(report["confidence"], "Confirmed")

    def test_correctly_protected_pages_are_not_reported(self):
        for safe in ("/portal/invoice", "/portal/messages", "/portal/dashboard"):
            self.assertNotIn(safe, self.by_path(), f"false positive on {safe}")
        self.assertEqual(len([i for i in self.items if i["path"] == "/students/record"]), 1)  # de-duplicated

    def test_step4_rechecks_logged_out_access(self):
        from protest.app.cli import session_file  # pylint: disable=import-outside-toplevel
        from protest.core.persister import Persister  # pylint: disable=import-outside-toplevel
        from protest.net.client import ClientConfiguration, HttpClient  # pylint: disable=import-outside-toplevel
        from protest.net.request import Request  # pylint: disable=import-outside-toplevel
        from protest.reporting.verify import INCONCLUSIVE, STILL_VULNERABLE, verify  # pylint: disable=C0415

        persister = Persister(session_file(Request(self.base), "folder", self.tmp))
        findings = {urlsplit_path(f.request.url): f for f in persister.get_findings()
                    if f.category == "Broken Access Control"}
        persister.close()
        client = HttpClient(ClientConfiguration(timeout=5))
        self.assertEqual(verify(client, findings["/portal/admin-report"]).verdict, STILL_VULNERABLE)
        # user-to-user findings need user B's session: Step 4 says so instead of guessing
        self.assertEqual(verify(client, findings["/portal/grades"]).verdict, INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
