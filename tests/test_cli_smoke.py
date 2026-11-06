# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""CLI exit codes that do not send attack payloads."""
import os
import tempfile
import unittest

from protest.app.cli import main


class CliSmokeTest(unittest.TestCase):
    def test_invalid_url_exits_2(self):
        self.assertEqual(main(["-u", "not-a-url"]), 2)

    def test_unreachable_target_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "report.txt")
            code = main([
                "-u", "http://127.0.0.1:1/", "-m", "passive", "--no-database",
                "--store-session", tmp, "--flush-session", "--max-scan-time", "3",
                "-f", "txt", "-o", report,
            ])
            self.assertEqual(code, 1)
            self.assertFalse(os.path.exists(report))


if __name__ == "__main__":
    unittest.main(verbosity=2)
