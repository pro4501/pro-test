# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Ask, stop, or continue after a vulnerability. Notices do not pause."""
from urllib.parse import urlsplit

from protest_msc.checks import Finding


class ScanStopped(Exception):
    """before_request was called after the operator chose to stop."""


class Pause:
    def __init__(self, policy: str, interactive: bool, read_line=None):
        if policy not in ("ask", "stop", "continue"):
            raise ValueError(policy)
        self.policy = policy
        self.interactive = interactive
        self._read_line = read_line or input
        self.stopped = False
        self._seen = set()

    def observe(self, finding: Finding) -> None:
        if finding.kind != "vulnerability" or self.stopped:
            return
        key = (finding.name, (urlsplit(finding.url).netloc or "").lower())
        if key in self._seen:
            return
        self._seen.add(key)
        decision = self.policy
        if decision == "ask":
            if not self.interactive:
                print("[!] Not a terminal. Stopping after this finding. "
                      "Pass --on-finding continue to keep scanning.")
                decision = "stop"
            else:
                decision = self._prompt(finding)
        if decision == "stop":
            self.stopped = True

    def _prompt(self, finding: Finding) -> str:
        print()
        print(f"[!] {finding.name}")
        print(f"    {finding.url}")
        print(f"    {finding.evidence}")
        print("    1) Continue scanning")
        print("    2) Stop here")
        while True:
            try:
                answer = self._read_line("Choice [2]: ").strip()
            except EOFError:
                print("[!] End of input. Stopping.")
                return "stop"
            if answer in ("", "2"):
                return "stop"
            if answer == "1":
                return "continue"
            print("Enter 1 to continue or 2 to stop.")

    def before_request(self) -> None:
        if self.stopped:
            raise ScanStopped("Stopped. This URL was not requested.")


def resolve_policy(choice, stdin) -> tuple:
    interactive = bool(stdin is not None and getattr(stdin, "isatty", lambda: False)())
    policy = choice or ("ask" if interactive else "stop")
    return policy, interactive
