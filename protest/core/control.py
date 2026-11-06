# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Pause when a vulnerability is recorded, then continue or stop.

A vulnerability is a finding whose type is exactly "vulnerability". Anomalies
and informational results do not pause. The same category on the same host and
parameter is asked about once.

Stop means later calls to before_request raise ScanStopped, so the HTTP client
does not open another connection. A request already on the wire can finish.
Enter and end-of-file both mean stop. A non-interactive session cannot ask,
so "ask" becomes stop unless the operator passed continue.
"""
import threading
from typing import Optional
from urllib.parse import urlsplit

from protest.core import log


class ScanStopped(Exception):
    """A new HTTP request was refused because the operator stopped the scan."""


class ScanControl:
    def __init__(self, policy: str, interactive: bool, read_line=None):
        if policy not in ("ask", "stop", "continue"):
            raise ValueError(f"Unknown vulnerability policy {policy}")
        self.policy = policy
        self.interactive = interactive
        self._read_line = read_line or input
        self.stopped = False
        self._seen = set()
        self._lock = threading.Lock()
        self._prompt_lock = threading.Lock()

    def observe(self, finding_type: str, category: str, url: str, parameter: str, info: str) -> None:
        if finding_type != "vulnerability" or self.stopped:
            return
        key = (category, (urlsplit(url).netloc or "").lower(), parameter or "")
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
        decision = self.policy
        if decision == "ask":
            if not self.interactive:
                log.warning("[!] Not a terminal, so the scan stops on this vulnerability. "
                            "Pass --on-vulnerability continue to keep scanning.")
                decision = "stop"
            else:
                with self._prompt_lock:
                    if self.stopped:
                        return
                    decision = self._prompt(category, url, info)
        if decision == "stop":
            self.stopped = True

    def _prompt(self, category: str, url: str, info: str) -> str:
        print()
        print(f"[!] Vulnerability: {category}")
        if url:
            print(f"    {url}")
        first = (info or "").splitlines()
        if first and first[0].strip():
            print(f"    {first[0].strip()[:200]}")
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
            raise ScanStopped("Scan stopped after a vulnerability; no further request was sent")


def resolve_vulnerability_policy(choice: Optional[str], stdin) -> tuple:
    """Return (policy, interactive). Omitted choice asks on a terminal and stops otherwise."""
    interactive = bool(stdin is not None and getattr(stdin, "isatty", lambda: False)())
    policy = choice or ("ask" if interactive else "stop")
    return policy, interactive
