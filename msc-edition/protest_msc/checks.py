# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Passive observations. Each function looks at one response and returns findings.

A vulnerability is something the operator may want to stop on. A notice is
recorded and does not stop the crawl. Neither kind is an exploit: the check
only says what the response contained.
"""
from dataclasses import dataclass
from urllib.parse import urlsplit

from protest_msc.fetch import FetchedPage
from protest_msc.parse import read_page


@dataclass
class Finding:
    kind: str
    name: str
    url: str
    evidence: str


def _header_values(page: FetchedPage, name: str) -> list:
    return [value for key, value in page.headers if key.lower() == name]


def _joined(page: FetchedPage, name: str) -> str:
    return " ".join(_header_values(page, name)).lower()


def cleartext_password(page: FetchedPage) -> list:
    _hrefs, passwords = read_page(page.body)
    if passwords == 0 or urlsplit(page.url).scheme != "http":
        return []
    return [Finding(
        "vulnerability",
        "Cleartext password field",
        page.url,
        f"The HTML contains {passwords} password field(s) and the URL is http, "
        "so a browser would submit that form without TLS.",
    )]


def cookie_flags(page: FetchedPage) -> list:
    findings = []
    for value in _header_values(page, "set-cookie"):
        lowered = value.lower()
        name = value.split("=", 1)[0].strip() or "(unnamed)"
        if "httponly" not in lowered:
            findings.append(Finding(
                "vulnerability",
                "Cookie without HttpOnly",
                page.url,
                f"Set-Cookie for {name} has no HttpOnly attribute. The value is not copied into this report.",
            ))
        if "secure" not in lowered:
            findings.append(Finding(
                "vulnerability",
                "Cookie without Secure",
                page.url,
                f"Set-Cookie for {name} has no Secure attribute. The value is not copied into this report.",
            ))
    return findings


def header_notices(page: FetchedPage) -> list:
    notices = []
    if "html" not in _joined(page, "content-type"):
        return notices
    framing = _joined(page, "x-frame-options")
    policy = _joined(page, "content-security-policy")
    if not framing and "frame-ancestors" not in policy:
        notices.append(Finding(
            "notice",
            "No framing header",
            page.url,
            "The response has neither X-Frame-Options nor a CSP frame-ancestors directive.",
        ))
    if "nosniff" not in _joined(page, "x-content-type-options"):
        notices.append(Finding(
            "notice",
            "No nosniff header",
            page.url,
            "X-Content-Type-Options: nosniff is not set.",
        ))
    return notices


def inspect_page(page: FetchedPage) -> list:
    return cleartext_password(page) + cookie_flags(page) + header_notices(page)
