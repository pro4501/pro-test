# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Access control module: pages of user A that user B, or a logged-out visitor, can also read.

WEAKNESS (OWASP Top 10 A01, CWE-639 IDOR / CWE-862 missing authorization, WSTG-ATHZ-02/04)
    The server shows a record (grades, invoice, profile, report...) to whoever asks for its URL. It may
    check that SOMEONE is logged in, but not that the record belongs to THAT person.

WHY SCANNERS USUALLY MISS IT
    A single session can't tell "my own page" from "somebody else's page": both answer HTTP 200. You
    need a second point of view. This module uses three:

        user A       the scan's own session (--form-user / --form-password, or -C cookie): the crawl
                     discovers A's pages with it
        user B       a second test account (--compare-form-user / --compare-form-password, or
                     --compare-cookie)
        anonymous    no cookie and no credentials at all

HOW THE CHECK DECIDES
    1. "Identity markers" are strings that identify user A: A's username plus any --identity-marker
       (full name, student number, e-mail...). Only pages whose answer AS A contains a marker are
       tested: other pages show nothing private to protect.
    2. The page is requested again ANONYMOUSLY. If it is served (HTTP 200, no login form) and still
       contains A's marker  ->  "readable without logging in" (missing authentication).
    3. Otherwise it is requested AS USER B. If B gets HTTP 200 and the page still contains A's
       marker  ->  "user B can read user A's data" (IDOR / missing ownership check).
       Pages built per user (B sees B's own data, not A's) are correctly NOT reported.
    4. Each finding is re-sent once (re-verification) before being marked Confirmed.

SAFETY / SCOPE
    * GET pages only (do_post = False): no form is replayed, nothing is modified
    * only URLs user A legitimately reached during the crawl; IDs are never changed or guessed
    * use dedicated test accounts that you own

FIX
    Check authorization on the server for every request: load the record AND verify it belongs to the
    logged-in user (or that the role allows it); deny by default; require authentication on every
    non-public page. See /portal/invoice on the practice server for the correct pattern.
"""
import re
from typing import List, Optional
from urllib.parse import urlsplit

from protest.active.base import Attack
from protest.core import log
from protest.core.definitions import BROKEN_ACCESS_CONTROL, CONFIRMED, POSSIBLE
from protest.core.evidence import around, page_summary
from protest.parsing.page import Html
from protest.net.client import HttpClient, InvalidURL, RequestError
from protest.net.request import Request
from protest.net.response import Response

TEXT_TYPES = ("html", "json", "text/plain", "xml")
SKIPPED_PATHS = re.compile(r"log[-_ ]?(in|out|off)|sign[-_ ]?(in|out|up)|register|password|reset", re.I)
ID_LIKE = re.compile(r"(^|_)(id|uid|user|student|account|order|invoice|doc|file|record|no|num|number)$", re.I)
MIN_MARKER_LENGTH = 3


def _text(response: Response) -> str:
    return Html(response.content, response.url).text_only if "html" in response.type else response.content


def _is_login_page(response: Response) -> bool:
    return "html" in response.type and any(form.has_password_field()
                                           for form in Html(response.content, response.url).iter_forms())


def _contains(response: Optional[Response], markers: List[str]) -> List[str]:
    """Markers of user A present in a response that was served normally (HTTP 200, not a login page)."""
    if response is None or response.status != 200 or _is_login_page(response):
        return []
    text = _text(response).lower()
    return [marker for marker in markers if marker.lower() in text]


def _describe(label: str, response: Optional[Response], error: str = "") -> str:
    if response is None:
        return f"{label:<10}: {error or 'no answer'}"
    location = f" -> {urlsplit(response.redirection_url).path}" if response.is_redirect else ""
    return f"{label:<10}: {page_summary(response, 90)}{location}"


class ModuleAccessControl(Attack):
    """Detects broken access control (IDOR): user A's pages readable by user B or without logging in."""

    name = "access_control"
    do_post = False      # never replay forms: they may change data
    PRIORITY = 4

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        settings = options.get("access_control") or {}
        self.other: Optional[HttpClient] = settings.get("other")
        self.anonymous: Optional[HttpClient] = settings.get("anonymous")
        self.other_name: str = settings.get("other_name") or "user B"
        self.own_name: str = settings.get("own_name") or "user A"
        self.markers = [m for m in settings.get("markers", []) if m and len(m) >= MIN_MARKER_LENGTH]
        self.tested = set()
        if not self.markers:
            log.warning("[!] access_control: no identity marker. Log in as user A (--form-user/--form-password)"
                        " or give --identity-marker so the module knows what 'A's data' looks like.")

    @staticmethod
    def _key(request: Request) -> str:
        """One test per page path: /record, /record?id=1 and /record?id=1&x=2 are served by the same
        server-side code, so the same (missing) access check applies to all of them."""
        return request.path

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        if not self.markers or request.method != "GET" or self._key(request) in self.tested:
            return False
        if response is None or response.status != 200 or not any(t in response.type for t in TEXT_TYPES):
            return False
        return not SKIPPED_PATHS.search(request.file_path)

    def _fetch(self, client: HttpClient, request: Request):
        """Send `request` with another identity. Returns (response, error)."""
        if self.cancel_event.is_set():
            return None, "cancelled"
        try:
            return client.send(Request(request.url)), ""
        except (RequestError, InvalidURL) as error:
            self.network_errors += 1
            return None, str(error)

    def _id_parameter(self, request: Request) -> str:
        return next((name for name, _ in request.get_params if ID_LIKE.search(name or "")), "")

    def attack(self, request: Request, response: Optional[Response] = None):
        self.tested.add(self._key(request))
        try:
            own = self.send(Request(request.url))
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return
        found = _contains(own, self.markers)
        if not found:
            return  # nothing on this page identifies user A: nothing private to protect
        marker = found[0]
        lines = [_describe(self.own_name, own)]

        # 1. Logged-out visitor
        if self.anonymous is not None:
            anon, error = self._fetch(self.anonymous, request)
            lines.append(_describe("logged out", anon, error))
            if _contains(anon, [marker]):
                again, _ = self._fetch(self.anonymous, request)
                self._report(request, anon, marker, lines, "without logging in",
                             CONFIRMED if _contains(again, [marker]) else POSSIBLE)
                return

        # 2. Second user
        if self.other is not None:
            other, error = self._fetch(self.other, request)
            lines.append(_describe(self.other_name, other, error))
            if _contains(other, [marker]):
                again, _ = self._fetch(self.other, request)
                self._report(request, other, marker, lines, f"by {self.other_name}",
                             CONFIRMED if _contains(again, [marker]) else POSSIBLE)

    # pylint: disable=too-many-arguments
    def _report(self, request: Request, leaked: Response, marker: str, lines: List[str], who: str,
                confidence: str):
        parameter = self._id_parameter(request)
        where = f" (record selected by the parameter '{parameter}')" if parameter else ""
        info = f"{request.path} shows {self.own_name}'s data and can be read {who}{where}"
        evidence = ("The same page was requested with different identities:\n    " + "\n    ".join(lines) +
                    f"\n{self.own_name}'s identity marker '{marker}' is still in the page served {who}:\n    " +
                    around(_text(leaked), marker, 90) +
                    f"\nRe-verification: {'reproduced' if confidence == CONFIRMED else 'NOT reproduced'}.")
        self.add_high(BROKEN_ACCESS_CONTROL, request=Request(request.url), parameter=parameter, info=info,
                      response=leaked, payload=f"identity marker: {marker} | read {who}", evidence=evidence,
                      confidence=confidence)
