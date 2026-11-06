# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Bounded crawl. One queue, one page at a time, same origin only."""
from collections import deque
from urllib.parse import urljoin

from protest_msc.checks import Finding, inspect_page
from protest_msc.fetch import FetchError, fetch
from protest_msc.parse import read_page
from protest_msc.scope import require_web_url, resolve_link, same_origin


def _redirect_target(page_url: str, location: str, start_url: str) -> str:
    if not location:
        return ""
    absolute = urljoin(page_url, location)
    if same_origin(start_url, absolute):
        return absolute
    return ""


def crawl(start_url: str, *, max_pages: int, max_depth: int, timeout: float, verify_tls: bool, pause) -> tuple:
    require_web_url(start_url)
    waiting = deque([(start_url, 0)])
    seen = set()
    pages = []
    findings = []
    try:
        return _crawl_queue(start_url, waiting, seen, pages, findings, max_pages, max_depth, timeout, verify_tls, pause)
    except KeyboardInterrupt:
        pause.stopped = True
        pause.interrupted = True
        return pages, findings


def _crawl_queue(start_url, waiting, seen, pages, findings, max_pages, max_depth, timeout, verify_tls, pause):
    while waiting and len(pages) < max_pages:
        if pause.stopped:
            break
        url, depth = waiting.popleft()
        if url in seen:
            continue
        seen.add(url)
        if not same_origin(start_url, url):
            continue
        pause.before_request()
        try:
            page = fetch(url, timeout, verify_tls=verify_tls)
        except FetchError as error:
            findings.append(Finding("notice", "Fetch failed", url, str(error)))
            continue
        pages.append(page)
        for finding in inspect_page(page):
            findings.append(finding)
            pause.observe(finding)
            if pause.stopped:
                break
        if pause.stopped or depth >= max_depth:
            continue
        if page.status in (301, 302, 303, 307, 308):
            target = _redirect_target(page.url, page.location, start_url)
            if target:
                waiting.append((target, depth + 1))
            elif page.location:
                findings.append(Finding(
                    "notice",
                    "Redirect not followed",
                    page.url,
                    f"Location {page.location!r} is a different origin or is not http(s). It was not requested.",
                ))
            continue
        for href in read_page(page.body)[0]:
            linked = resolve_link(page.url, href)
            if linked and linked not in seen:
                waiting.append((linked, depth + 1))
    return pages, findings
