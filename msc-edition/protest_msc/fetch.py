# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""One HTTP GET. Redirects are returned, not followed. TLS is verified by default."""
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

from protest_msc.scope import require_web_url

MAX_BODY = 1024 * 1024
USER_AGENT = "pro-test-msc"


class FetchError(Exception):
    """The host did not accept the connection or the URL was not http(s)."""


@dataclass
class FetchedPage:
    url: str
    status: int
    headers: list
    body: str
    location: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # pylint: disable=too-many-arguments
        return None


def fetch(url: str, timeout: float, verify_tls: bool = True) -> FetchedPage:
    require_web_url(url)
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    # An empty ProxyHandler avoids sending the URL to a proxy from the environment.
    opener = urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.ProxyHandler({}),
    )
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        raw = opener.open(request, timeout=timeout)
        status = raw.status
    except urllib.error.HTTPError as error:
        raw = error
        status = error.code
    except urllib.error.URLError as error:
        raise FetchError(str(error.reason)) from error
    try:
        payload = raw.read(MAX_BODY)
        header_items = list(raw.headers.items())
    finally:
        raw.close()
    location = ""
    for name, value in header_items:
        if name.lower() == "location":
            location = value.strip()
            break
    return FetchedPage(url, status, header_items, payload.decode("utf-8", errors="replace"), location)
