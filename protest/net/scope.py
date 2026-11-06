# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Scan scope: decides which discovered URLs are allowed to be crawled and attacked.

Scopes:
    url        only the exact base URL
    page       the base page with any query string
    folder     everything under the base URL's folder (default)
    host       same hostname and port (default ports 80 and 443)
    subdomain  deprecated alias of host. It used to ignore the port. It does not any more.
    domain     other host names that share a registrable domain in the curated suffix list
    punk       any http or https URL (explicit)

``url``, ``page``, ``folder`` and ``host`` require the same scheme, hostname and port.
``domain`` uses the longest matching suffix in the list below. An unknown suffix does
not fall back to "the last two labels", so github.io and s3.amazonaws.com are not
treated as one site. This list is not the Public Suffix List.
"""
import ipaddress
import re
from typing import Iterable, Optional, Set, Union
from urllib.parse import urlsplit

from protest.net.request import Request

# Curated suffixes, longest match wins. Not the Public Suffix List.
_PUBLIC_SUFFIXES = {
    "com", "net", "org", "edu", "gov", "io", "dev", "app", "co", "uk", "us", "de", "fr", "info", "biz",
    "xyz", "me", "ai", "cloud",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.in", "co.nz", "co.za", "com.au", "net.au",
    "org.au", "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk", "co.kr", "gov.in", "ac.in",
    "github.io", "githubusercontent.com", "amazonaws.com", "s3.amazonaws.com", "appspot.com",
    "herokuapp.com", "pages.dev", "blob.core.windows.net",
}


def origin_key(url: str) -> tuple:
    """Scheme, hostname and port. Missing ports become 80 or 443."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.port is not None:
        port = parts.port
    elif parts.scheme == "https":
        port = 443
    elif parts.scheme == "http":
        port = 80
    else:
        port = None
    return parts.scheme, host, port


def registered_domain(hostname: str) -> str:
    """Registrable domain, or "" when the suffix is not in the curated list.

    An empty result means "do not guess". Callers must not treat two empty
    results as the same site.
    """
    hostname = (hostname or "").lower().strip(".")
    if not hostname:
        return ""
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    labels = hostname.split(".")
    best_index: Optional[int] = None
    best_length = -1
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in _PUBLIC_SUFFIXES and candidate.count(".") > best_length:
            best_index = index
            best_length = candidate.count(".")
    if best_index is None:
        return ""
    if best_index == 0:
        return hostname
    return ".".join(labels[best_index - 1:])


def same_registered_domain(left: str, right: str) -> bool:
    left_name = registered_domain(left)
    right_name = registered_domain(right)
    if not left_name or not right_name:
        return (left or "").lower() == (right or "").lower() and bool(left)
    return left_name == right_name


class Scope:
    NAMES = ("url", "page", "folder", "host", "subdomain", "domain", "punk")

    def __init__(self, base_request: Request, scope: str = "folder"):
        if scope not in self.NAMES:
            raise ValueError(f"Unknown scope {scope}")
        self._scope = scope
        self._base = base_request

    @property
    def name(self) -> str:
        return self._scope

    def check(self, resource: Union[Request, str]) -> bool:
        if not resource:
            return False
        url = resource.url if isinstance(resource, Request) else resource
        parts = urlsplit(url)
        if self._scope == "punk":
            return parts.scheme in ("http", "https") and bool(parts.netloc)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        if self._scope == "domain":
            return same_registered_domain(parts.hostname, self._base.hostname)
        if origin_key(url) != origin_key(self._base.url):
            return False
        if self._scope in ("host", "subdomain"):
            return True
        if self._scope == "folder":
            return url.startswith(self._base.dir_name if not self._base.path.endswith("/") else self._base.path)
        if self._scope == "page":
            return url.split("?")[0] == self._base.path
        return url == self._base.url

    def filter(self, resources: Iterable[Union[Request, str]]) -> Set[Union[Request, str]]:
        return {resource for resource in resources if self.check(resource)}


def wildcard_translate(pattern: str) -> re.Pattern:
    """Translate a wildcard pattern (only '*' is special) to a compiled regex for full matching."""
    regex = "".join(".*" if char == "*" else re.escape(char) for char in pattern)
    return re.compile(r"(?ms)" + regex + r"\Z")
