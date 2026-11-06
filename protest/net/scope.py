"""Scan scope: decides which discovered URLs are allowed to be crawled and attacked.

Scopes (same semantics as Wapiti):
    url        only the exact base URL
    page       the base page with any query string
    folder     everything under the base URL's folder (default)
    subdomain  everything on the same host name
    domain     everything on the same registered domain (and its subdomains)
    punk       everything (use with extreme care)
"""
import ipaddress
import re
from typing import Iterable, Set, Union
from urllib.parse import urlsplit

from protest.net.request import Request

# Common multi-label public suffixes; good enough without shipping the full PSL.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.in", "co.nz", "co.za", "com.au", "net.au",
    "org.au", "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk", "co.kr", "gov.in", "ac.in",
}


def registered_domain(hostname: str) -> str:
    hostname = (hostname or "").lower().strip(".")
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class Scope:
    NAMES = ("url", "page", "folder", "subdomain", "domain", "punk")

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

        if self._scope == "punk":
            return True
        if self._scope == "domain":
            host = urlsplit(url).hostname or ""
            return registered_domain(host) == registered_domain(self._base.hostname)
        if self._scope == "subdomain":
            return (urlsplit(url).hostname or "") == self._base.hostname
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
