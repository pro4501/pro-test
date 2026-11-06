# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Same-origin rule: scheme, hostname and port must all match the start URL."""
from urllib.parse import urlsplit, urljoin


class ScopeError(ValueError):
    """The URL is not an absolute http or https URL with a host."""


def _port(parts) -> int | None:
    if parts.port is not None:
        return parts.port
    if parts.scheme == "https":
        return 443
    if parts.scheme == "http":
        return 80
    return None


def require_web_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ScopeError(f"Only absolute http and https URLs are accepted, not {url!r}")


def origin(url: str) -> tuple:
    parts = urlsplit(url)
    return parts.scheme, (parts.hostname or "").lower(), _port(parts)


def same_origin(start_url: str, other_url: str) -> bool:
    try:
        require_web_url(other_url)
    except ScopeError:
        return False
    return origin(start_url) == origin(other_url)


def resolve_link(page_url: str, href: str) -> str:
    """Turn a link into an absolute URL, or '' when it cannot be requested."""
    if not href or href.startswith(("#", "mailto:", "javascript:", "data:", "file:")):
        return ""
    absolute = urljoin(page_url, href)
    if not same_origin(page_url, absolute):
        return ""
    return absolute
