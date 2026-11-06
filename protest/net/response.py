# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""HTTP response model.

Headers is case-insensitive and keeps repeated headers (several Set-Cookie lines). Response decodes
the body lazily with the charset announced by the server and offers the predicates the modules rely
on: is_redirect / redirection_url (open redirect, crawling), is_directory_redirection (/dir -> /dir/),
is_server_error (anomalies), md5 (de-duplication). to_dict()/from_dict() let the persister store a
response (body capped) in SQLite.
"""
import hashlib
import json
from typing import List, Optional, Tuple
from urllib.parse import urljoin


class Headers:
    """Case-insensitive, multi-valued header container."""

    def __init__(self, items: Optional[List[Tuple[str, str]]] = None):
        self._items: List[Tuple[str, str]] = list(items or [])

    def get(self, name: str, default=None):
        name = name.lower()
        values = [v for k, v in self._items if k.lower() == name]
        if not values:
            return default
        # Multiple values are joined like a browser would for most headers
        return ", ".join(values)

    def get_list(self, name: str) -> List[str]:
        name = name.lower()
        return [v for k, v in self._items if k.lower() == name]

    def __contains__(self, name: str) -> bool:
        name = name.lower()
        return any(k.lower() == name for k, _ in self._items)

    def items(self) -> List[Tuple[str, str]]:
        return list(self._items)


class Response:
    # pylint: disable=too-many-arguments
    def __init__(self, url: str, status: int, headers: Headers, raw: bytes, elapsed: float = 0.0):
        self.url = url
        self.status = status
        self.headers = headers
        self.raw = raw or b""
        self.elapsed = elapsed
        self._content: Optional[str] = None

    @property
    def content(self) -> str:
        if self._content is None:
            charset = "utf-8"
            ctype = self.headers.get("content-type", "") or ""
            for part in ctype.split(";"):
                part = part.strip()
                if part.lower().startswith("charset="):
                    charset = part.split("=", 1)[1].strip("\"' ") or "utf-8"
            try:
                self._content = self.raw.decode(charset, errors="replace")
            except LookupError:
                self._content = self.raw.decode("utf-8", errors="replace")
        return self._content

    @property
    def type(self) -> str:
        return (self.headers.get("content-type", "") or "").lower()

    @property
    def raw_size(self) -> int:
        return len(self.raw)

    @property
    def md5(self) -> str:
        return hashlib.md5(self.raw).hexdigest()  # nosec - fingerprint only

    @property
    def is_redirect(self) -> bool:
        return self.status in (301, 302, 303, 307, 308) and "location" in self.headers

    @property
    def redirection_url(self) -> str:
        if self.is_redirect:
            return urljoin(self.url, self.headers.get("location", "").split(",")[0].strip())
        return ""

    @property
    def is_directory_redirection(self) -> bool:
        if not self.is_redirect:
            return False
        return self.redirection_url == self.url.split("?")[0] + "/"

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status < 600

    def to_dict(self, max_body: int = 20000) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "headers": self.headers.items(),
            "body": self.content[:max_body],
            "elapsed": self.elapsed,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Response":
        return cls(
            data["url"],
            data["status"],
            Headers([tuple(item) for item in data.get("headers", [])]),
            (data.get("body") or "").encode("utf-8"),
            data.get("elapsed", 0.0),
        )

    def to_json(self, max_body: int = 20000) -> str:
        return json.dumps(self.to_dict(max_body))

    def __repr__(self) -> str:
        return f"<Response {self.status} {self.url}>"
